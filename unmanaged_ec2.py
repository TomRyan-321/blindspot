#!/usr/bin/env python3
"""Find unmanaged EC2 instances (no Falcon sensor) via the Cloud Security Assets API.

Mirrors the Cloud Security asset inventory query in the Falcon console:
    Asset type = EC2 Instance
    Region     = <optional>
    Asset status = Active
    Category   = Compute
    Sensor installed = false
    First seen before 6 hours    <- --age (default 6h); newer launches are covered by unmanaged_ec2.cql

Sensor status sources (--source):
  hosts (default)  Cloud asset inventory supplies the candidate EC2 list; the Hosts API supplies
                   live sensor check-in status. cloud_context.managed_by reflects the most recent
                   CSPM scan, so the two are compared and differences reported.
  cspm             Use cloud_context.managed_by server-side (fastest; as of the last scan).

Built for large, high-churn environments:
  - Candidate IDs are paged 1000 at a time with the `after` token, so inventory size is unbounded.
  - Asset IDs (GCRNs) already contain account, region and instance ID, so the sensor check needs no
    asset details. The CSPM view for every candidate comes from a second ID-only query.
  - Asset details (~25 KB each) are fetched only for rows being output, 500 per POST, in parallel,
    and rows are streamed to the output as each batch completes.
  - Hosts lookups use the combined endpoint (full records, no separate detail calls), 100 instance
    IDs per request, in parallel.
  - 429 / 5xx responses are retried with backoff, honouring X-Ratelimit-RetryAfter.

Endpoints:
  GET  /cloud-security-assets/queries/resources/v1   CloudSecurityAssets.query_assets
  POST /cloud-security-assets/entities/resources/v1  CloudSecurityAssets.cloud_security_assets_entities_post
  GET  /devices/combined/devices/v1                  Hosts.query_devices_by_filter_combined

Required API scopes: Cloud Security Assets: Read, Hosts: Read (for --source hosts)

Creds: FALCON_CLIENT_ID / FALCON_CLIENT_SECRET / FALCON_BASE_URL (optional) from env vars or
       ./.env next to this script (--env-file to override).
"""
import argparse
import csv
import json
import os
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

from falconpy import CloudSecurityAssets, Hosts

# Only Server host records count as a sensor (Linux + Windows, incl. EKS worker nodes running the
# DaemonSet sensor). Excludes Kubernetes Cluster (KAC) and Pod (sidecar) records, which also carry the
# node's instance_id but don't protect the node itself. Applied server-side in the Hosts FQL.
# Don't filter on agent_version: some DaemonSet node sensors report 0.13.0000.0 but are real sensors.
HOSTS_TYPE_FQL = "product_type_desc:'Server'"

ASSET_QUERY_PAGE = 1000      # query_assets max
ASSET_DETAIL_BATCH = 500     # entities POST max
HOSTS_ID_BATCH = 100         # instance IDs per Hosts FQL (keeps the URL well under limits)
HOSTS_PAGE = 10000           # combined devices max

COLS = ["account_id", "account_name", "region", "instance_id", "name", "sensor_status", "cspm_managed_by",
        "cspm_mismatch", "sensor_last_seen", "sensor_aid", "sensor_version", "ssm_managed", "os",
        "instance_type", "private_ip", "public_ip", "launch_time", "first_seen", "asg", "eks_cluster",
        "console_url"]


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def load_env(path):
    if path and os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("\"'"))


def parse_age(text):
    """'90m', '6h', '1.5d', '2w' -> timedelta. Bare number = days."""
    text = text.strip().lower()
    units = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
    if text[-1] in units:
        return timedelta(**{units[text[-1]]: float(text[:-1])})
    return timedelta(days=float(text))


def iso(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00")[:19] + "+00:00") if ts else None


def build_fql(age, regions, sensor_fql, now=None):
    # first_seen is compared to the second; absolute UTC timestamp keeps the query reproducible/loggable
    cutoff = ((now or datetime.now(timezone.utc)) - age).strftime("%Y-%m-%dT%H:%M:%SZ")
    parts = [
        "resource_type:'AWS::EC2::Instance'",   # Asset type = EC2 Instance
        "active:true",                           # Asset status = Active
        "service_category:'Compute'",            # Category = Compute
        f"first_seen:<'{cutoff}'",               # First seen before <age>
    ]
    if regions:
        parts.append("region:[" + ",".join(f"'{r}'" for r in regions) + "]")
    if sensor_fql:
        parts.append(sensor_fql)
    return "+".join(parts)


def call(fn, what, retries=6, **kwargs):
    """Call a falconpy method; retry 429/5xx with backoff; exit on other errors."""
    for attempt in range(retries):
        r = fn(**kwargs)
        code = int(r["status_code"])
        if code == 200:
            return r.get("body") or r.get("resources") or {}
        if code == 429 or code >= 500:
            retry_at = (r.get("headers") or {}).get("X-Ratelimit-Retryafter")
            wait = max(1, int(retry_at) - int(time.time())) if retry_at else 2 ** attempt
            log(f"{what}: HTTP {code}, retrying in {wait}s")
            time.sleep(min(wait, 60))
            continue
        body = r.get("body") or r.get("resources") or {}
        sys.exit(f"{what} failed: HTTP {code} {body.get('errors')}")
    sys.exit(f"{what} failed after {retries} attempts")


def parse_gcrn(gcrn):
    """'cid|aws|account|region|AWS::EC2::Instance|i-...' -> (account, region, instance_id)."""
    parts = gcrn.split("|")
    return (parts[2], parts[3], parts[5]) if len(parts) >= 6 else (None, None, gcrn)


def console_url(region, instance_id):
    if region and instance_id:
        return (f"https://{region}.console.aws.amazon.com/ec2/home?region={region}"
                f"#InstanceDetails:instanceId={instance_id}")
    return None


def query_all_ids(api, fql):
    """All asset IDs for an FQL filter, paged with the `after` token."""
    ids, after = [], None
    while True:
        params = {"filter": fql, "limit": ASSET_QUERY_PAGE}
        if after:
            params["after"] = after
        body = call(api.query_assets, "query_assets", **params)
        got = body.get("resources") or []
        ids.extend(got)
        meta = body.get("meta", {}) or {}
        after = meta.get("next") or (meta.get("pagination") or {}).get("after")   # token lives at meta.next
        if not after or not got:
            return ids


def fetch_details(api, ids, workers):
    """Yield asset detail batches (500 per POST) as they complete."""
    batches = [ids[i:i + ASSET_DETAIL_BATCH] for i in range(0, len(ids), ASSET_DETAIL_BATCH)]
    with ThreadPoolExecutor(workers) as ex:
        futs = [ex.submit(call, api.cloud_security_assets_entities_post, "asset details", body={"ids": b})
                for b in batches]
        for f in as_completed(futs):
            yield f.result().get("resources") or []


def _hosts_batch(hosts, iids):
    """Latest Server sensor record per instance ID for one batch (pages through duplicates)."""
    fql = HOSTS_TYPE_FQL + "+instance_id:[" + ",".join(f"'{x}'" for x in iids) + "]"
    best, token, seen = {}, None, 0
    while True:
        params = {"filter": fql, "limit": HOSTS_PAGE}
        if token:
            params["offset"] = token
        body = call(hosts.query_devices_by_filter_combined, "hosts query", **params)
        got = body.get("resources") or []
        seen += len(got)
        for d in got:
            iid = d.get("instance_id")
            if iid and (iid not in best or (d.get("last_seen") or "") > best[iid]["last_seen"]):
                best[iid] = {k: d.get(k) or "" for k in ("device_id", "last_seen", "agent_version")}
        pag = (body.get("meta") or {}).get("pagination") or {}
        token = pag.get("next") or (pag.get("offset") if isinstance(pag.get("offset"), str) else None)
        if not got or not token or seen >= int(pag.get("total") or 0):
            return best


def host_sensors_by_instance(hosts, instance_ids, workers):
    batches = [instance_ids[i:i + HOSTS_ID_BATCH] for i in range(0, len(instance_ids), HOSTS_ID_BATCH)]
    out = {}
    with ThreadPoolExecutor(workers) as ex:
        for part in ex.map(lambda b: _hosts_batch(hosts, b), batches):
            out.update(part)
    return out


def classify(host, stale_after, now):
    """Return (sensor_status, unmanaged?) using Hosts as source of truth."""
    if not host:
        return "none", True
    last = iso(host.get("last_seen"))
    if last and now - last > stale_after:
        return "stale", True
    return "active", False


def base_row(gcrn, host, status, cspm_sensor):
    account, region, iid = parse_gcrn(gcrn)
    row = dict.fromkeys(COLS)
    row.update({
        "account_id": account, "region": region, "instance_id": iid,
        "sensor_status": status,
        "cspm_managed_by": "Sensor" if cspm_sensor else ("not Sensor" if cspm_sensor is not None else None),
        "cspm_mismatch": None if status is None or cspm_sensor is None else (cspm_sensor != (status == "active")),
        "sensor_last_seen": (host or {}).get("last_seen") or None,
        "sensor_aid": (host or {}).get("device_id") or None,
        "sensor_version": (host or {}).get("agent_version") or None,
        "console_url": console_url(region, iid),
    })
    return row


def enrich(row, x):
    cc = x.get("cloud_context") or {}
    chost = cc.get("host") or {}
    try:
        cfg = json.loads(x.get("configuration") or "{}")
    except (TypeError, ValueError):
        cfg = {}
    tags = x.get("tags") or {}
    row.update({
        "account_name": x.get("account_name"),
        "name": x.get("resource_name"),
        "cspm_managed_by": cc.get("managed_by") or row["cspm_managed_by"],   # Sensor | Snapshot | Unmanaged
        "ssm_managed": chost.get("ssm_managed"),
        "os": chost.get("os_version") or chost.get("platform_name"),
        "instance_type": cfg.get("instanceType"),
        "private_ip": cfg.get("privateIpAddress"),
        "public_ip": cfg.get("publicIpAddress"),
        "launch_time": cfg.get("launchTime"),
        "first_seen": x.get("first_seen"),
        "asg": tags.get("aws:autoscaling:groupName"),
        "eks_cluster": tags.get("alpha.eksctl.io/cluster-name") or tags.get("eks:cluster-name"),
        "console_url": x.get("resource_url") or row["console_url"],
    })
    return row


class Writer:
    def __init__(self, path):
        self.n = 0
        self.fh = open(path, "w", newline="") if path else None
        self.csv = csv.DictWriter(self.fh, fieldnames=COLS) if self.fh else None
        if self.csv:
            self.csv.writeheader()

    def write(self, row):
        self.n += 1
        if self.csv:
            self.csv.writerow(row)
        else:
            print(json.dumps(row, default=str), flush=False)

    def close(self):
        if self.fh:
            self.fh.close()
        else:
            sys.stdout.flush()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--age", default="6h",
                   help="min time since first seen: 30m, 6h, 1d, 2w (default 6h). Second-level precision")
    p.add_argument("--days", type=float, help="legacy: same as --age <N>d")
    p.add_argument("--region", action="append", help="AWS region filter, repeatable (e.g. us-east-1)")
    p.add_argument("--source", choices=["hosts", "cspm"], default="hosts",
                   help="where 'sensor installed' comes from (default hosts; see top of file)")
    p.add_argument("--stale-after", default="24h",
                   help="--source hosts: sensor not seen for this long counts as unmanaged (default 24h)")
    p.add_argument("--sensor-fql", default="managed_by:!'Sensor'",
                   help="--source cspm: FQL clause for 'sensor installed = false'. managed_by values: "
                        "Sensor | Snapshot | Unmanaged")
    p.add_argument("--all", action="store_true", help="output every candidate with its status, not just unmanaged")
    p.add_argument("--no-details", action="store_true",
                   help="skip asset detail fetch: output account, region, instance ID, sensor status and console "
                        "URL only (fastest at very large scale)")
    p.add_argument("--workers", type=int, default=8, help="parallel API requests (default 8)")
    p.add_argument("--csv", help="write results to CSV (streamed)")
    p.add_argument("--env-file", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    a = p.parse_args()

    load_env(a.env_file)
    creds = dict(client_id=os.environ["FALCON_CLIENT_ID"], client_secret=os.environ["FALCON_CLIENT_SECRET"],
                 base_url=os.environ.get("FALCON_BASE_URL", "auto"))
    api = CloudSecurityAssets(**creds)
    age = parse_age(f"{a.days}d" if a.days is not None else a.age)
    now = datetime.now(timezone.utc)
    t0 = time.time()

    if a.source == "cspm":
        fql = build_fql(age, a.region, None if a.all else a.sensor_fql, now)
        log(f"FQL: {fql}")
        out_ids = query_all_ids(api, fql)
        log(f"{len(out_ids)} cloud assets matched ({time.time() - t0:.1f}s)")
        rows = {g: base_row(g, None, None, None) for g in out_ids}
    else:
        fql = build_fql(age, a.region, None, now)
        log(f"FQL: {fql}")
        ids = query_all_ids(api, fql)
        cspm_sensor = set(query_all_ids(api, fql + "+managed_by:'Sensor'"))      # CSPM view, IDs only
        log(f"{len(ids)} cloud assets matched, CSPM says {len(cspm_sensor)} have a sensor "
            f"({time.time() - t0:.1f}s)")
        iid_of = {g: parse_gcrn(g)[2] for g in ids}
        sensors = host_sensors_by_instance(Hosts(**creds), sorted(set(iid_of.values())), a.workers)
        log(f"Hosts lookup: {len(sensors)} instances have a Server sensor record ({time.time() - t0:.1f}s)")

        stale_after, rows, status_count, mism = parse_age(a.stale_after), {}, Counter(), []
        for g in ids:
            host = sensors.get(iid_of[g])
            status, unmanaged = classify(host, stale_after, now)
            status_count[status] += 1
            row = base_row(g, host, status, g in cspm_sensor)
            if row["cspm_mismatch"]:
                mism.append(row)
            if unmanaged or a.all:
                rows[g] = row
        log(f"Hosts sensor_status: {dict(status_count)}")
        log(f"CSPM managed_by (last scan) differs from live Hosts status on {len(mism)}" + (" (first 20):" if len(mism) > 20 else ":"))
        for r in mism[:20]:
            log(f"  {r['instance_id']} {r['region']}: cspm={r['cspm_managed_by']} hosts={r['sensor_status']}"
                f" last_seen={r['sensor_last_seen']}")

    w = Writer(a.csv)
    if a.no_details:
        for r in rows.values():
            w.write(r)
    else:
        for batch in fetch_details(api, list(rows), a.workers):
            for x in batch:
                r = rows.pop(x.get("id"), None)
                if r:
                    w.write(enrich(r, x))
        for r in rows.values():          # assets that disappeared between query and detail fetch
            w.write(r)
    w.close()
    if a.csv:
        log(f"wrote {w.n} rows to {a.csv}")
    log(f"{w.n} {'candidates' if a.all else 'unmanaged EC2 instances'} ({time.time() - t0:.1f}s)")


if __name__ == "__main__":
    main()
