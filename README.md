# blindspot

Find AWS EC2 instances running without a CrowdStrike Falcon sensor, including auto-scaling groups and EKS worker nodes.

| Tool | Finds | Data source |
|---|---|---|
| `unmanaged_ec2.cql` | Running instances launched recently, minutes after launch | NG-SIEM: CloudTrail + sensor telemetry |
| `unmanaged_ec2_ended.cql` | Short-lived instances that ran without a sensor and have already ended | NG-SIEM: CloudTrail + sensor telemetry |
| `unmanaged_ec2.py` | Everything in the cloud asset inventory, including sensors that stopped checking in | Cloud Security Assets + Hosts APIs |

For an initial assessment, run `unmanaged_ec2.cql` over the last 6 hours and the script with its default `--age 6h`. For ongoing coverage, schedule the queries every 15–30 minutes and the script less often. See [Scheduling](#scheduling).

## Setup

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env    # add FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, optionally FALCON_BASE_URL
```

Credentials can also come from environment variables. `.env` is git-ignored.

| API scope | Needed for |
|---|---|
| Cloud Security Assets: Read | `unmanaged_ec2.py` |
| Hosts: Read | `unmanaged_ec2.py` (default `--source hosts`) |
| NGSIEM: Read + Write | `ngsiem_query.py` (each query creates a search job) |

The NG-SIEM queries need AWS CloudTrail ingested through Falcon Cloud Security registration.

---

## `unmanaged_ec2.cql`: running instances

Paste into **Next-Gen SIEM → Advanced Event Search**, or run from the CLI:

```bash
.venv/bin/python ngsiem_query.py --file unmanaged_ec2.cql --start 6h
.venv/bin/python ngsiem_query.py --file unmanaged_ec2.cql --start 45m --arg grace_minutes=10
```

- **Instances:** CloudTrail `RunInstances` and `StartInstances` events, minus any instance with a later `Stop` or `TerminateInstances`.
- **Sensors:** the Falcon sensor sends an `InstanceMetadata` event with the EC2 instance ID about 40 s after boot. Only Server sensors count; Kubernetes cluster (KAC) records are excluded.
- **Grace period:** instances are flagged only after running longer than `grace_minutes` (default 15), allowing time for bootstrapping and sensor install.
- **Attribution:** `launched_by` is the caller's ARN, or the caller's account and principal ID for cross-account calls. `user_agent` shows the tool used (Terraform, CLI, console). `account` is the account that owns the instance.

**Columns:** account, region, instance ID, platform, type, private IP, launch time, minutes running, launched by, user agent, console URL.

> The **Table: sensors** tab in the console is an intermediate lookup. Results are on the first tab.

## `unmanaged_ec2_ended.cql`: short-lived instances

Instances that ran without a sensor and have since stopped or terminated, such as auto-scaling, CI and batch workloads that end between scheduled runs.

```bash
.venv/bin/python ngsiem_query.py --file unmanaged_ec2_ended.cql --start 24h
.venv/bin/python ngsiem_query.py --file unmanaged_ec2_ended.cql --start 2h --arg min_lifetime_minutes=0
```

- Uses the same lifecycle and sensor logic as `unmanaged_ec2.cql`. Both launch and end must fall inside the search window.
- `min_lifetime_minutes` (default 5) skips instances that ended too quickly for a sensor to check in, usually failed launches. Set `0` to see all, or match `grace_minutes` to see only instances that should have had a sensor.

**Columns:** account, region, instance ID, platform, type, private IP, launch time, end time, lifetime (minutes), stopped or terminated, launched by, ended by, user agent.

## `unmanaged_ec2.py`: full inventory

Reproduces the Cloud Security asset inventory filter *EC2 Instance, Active, Compute, Sensor installed = false, First seen before 1 day*, then checks each instance against live sensor status in the Hosts API.

```bash
.venv/bin/python unmanaged_ec2.py --csv unmanaged.csv            # first seen > 6h
.venv/bin/python unmanaged_ec2.py --age 1d                       # match the console filter
.venv/bin/python unmanaged_ec2.py --region us-east-1 --region us-west-2
.venv/bin/python unmanaged_ec2.py --all --csv all.csv            # every candidate, managed or not
.venv/bin/python unmanaged_ec2.py --no-details --csv ids.csv     # fastest
```

1. **Candidates:** active Compute EC2 instances first seen before `--age` (`30m`, `6h`, `1d`, `2w`).
2. **Sensor check:** each instance ID is looked up in the Hosts API, Server records only. EKS nodes with the DaemonSet sensor count as managed; KAC and pod records don't. If an instance has several host records, the most recently seen wins.
3. **Status:** `active` (checked in within `--stale-after`, managed), `stale` (sensor stopped checking in) or `none` (no sensor). `stale` and `none` are reported.

`cspm_mismatch` marks instances whose sensor status has changed since the last CSPM scan. `--source cspm` skips the Hosts lookup and uses the scan's `managed_by` value instead (`Sensor`, `Snapshot` or `Unmanaged`).

| Flag | Default | Description |
|---|---|---|
| `--age` | `6h` | Minimum time since first seen |
| `--region` | all | Region filter; repeatable |
| `--source` | `hosts` | `hosts` (live) or `cspm` (last scan) |
| `--stale-after` | `24h` | Sensor silent this long counts as unmanaged |
| `--sensor-fql` | `managed_by:!'Sensor'` | Filter used with `--source cspm` |
| `--all` | off | Output every candidate |
| `--no-details` | off | Skip asset details; output IDs, status and console URL only |
| `--workers` | `8` | Parallel API requests |
| `--csv` | JSON to stdout | Write CSV, streamed as batches complete |
| `--env-file` | `./.env` | Credentials file |

**Columns:** account ID and name, region, instance ID, name, sensor status, CSPM `managed_by`, mismatch flag, sensor last seen, AID and version, SSM-managed, OS, instance type, private and public IP, launch time, first seen, auto-scaling group, EKS cluster, console URL.

---

## Scheduling

| Tool | Schedule | Window |
|---|---|---|
| `unmanaged_ec2.cql` | Every 15–30 min | interval + `grace_minutes` + 15 min |
| `unmanaged_ec2_ended.cql` | Every 30–60 min | interval + longest lifetime to catch |
| `unmanaged_ec2.py` | Hourly to every few hours | `--age 1h`–`2h` |

For example, running `unmanaged_ec2.cql` every 15 minutes over 45 minutes reports an unmanaged instance 15–30 minutes after launch. Running `unmanaged_ec2_ended.cql` hourly over 3 hours catches instances that lived up to 2 hours.

- **Windows overlap on purpose.** The extra 15 minutes absorbs late events and delayed runs, so an instance can appear in consecutive runs. Deduplicate on `instance_id` rather than shortening the window.
- **Each query sees only launches inside its window.** Once an instance's launch falls outside it, tracking passes to the script.
- **The script counts from `first_seen`,** set when a CSPM scan first discovers the instance, which can trail launch by a scan cycle. A shorter `--age` on scheduled runs closes the gap with the queries.
- **The script also catches** accounts or regions not sending CloudTrail, instances launched before scheduling began, and stale sensors.

## Scale

Built for large environments with high launch rates.

- **Script:** candidate IDs are paged with `after` tokens, so inventory size is unbounded. Account, region and instance ID are parsed from the asset ID, so the sensor check needs no detail calls. Hosts lookups (100 IDs per request) and asset detail fetches (500 per request) run in parallel, and rows stream to CSV. 429 and 5xx responses are retried with backoff.
- **Queries:** aggregations use `limit=max` and results allow up to 200,000 rows. `ngsiem_query.py` stops a search after `--timeout` (default 900 s).

## Notes

- Only **Server** host records count as a sensor. To include Windows desktop OSes (*Workstation*) or domain controllers, extend `HOSTS_TYPE_FQL` in the script and the `ProductType` list in both queries.
- An instance that is stopped and started again moves from the ended query back to the running one.
- Console links open in the AWS account you're signed in to.
