#!/usr/bin/env python3
"""Run an NG-SIEM (CQL) query via falconpy and print the events as JSON lines.

usage: ngsiem_query.py '<cql>' [--start 7d] [--repo search-all] [--file query.cql]
Requires API scope: NGSIEM: Read + Write (search jobs are created via POST).
"""
import argparse, json, os, sys, time
from falconpy import NGSIEM
from unmanaged_ec2 import load_env

p = argparse.ArgumentParser()
p.add_argument("query", nargs="?")
p.add_argument("--file", help="read CQL from file")
p.add_argument("--start", default="7d")
p.add_argument("--repo", default="search-all")
p.add_argument("--max", type=int, default=200, help="max events to print (-1 = all)")
p.add_argument("--timeout", type=int, default=900, help="seconds to wait for the search (default 900)")
p.add_argument("--arg", action="append", default=[], help="query parameter k=v (for ?{k=...} in CQL)")
a = p.parse_args()
q = open(a.file).read() if a.file else a.query
load_env(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
api = NGSIEM(client_id=os.environ["FALCON_CLIENT_ID"], client_secret=os.environ["FALCON_CLIENT_SECRET"],
             base_url=os.environ.get("FALCON_BASE_URL", "auto"))
args = dict(x.split("=", 1) for x in a.arg)
r = api.start_search(repository=a.repo, query_string=q, start=a.start, is_live=False, arguments=args)
if r["status_code"] not in (200, 201):
    sys.exit(f"start_search HTTP {r['status_code']}: {r.get('body') or r.get('resources')}")
sid = (r.get("resources") or r.get("body") or {}).get("id")
deadline, delay = time.time() + a.timeout, 0.5
while True:
    if time.time() > deadline:
        api.stop_search(repository=a.repo, id=sid)
        sys.exit(f"search did not finish within {a.timeout}s (stopped)")
    s = api.get_search_status(repository=a.repo, search_id=sid)
    b = s.get("body") or s.get("resources") or {}
    if int(s["status_code"]) != 200:
        sys.exit(f"status HTTP {s['status_code']}: {b}")
    if b.get("done"):
        break
    time.sleep(delay)
    delay = min(delay * 2, 5)        # back off: 0.5s -> 5s
ev = b.get("events") or []
print(f"{len(ev)} events  meta={json.dumps({k: b.get('metaData', {}).get(k) for k in ('eventCount', 'processedEvents')})}", file=sys.stderr)
for e in (ev if a.max < 0 else ev[:a.max]):
    print(json.dumps(e, default=str))
