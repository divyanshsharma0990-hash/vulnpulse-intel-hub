"""CLI: generate a Markdown digest from watchlist.json (cron / Task Scheduler friendly).

    python digest.py --watchlist watchlist.json --days 1 --out digest.md
"""
import argparse
import json

from core import digest, enrich, nvd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--watchlist", default="watchlist.json")
    ap.add_argument("--days", type=int, default=1)
    ap.add_argument("--out", default="digest.md")
    args = ap.parse_args()

    with open(args.watchlist, encoding="utf-8") as f:
        products = json.load(f).get("products", [])

    records, seen = [], set()
    for p in products:
        try:
            for r in nvd.search_recent(p, args.days):
                if r["id"] not in seen:
                    seen.add(r["id"])
                    records.append({**r, "product": p})
        except Exception as exc:
            print(f"[warn] {p}: {exc}")

    records = enrich.enrich_records(records)
    md = digest.build_markdown(records, products, args.days)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"Wrote {args.out} ({len(records)} CVEs)")


if __name__ == "__main__":
    main()
