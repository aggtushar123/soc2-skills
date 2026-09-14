#!/usr/bin/env python3
"""
control_map.py — reconcile SOC2:<ID> code annotations with .soc2/CONTROL_MAP.md.

Reports:
  * annotations whose ID is not in the requirement registry (typo)
  * requirements annotated in code but marked missing / absent in CONTROL_MAP.md
  * CONTROL_MAP rows whose implementation path no longer exists
  * a per-requirement annotation index (with --index)

Usage:
    python3 control_map.py [repo-root] [--strict] [--index] [--json]

Exit code 1 with --strict when drift is found.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(HERE, "..", "references", "requirements.md")
IGNORE_DIRS = {".git", "node_modules", "vendor", "dist", "build", "target", "__pycache__", ".venv", "venv", ".terraform", ".soc2"}
ANNOT = re.compile(r"SOC2:([A-Z]+-\d{2})\b")
ROW = re.compile(r"^\|\s*([A-Z]+-\d{2})\s*\|\s*([a-z/]+)\s*\|\s*([^|]*)\|")
PATH_IN_CELL = re.compile(r"`([^`:\s]+?\.[A-Za-z0-9]+)(?::[^`]*)?`")


def registry_ids() -> set[str]:
    ids = set()
    if os.path.isfile(REGISTRY):
        for line in open(REGISTRY, encoding="utf-8"):
            m = re.match(r"^\|\s*([A-Z]+-\d{2})\s*\|", line)
            if m:
                ids.add(m.group(1))
    return ids


def scan_annotations(root: str) -> dict[str, list[tuple[str, int, str]]]:
    found: dict[str, list[tuple[str, int, str]]] = {}
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in IGNORE_DIRS]
        for f in fn:
            p = os.path.join(dp, f)
            try:
                if os.path.getsize(p) > 1_000_000:
                    continue
                with open(p, encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        for m in ANNOT.finditer(line):
                            found.setdefault(m.group(1), []).append((os.path.relpath(p, root).replace(os.sep, "/"), i, line.strip()[:120]))
            except OSError:
                continue
    return found


def parse_map(path: str) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    if not os.path.isfile(path):
        return rows
    in_example = False
    for line in open(path, encoding="utf-8"):
        if line.startswith("## Example"):
            in_example = True
        if in_example:
            continue
        m = ROW.match(line)
        if m:
            rows[m.group(1)] = {"status": m.group(2).strip(), "impl": m.group(3).strip(), "paths": PATH_IN_CELL.findall(m.group(3))}
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--index", action="store_true", help="print every annotation grouped by requirement")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)

    ids = registry_ids()
    ann = scan_annotations(root)
    cmap = parse_map(os.path.join(root, ".soc2", "CONTROL_MAP.md"))

    unknown = {k: v for k, v in ann.items() if ids and k not in ids}
    annotated_not_mapped = sorted(k for k in ann if k not in unknown and (k not in cmap or cmap[k]["status"] in ("missing", "")))
    stale_rows = []
    for rid, row in cmap.items():
        for pth in row["paths"]:
            if not os.path.exists(os.path.join(root, pth)):
                stale_rows.append((rid, pth))
    mapped_met_unannotated = sorted(k for k, r in cmap.items() if r["status"] == "met" and k not in ann and k.split("-")[0] in ("AUTH", "API", "DATA", "LOG", "SEC"))

    drift = bool(unknown or annotated_not_mapped or stale_rows)
    if args.json:
        print(json.dumps({
            "annotations": {k: [{"file": f, "line": l, "text": t} for f, l, t in v] for k, v in ann.items()},
            "unknown_ids": sorted(unknown), "annotated_not_mapped": annotated_not_mapped,
            "stale_rows": stale_rows, "met_without_annotation": mapped_met_unannotated, "drift": drift}, indent=2))
    else:
        print(f"control_map: {len(ann)} requirement IDs annotated across {sum(len(v) for v in ann.values())} sites; "
              f"{len(cmap)} rows in CONTROL_MAP.md")
        if not cmap:
            print("  ! .soc2/CONTROL_MAP.md not found or empty (EVD-01). Run soc2_init.py.")
        if unknown:
            print("  ! Unknown requirement IDs in annotations (typo or not in registry):")
            for k, v in sorted(unknown.items()):
                for f, l, _ in v:
                    print(f"      {k}  {f}:{l}")
        if annotated_not_mapped:
            print("  ! Annotated in code but CONTROL_MAP.md row is missing/absent — update the map:")
            for k in annotated_not_mapped:
                f, l, _ = ann[k][0]
                print(f"      {k}  e.g. {f}:{l}")
        if stale_rows:
            print("  ! CONTROL_MAP.md rows pointing at files that no longer exist:")
            for rid, pth in stale_rows:
                print(f"      {rid}  {pth}")
        if mapped_met_unannotated:
            print("  ~ Marked met in the map but no SOC2:<ID> annotation found in code (EVD-02, advisory):")
            print("      " + ", ".join(mapped_met_unannotated))
        if not drift:
            print("  ok: no drift between annotations and CONTROL_MAP.md")
        if args.index:
            print("\nAnnotation index:")
            for k in sorted(ann):
                print(f"  {k}")
                for f, l, t in ann[k]:
                    print(f"    {f}:{l}  {t}")
    return 1 if (args.strict and drift) else 0


if __name__ == "__main__":
    sys.exit(main())
