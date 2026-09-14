#!/usr/bin/env python3
"""
soc2_init.py — scaffold SOC 2 repo controls.

Creates (never overwrites without --force):
  .soc2/config.yml              stack detected and filled in
  .soc2/CONTROL_MAP.md          requirement → implementation → evidence
  .soc2/EXCEPTIONS.md           recorded exceptions
  .soc2/reports/                scanner and gap reports
  .github/pull_request_template.md   (CHG-03)
  .github/CODEOWNERS                 (CHG-04)
  .github/workflows/soc2-gates.yml   (CHG-02, SEC-01, SEC-03, SEC-04, SEC-05)
  SECURITY.md                        (SEC-03)
  .pre-commit-config.yaml            (SEC-01) only if none exists
  .gitignore                         ensures .env is ignored (SEC-01)

Usage:
    python3 soc2_init.py [repo-root] [--company "Acme"] [--force] [--no-github]
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = os.path.join(HERE, "..", "templates")


def detect(root: str) -> dict:
    def has(*names):
        return any(os.path.exists(os.path.join(root, n)) for n in names)

    def read(name):
        p = os.path.join(root, name)
        return open(p, encoding="utf-8", errors="replace").read() if os.path.isfile(p) else ""

    lang = fw = ci = cloud = ""
    if has("package.json"):
        lang = "node"
        pj = read("package.json")
        for k, v in (("express", "express"), ("fastify", "fastify"), ("@nestjs/core", "nestjs"), ("koa", "koa"), ("next", "next")):
            if f'"{k}"' in pj:
                fw = v
                break
    elif has("pyproject.toml", "requirements.txt", "Pipfile", "setup.py"):
        lang = "python"
        blob = read("pyproject.toml") + read("requirements.txt") + read("Pipfile")
        for k in ("fastapi", "django", "flask"):
            if k in blob.lower():
                fw = k
                break
    elif has("go.mod"):
        lang = "go"
        gm = read("go.mod")
        for k, v in (("go-chi/chi", "chi"), ("gin-gonic/gin", "gin"), ("labstack/echo", "echo"), ("gofiber/fiber", "fiber")):
            if k in gm:
                fw = v
                break
    elif has("pom.xml", "build.gradle", "build.gradle.kts"):
        lang = "java"
        if "spring-boot" in (read("pom.xml") + read("build.gradle") + read("build.gradle.kts")):
            fw = "spring"
    elif has("Gemfile"):
        lang, fw = "ruby", "rails" if "rails" in read("Gemfile") else ""
    elif any(f.endswith((".csproj", ".sln")) for f in os.listdir(root)):
        lang = "dotnet"

    if has(".github/workflows"):
        ci = "github"
    elif has(".gitlab-ci.yml"):
        ci = "gitlab"
    elif has(".circleci"):
        ci = "circleci"

    everything = ""
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "node_modules", "vendor", "dist", "build", ".terraform")]
        for f in fn:
            if f.endswith((".tf", ".yml", ".yaml", ".json")) and len(everything) < 2_000_000:
                try:
                    everything += open(os.path.join(dp, f), encoding="utf-8", errors="replace").read()
                except OSError:
                    pass
    if re.search(r"(?i)\baws_|amazonaws|provider \"aws\"", everything):
        cloud = "aws"
    elif re.search(r"(?i)google_|googleapis|provider \"google\"", everything):
        cloud = "gcp"
    elif re.search(r"(?i)azurerm_|azure", everything):
        cloud = "azure"
    return {"language": lang, "framework": fw, "ci": ci, "cloud": cloud}


def write(root: str, rel: str, content: str, force: bool, created: list, skipped: list):
    dst = os.path.join(root, rel)
    if os.path.exists(dst) and not force:
        skipped.append(rel)
        return
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    with open(dst, "w", encoding="utf-8") as fh:
        fh.write(content)
    created.append(rel)


def tpl(name: str) -> str:
    return open(os.path.join(TEMPLATES, name), encoding="utf-8").read()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--company", default=None)
    ap.add_argument("--owner", default=None, help="default control owner, e.g. @security-team or an email")
    ap.add_argument("--force", action="store_true", help="overwrite existing files")
    ap.add_argument("--no-github", action="store_true", help="skip .github/ files (non-GitHub hosting)")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    created, skipped = [], []
    st = detect(root)

    cfg = tpl("soc2.config.yml")
    if args.company:
        cfg = cfg.replace('company: "[COMPANY NAME]"', f'company: "{args.company}"')
    if args.owner:
        cfg = cfg.replace('owner: "[security-owner@example.com]"', f'owner: "{args.owner}"')
    for k, v in st.items():
        if v:
            cfg = re.sub(rf'(?m)^(\s*{k}:\s*)""', rf'\1"{v}"', cfg)
    write(root, ".soc2/config.yml", cfg, args.force, created, skipped)
    write(root, ".soc2/CONTROL_MAP.md", tpl("CONTROL_MAP.md"), args.force, created, skipped)
    write(root, ".soc2/EXCEPTIONS.md", tpl("EXCEPTIONS.md"), args.force, created, skipped)
    os.makedirs(os.path.join(root, ".soc2", "reports"), exist_ok=True)
    write(root, ".soc2/reports/.gitkeep", "", False, created, skipped)

    write(root, "SECURITY.md", tpl("SECURITY.md"), args.force, created, skipped)
    if not (os.path.exists(os.path.join(root, ".pre-commit-config.yaml")) or os.path.exists(os.path.join(root, ".pre-commit-config.yml"))):
        write(root, ".pre-commit-config.yaml", tpl("pre-commit-config.yaml"), args.force, created, skipped)
    else:
        skipped.append(".pre-commit-config.yaml (exists; add the gitleaks hook manually)")

    if not args.no_github and st["ci"] in ("github", ""):
        write(root, ".github/pull_request_template.md", tpl("pull_request_template.md"), args.force, created, skipped)
        write(root, ".github/CODEOWNERS", tpl("CODEOWNERS"), args.force, created, skipped)
        write(root, ".github/workflows/soc2-gates.yml", tpl("github-workflow-soc2.yml"), args.force, created, skipped)
    else:
        skipped.append(".github/* (CI is not GitHub; port templates/github-workflow-soc2.yml to your CI)")

    # .gitignore: ensure .env is ignored
    gi_path = os.path.join(root, ".gitignore")
    gi = open(gi_path, encoding="utf-8", errors="replace").read() if os.path.isfile(gi_path) else ""
    if not re.search(r"(?m)^\s*\.env(\.\*)?\s*$", gi):
        with open(gi_path, "a", encoding="utf-8") as fh:
            fh.write(("\n" if gi and not gi.endswith("\n") else "") + "# SOC2:SEC-01 never commit secrets\n.env\n.env.*\n!.env.example\n")
        created.append(".gitignore (appended .env rules)")

    print("soc2-dev init")
    print(f"  root:      {root}")
    print(f"  detected:  language={st['language'] or '?'} framework={st['framework'] or '?'} ci={st['ci'] or '?'} cloud={st['cloud'] or '?'}")
    print("  created:")
    for c in created:
        print(f"    + {c}")
    if skipped:
        print("  skipped (already exist; use --force to overwrite):")
        for s in skipped:
            print(f"    - {s}")
    print("\nNext steps (cannot be automated from the repo):")
    print("  1. Edit .soc2/config.yml: company, TSC scope, data classes, public_routes.")
    print("  2. Enable branch protection on the default branch (CHG-01): require PR, 1 approval,")
    print("     dismiss stale reviews, require status checks: secret-scan, dependency-scan, static-analysis, tests.")
    print("     gh api -X PUT repos/{owner}/{repo}/branches/main/protection --input branch-protection.json")
    print("  3. Replace @security-team / @platform-team in .github/CODEOWNERS with real teams.")
    print("  4. Run: python3 <skill>/scripts/soc2_scan.py . --format md > .soc2/reports/scan-baseline.md")
    print("  5. Ask Claude: 'audit this repo for SOC 2' to turn the scan into a gap report.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
