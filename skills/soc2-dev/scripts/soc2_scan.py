#!/usr/bin/env python3
"""
soc2_scan.py — heuristic SOC 2 scanner for application repositories.

Finds obvious violations of the soc2-dev requirement registry and reports them with
requirement IDs, severity, file, line, and a fix hint. It is a lead generator for a
human or Claude review, not proof that a control exists.

Usage:
    python3 soc2_scan.py <repo-root> [--format md|json] [--config .soc2/config.yml]
                         [--fail-on critical|high|medium|none]
    python3 soc2_scan.py . --staged --fail-on high    # pre-commit gate

Exit code 1 when any finding meets or exceeds --fail-on (default: critical).
No third-party dependencies.

Suppress a single line with a trailing `soc2:ignore` comment (see SUPPRESS below).
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from typing import Iterable

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

ALWAYS_IGNORE_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "target", "out", ".next",
    "__pycache__", ".venv", "venv", "env", ".tox", ".mypy_cache", ".pytest_cache",
    "coverage", ".terraform", ".idea", ".vscode", "bin", "obj", ".claude", "reports",
}
CODE_EXT = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".java", ".kt",
    ".rb", ".php", ".cs", ".scala", ".rs", ".swift",
}
CONFIG_EXT = {
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".env", ".tf", ".hcl",
    ".properties", ".xml", ".conf", ".sh", ".sql",
}
MAX_FILE_BYTES = 1_000_000

# Per-line suppression. `soc2:ignore` is the canonical marker; the rest are accepted
# so repos already using gitleaks/detect-secrets conventions do not need a rewrite.
# `soc2:ignore-next-line` suppresses the following line instead, for languages where a
# trailing comment is awkward. A suppressed line must still be justified in review — it
# is not an exception record (those live in .soc2/EXCEPTIONS.md).
SUPPRESS = re.compile(
    r"(?i)(?:#|//|/\*|--|<!--)\s*(?:soc2:ignore|nosecret(?:-log|-sql)?|pragma:\s*allowlist\s+secret)"
)
SUPPRESS_NEXT = re.compile(r"(?i)(?:#|//|/\*|--|<!--)\s*soc2:ignore-next-line")


def suppressed_lines(text: str) -> set[int]:
    out: set[int] = set()
    for i, line in enumerate(text.splitlines(), 1):
        if SUPPRESS_NEXT.search(line):
            out.add(i + 1)
        elif SUPPRESS.search(line):
            out.add(i)
    return out

# Files allowed to enable debug: local/dev-only configuration.
DEBUG_ALLOWED_NAMES = {
    ".env.local", ".env.development", ".env.dev", ".env.test", ".env.example",
    "settings_local.py", "settings_dev.py", "conftest.py", "docker-compose.override.yml",
}


def git_staged_files(root: str) -> list[str]:
    """Paths staged for commit (added/copied/modified), absolute. Empty if not a repo."""
    try:
        out = subprocess.run(
            ["git", "-C", root, "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    return [os.path.join(root, p) for p in out.splitlines() if p.strip()]


# --------------------------------------------------------------------------- config


def load_config(path: str) -> dict:
    """Load .soc2/config.yml with PyYAML if available, else a minimal parser that
    understands the subset the template uses (nested maps, scalars, and lists)."""
    if not os.path.isfile(path):
        return {}
    text = open(path, encoding="utf-8", errors="replace").read()
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text) or {}
    except ImportError:
        pass
    return _mini_yaml(text)


def _mini_yaml(text: str) -> dict:
    root: dict = {}
    stack: list[tuple[int, dict | list]] = [(-1, root)]
    last_key_at: dict[int, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip() if not raw.strip().startswith('"') else raw.rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        content = line.strip()
        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if content.startswith("- "):
            val = _scalar(content[2:])
            if isinstance(parent, dict):
                key = last_key_at.get(stack[-1][0])
                if key is not None:
                    if not isinstance(parent.get(key), list):
                        parent[key] = []
                    parent[key].append(val)
            elif isinstance(parent, list):
                parent.append(val)
            continue
        if ":" in content:
            key, _, rest = content.partition(":")
            key = key.strip().strip('"').strip("'")
            rest = rest.strip()
            if not isinstance(parent, dict):
                continue
            if rest == "":
                child: dict = {}
                parent[key] = child
                last_key_at[indent] = key
                stack.append((indent, child))
            elif rest.startswith("[") and rest.endswith("]"):
                parent[key] = [_scalar(x) for x in rest[1:-1].split(",") if x.strip()]
            else:
                parent[key] = _scalar(rest)
                last_key_at[indent] = key
    return root


def _scalar(s: str):
    s = s.strip()
    if s.startswith(("'", '"')) and s.endswith(("'", '"')) and len(s) >= 2:
        return s[1:-1]
    low = s.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return s


# -------------------------------------------------------------------------- findings


@dataclass
class Finding:
    requirement: str
    severity: str
    confidence: str  # high | medium | low
    file: str
    line: int
    message: str
    fix: str
    snippet: str = ""
    check: str = ""

    def key(self):
        return (self.requirement, self.file, self.line, self.check)


class Scanner:
    def __init__(self, root: str, config: dict, staged: list[str] | None = None):
        self.root = os.path.abspath(root)
        self.cfg = config
        self.staged = staged
        self.findings: list[Finding] = []
        self.files: list[str] = []   # files to scan (the staged set, or the whole repo)
        self.corpus: list[str] = []  # whole repo, for presence/heuristic checks
        self.text_cache: dict[str, str] = {}
        self.cur_file = ""          # relpath being scanned, for suppression lookup
        self.cur_suppressed: set[int] = set()
        self.ignore_globs = [str(g) for g in (config.get("scan_ignore") or [])]
        self.public_routes = {self._norm_route(r) for r in (config.get("public_routes") or [])}
        tsc = config.get("tsc") or {}
        self.in_scope = {
            "A1": bool(tsc.get("availability", False)),
            "C1": bool(tsc.get("confidentiality", True)),
            "PI1": bool(tsc.get("processing_integrity", False)),
            "P": bool(tsc.get("privacy", False)),
        }
        self.repo_text = ""  # concatenated code for presence checks (bounded)

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _norm_route(r: str) -> str:
        r = str(r).strip()
        parts = r.split(None, 1)
        if len(parts) == 2:
            return f"{parts[0].upper()} {parts[1].rstrip('/') or '/'}"
        return f"* {r.rstrip('/') or '/'}"

    def rel(self, p: str) -> str:
        return os.path.relpath(p, self.root).replace(os.sep, "/")

    def add(self, **kw):
        f = Finding(**kw)
        if f.file == self.cur_file and f.line in self.cur_suppressed:
            return
        if f.key() not in {x.key() for x in self.findings}:
            self.findings.append(f)

    def ignored(self, relpath: str) -> bool:
        parts = relpath.split("/")
        if any(p in ALWAYS_IGNORE_DIRS for p in parts[:-1]):
            return True
        for g in self.ignore_globs:
            g = g.strip("/")
            if fnmatch.fnmatch(relpath, g) or fnmatch.fnmatch(relpath, f"**/{g}") or fnmatch.fnmatch(
                relpath, f"{g}/**"
            ) or any(fnmatch.fnmatch(p, g) for p in parts):
                return True
        return False

    def read(self, path: str) -> str:
        if path in self.text_cache:
            return self.text_cache[path]
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                return ""
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                t = fh.read()
        except OSError:
            t = ""
        self.text_cache[path] = t
        return t

    def _scannable(self, fn: str) -> bool:
        ext = os.path.splitext(fn)[1].lower()
        return (
            ext in CODE_EXT
            or ext in CONFIG_EXT
            or fn in ("Dockerfile", ".env", ".gitignore", "CODEOWNERS", "Gemfile", "Procfile")
            or fn.startswith("Dockerfile")
            or fn.startswith(".env")
        )

    def walk(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in ALWAYS_IGNORE_DIRS]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rp = self.rel(full)
                if self.ignored(rp):
                    continue
                if self._scannable(fn):
                    self.corpus.append(full)
        if self.staged is None:
            self.files = list(self.corpus)
            return
        # Staged mode scans only the change set, but presence heuristics (stack
        # detection, global auth middleware, library availability) must still see the
        # whole repo or every staged route looks unauthenticated.
        for full in self.staged:
            if not os.path.isfile(full):
                continue  # staged deletion, or a path outside the worktree
            rp = self.rel(full)
            if self.ignored(rp) or not self._scannable(os.path.basename(full)):
                continue
            self.files.append(full)

    def exists(self, *cands: str) -> str | None:
        for c in cands:
            p = os.path.join(self.root, c)
            if os.path.exists(p):
                return c
            # glob support
            if any(ch in c for ch in "*?["):
                d, pat = os.path.split(c)
                dd = os.path.join(self.root, d)
                if os.path.isdir(dd):
                    for fn in os.listdir(dd):
                        if fnmatch.fnmatch(fn, pat):
                            return os.path.join(d, fn)
        return None

    def any_file_matches(self, pattern: re.Pattern, exts: Iterable[str] | None = None) -> bool:
        for p in self.corpus:
            if exts and os.path.splitext(p)[1].lower() not in exts:
                continue
            if pattern.search(self.read(p)):
                return True
        return False

    # ------------------------------------------------------------------- run
    def run(self) -> list[Finding]:
        self.walk()
        self.detect_stack()
        for p in self.files:
            rp = self.rel(p)
            text = self.read(p)
            if not text:
                continue
            ext = os.path.splitext(p)[1].lower()
            base = os.path.basename(p)
            self.cur_file = rp
            self.cur_suppressed = suppressed_lines(text)
            self.check_secrets(rp, text)
            if ext in CODE_EXT:
                self.check_weak_crypto(rp, text)
                self.check_injection(rp, text)
                self.check_logging_pii(rp, text)
                self.check_tls_disabled(rp, text)
                self.check_cors(rp, text)
                self.check_debug(rp, text)
                self.check_routes(rp, text, ext)
                self.check_pii_in_url(rp, text)
            if ext in (".tf", ".hcl", ".json", ".yml", ".yaml"):
                self.check_infra(rp, text)
                self.check_tls_disabled(rp, text)
            # Debug flags live in config and dotenv files as often as in code (SEC-06).
            if ext in CONFIG_EXT or base.startswith(".env"):
                self.check_debug(rp, text)
            if base.startswith("Dockerfile"):
                self.check_dockerfile(rp, text)
        self.cur_file, self.cur_suppressed = "", set()
        if self.staged is None:
            # Repo-posture checks describe the whole repo, not the staged change set.
            self.check_repo_controls()
        self.findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.requirement, f.file, f.line))
        return self.findings

    # ------------------------------------------------------------ stack detect
    def detect_stack(self):
        self.stack = set()
        if self.exists("package.json"):
            self.stack.add("node")
            pj = self.read(os.path.join(self.root, "package.json"))
            for fw in ("express", "fastify", "@nestjs/core", "koa", "hapi", "next"):
                if f'"{fw}"' in pj:
                    self.stack.add(fw)
            self.package_json = pj
        else:
            self.package_json = ""
        if self.exists("pyproject.toml", "requirements.txt", "setup.py", "Pipfile"):
            self.stack.add("python")
        if self.exists("go.mod"):
            self.stack.add("go")
        if self.exists("pom.xml", "build.gradle", "build.gradle.kts"):
            self.stack.add("java")
        if self.exists("Gemfile"):
            self.stack.add("ruby")
        if self.exists("*.csproj", "*.sln"):
            self.stack.add("dotnet")
        # Global auth presence heuristics
        self.global_auth = bool(
            self.any_file_matches(
                re.compile(
                    r"(app|router|server|r|e|engine|mux)\.(use|Use)\(\s*[^)]*"
                    r"(auth|Auth|jwt|JWT|passport|protect|session|Session|requireLogin|bearer|Bearer)"
                ),
                CODE_EXT,
            )
            or self.any_file_matches(re.compile(r"SecurityFilterChain|WebSecurityConfigurerAdapter|@EnableWebSecurity"), {".java", ".kt"})
            or self.any_file_matches(re.compile(r"(APIRouter|include_router)\([^)]*dependencies\s*="), {".py"})
            or self.any_file_matches(re.compile(r"app\.add_middleware\([^)]*(Auth|auth|JWT|jwt)"), {".py"})
            or self.any_file_matches(re.compile(r"MIDDLEWARE\s*=\s*\[[^\]]*AuthenticationMiddleware"), {".py"})
            or self.any_file_matches(re.compile(r"before_action\s+:?(authenticate|require_login)"), {".rb"})
        )

    # ------------------------------------------------------------------ checks
    SECRET_PATTERNS = [
        ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
        ("Private key block", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "critical"),
        ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical"),
        ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"), "critical"),
        ("Stripe live key", re.compile(r"\b(sk|rk)_live_[0-9a-zA-Z]{16,}\b"), "critical"),
        ("Stripe test key", re.compile(r"\b(sk|rk)_test_[0-9a-zA-Z]{16,}\b"), "medium"),
        ("AWS secret access key", re.compile(r"(?i)aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]"), "critical"),
        ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
        ("JWT literal", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "high"),
        (
            "Hardcoded credential assignment",
            re.compile(
                r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|db[_-]?pass(word)?)\b"
                r"\s*[:=]\s*[\"'`]([^\"'`\s]{8,})[\"'`]"
            ),
            "high",
        ),
        ("Connection string with password", re.compile(r"(?i)\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^:/\s]+:[^@/\s]{4,}@"), "critical"),
    ]
    PLACEHOLDER = re.compile(
        r"(?i)(example|changeme|change_me|placeholder|your[_-]?|xxx|dummy|sample|test(ing)?[_-]?(key|secret|pass)|<[^>]+>|\$\{|\{\{|process\.env|os\.environ|getenv|secrets?\.|\*{3,}|redacted|fake|todo|lorem|\.\.\.|password123|hunter2)"
    )

    def check_secrets(self, rp: str, text: str):
        base = os.path.basename(rp)
        is_test = re.search(r"(^|/)(test|tests|spec|__tests__|fixtures|mocks?)(/|$)|\.(test|spec)\.", rp)
        is_example = base.endswith((".example", ".sample", ".template", ".dist"))
        if is_example:
            return
        for i, line in enumerate(text.splitlines(), 1):
            if len(line) > 500:
                continue
            for name, pat, sev in self.SECRET_PATTERNS:
                m = pat.search(line)
                if not m:
                    continue
                if name == "Hardcoded credential assignment":
                    val = m.group(m.lastindex or 0)
                    if self.PLACEHOLDER.search(line) or self.PLACEHOLDER.search(val):
                        continue
                    if re.search(r"(?i)(schema|type|field|column|input|label|name|placeholder|required|min|max|regex|pattern|validate|prop)", line) and not re.search(r"[A-Za-z0-9+/]{20,}", val):
                        continue
                sev_eff = "medium" if is_test and sev != "critical" else sev
                self.add(
                    requirement="SEC-01",
                    severity=sev_eff,
                    confidence="high" if name != "Hardcoded credential assignment" else "medium",
                    file=rp,
                    line=i,
                    message=f"{name} found in source",
                    fix="Move to a secret manager or environment injection; rotate the exposed value; add gitleaks pre-commit.",
                    snippet=_snip(line),
                    check="secret",
                )
        if base.startswith(".env") and not is_example:
            gi = self.read(os.path.join(self.root, ".gitignore"))
            if not re.search(r"(?m)^\s*\.env(\.\*|\*)?\s*$|^\s*\*\.env\s*$|^\s*\.env\.\S+", gi):
                self.add(
                    requirement="SEC-01",
                    severity="high",
                    confidence="high",
                    file=rp,
                    line=1,
                    message=".env file present and not git-ignored",
                    fix="Add `.env` and `.env.*` to .gitignore; keep only `.env.example` in the repo; rotate any values already committed.",
                    check="env-file",
                )

    WEAK_CRYPTO = [
        (re.compile(r"(?i)createHash\(\s*['\"](md5|sha1)['\"]|hashlib\.(md5|sha1)\(|MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"|\"crypto/(md5|sha1)\"|Digest::(MD5|SHA1)|md5\(|sha1\("), "Weak hash (MD5/SHA-1)"),
        (re.compile(r"(?i)\b(DES|3DES|TripleDES|RC4|Blowfish)\b.*(cipher|encrypt|Cipher|createCipher)|createCipher(iv)?\(\s*['\"](des|rc4|bf)"), "Weak cipher"),  # soc2:ignore pattern table, not a call site
        (re.compile(r"(?i)/ECB/|mode\s*=\s*.*MODE_ECB|cipher\.NewCipher\(.*\)\s*$"), "ECB mode"),  # soc2:ignore pattern table, not a call site
        (re.compile(r"(?i)\bMath\.random\(\)|\brandom\.(random|randint|choice)\(|\bmath/rand\b|\bnew Random\(\)"), "Non-cryptographic RNG"),
        (re.compile(r"(?i)(password|passwd).{0,40}(md5|sha1|sha256|sha512)\(|(md5|sha1|sha256|sha512)\(.{0,40}(password|passwd)"), "Password hashed with a fast hash"),
    ]

    def check_weak_crypto(self, rp: str, text: str):
        for i, line in enumerate(text.splitlines(), 1):
            for pat, label in self.WEAK_CRYPTO:
                if not pat.search(line):
                    continue
                if label == "Non-cryptographic RNG" and not re.search(r"(?i)(token|secret|password|nonce|salt|otp|key|session|reset|csrf|iv\b)", line):
                    continue
                if label == "Weak hash (MD5/SHA-1)" and re.search(r"(?i)(etag|checksum|cache[_-]?key|fingerprint|dedup|content[_-]?hash)", line):
                    sev, req, msg = "low", "SEC-07", f"{label} used for non-security purpose; confirm"
                else:
                    sev, req, msg = ("high", "AUTH-04", label) if "Password" in label else ("high", "SEC-07", label)
                self.add(
                    requirement=req, severity=sev, confidence="medium", file=rp, line=i, message=msg,
                    fix="Use AES-256-GCM/ChaCha20-Poly1305, SHA-256+, argon2id/bcrypt for passwords, and a CSPRNG (crypto.randomBytes, secrets, crypto/rand, SecureRandom).",
                    snippet=_snip(line), check="crypto",
                )

    INJECTION = [
        (re.compile(r"(?i)\b(execute|executemany|raw|query|exec|prepare|cursor\.execute|db\.raw|knex\.raw|sequelize\.query|prisma\.\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*(f[\"']|[\"'`][^\"'`]*(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)[^\"'`]*[\"'`]\s*\+|`[^`]*\$\{)"), "SQL built from string formatting or concatenation", "API-03", "high"),
        (re.compile(r"(?i)(fmt\.Sprintf|String\.format|\.format\(|%\s*\()\s*\(?\s*[\"'][^\"']*\b(SELECT|INSERT|UPDATE|DELETE)\b[^\"']*(%s|%d|%v|\{\})"), "SQL built with format string", "API-03", "high"),
        (re.compile(r"(?i)[\"']\s*(SELECT|INSERT|UPDATE|DELETE)\b[^\"']*(WHERE|VALUES|SET)[^\"']*[\"']\s*\+\s*[A-Za-z_]"), "SQL string concatenated with a variable", "API-03", "high"),
        # The three below tolerate quote characters *inside* the SQL literal
        # (`"... WHERE name = '" + name`), which the [^"']* patterns above cannot cross.
        (re.compile(r"(?i)[\"'][^\"']{0,4}\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,240}?[\"']\s*\+\s*[A-Za-z_]"), "SQL string concatenated with a variable", "API-03", "high"),
        (re.compile(r"(?i)[\"'][^\"']{0,4}\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,240}?[\"']\s*\.\s*format\s*\("), "SQL built with .format()", "API-03", "high"),
        (re.compile(r"(?i)[\"'][^\"']{0,4}\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,240}?[\"']\s*%\s*[\(\[]?\s*[A-Za-z_]"), "SQL built with %-interpolation", "API-03", "high"),
        (re.compile(r"(?i)\b(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output)\([^)]*shell\s*=\s*True|child_process\.exec\(|execSync\(|Runtime\.getRuntime\(\)\.exec\(|exec\.Command\(\s*\"(sh|bash|cmd)\")"), "Shell command execution; verify inputs are not user-controlled", "API-03", "medium"),
        (re.compile(r"(?<![A-Za-z_.])eval\s*\(|new Function\(|vm\.runIn"), "Dynamic code evaluation", "API-03", "high"),
        (re.compile(r"(?i)\$where\s*:|\{\s*\$where"), "MongoDB $where operator (JS injection)", "API-03", "high"),
    ]

    def check_injection(self, rp: str, text: str):
        for i, line in enumerate(text.splitlines(), 1):
            for pat, msg, req, sev in self.INJECTION:
                if pat.search(line):
                    self.add(
                        requirement=req, severity=sev, confidence="medium", file=rp, line=i, message=msg,
                        fix="Use parameterized queries or the ORM's bound-parameter API; for shell, use argument arrays without a shell and validate inputs against an allow-list.",
                        snippet=_snip(line), check="injection",
                    )

    # NOTE: `print(` is a separate alternative with its own paren. Folding it into the
    # group above would require `print((` to match, which silently disabled the check.
    LOG_CALL = re.compile(
        r"(?i)(?:\b(?:console\.(?:log|info|warn|error|debug)"
        r"|logger?\.(?:info|warn|warning|error|debug|trace|log|Printf|Println|Print|Infof|Errorf|Warnf|Debugf)"
        r"|logging\.(?:info|warning|error|debug)"
        r"|log\.(?:Printf|Println|Print)"
        r"|slog\.(?:Info|Warn|Error|Debug)"
        r"|fmt\.(?:Print|Printf|Println|Fprintf)"
        r"|System\.out\.print(?:ln)?"
        r"|zap\.[SL]\(\)\.\w+)\s*\("
        r"|(?<![\w.])print\s*\()"
    )
    LOG_SENSITIVE = re.compile(
        r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|token|access[_-]?token|refresh[_-]?token"
        r"|id[_-]?token|authorization|auth[_-]?header|bearer|ssn|social[_-]?security|credit[_-]?card"
        r"|card[_-]?number|cvv|req\.body|request\.body|req\.headers|request\.headers|\.cookies"
        r"|private[_-]?key|otp)\b"
        # Identifier-suffixed forms: generate_token(), user_secret, refresh_password.
        r"|[A-Za-z]+_(?:tokens?|secrets?|passwords?|credentials?)\b"
    )
    # A string literal with no interpolation is static text, not logged data.
    STATIC_STR = re.compile(r"""(['"`])(?:\\.|(?!\1)[^\\])*\1""")
    INTERPOLATED = re.compile(r"\$\{|\{[A-Za-z_][\w.\[\]'\"]*\}|%\(|%[sdrvf]\b|\{\}")

    @classmethod
    def _strip_static_strings(cls, line: str) -> str:
        """Blank out literal strings that interpolate nothing, so a help message
        mentioning 'secret-scan' is not mistaken for a logged credential."""
        return cls.STATIC_STR.sub(
            lambda m: m.group(0) if cls.INTERPOLATED.search(m.group(0)) else '""', line
        )

    def check_logging_pii(self, rp: str, text: str):
        for i, line in enumerate(text.splitlines(), 1):
            if self.LOG_CALL.search(line) and self.LOG_SENSITIVE.search(self._strip_static_strings(line)):
                if re.search(r"(?i)(redact|mask|sanitize|scrub|\*\*\*|\[REDACTED\])", line):
                    continue
                self.add(
                    requirement="LOG-03", severity="high", confidence="medium", file=rp, line=i,
                    message="Log statement references a secret, token, credential, or raw request payload",
                    fix="Log identifiers and outcomes only; pass objects through a redaction helper with a field deny-list before logging.",
                    snippet=_snip(line), check="log-pii",
                )

    TLS_OFF = re.compile(r"(?i)rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|sslmode\s*=\s*disable|ssl\s*[:=]\s*false|verify_ssl\s*=\s*False|CURLOPT_SSL_VERIFYPEER,\s*false|TrustAllCerts|trustAllCertificates|ALLOW_ALL_HOSTNAME_VERIFIER|\bhttp://[a-z0-9.-]*(api|auth|db|internal|service)[a-z0-9.-]*[:/]")  # soc2:ignore pattern table, not a call site

    def check_tls_disabled(self, rp: str, text: str):
        for i, line in enumerate(text.splitlines(), 1):
            if self.TLS_OFF.search(line) and not re.search(r"localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com", line):
                self.add(
                    requirement="DATA-03", severity="high", confidence="medium", file=rp, line=i,
                    message="TLS verification disabled or plaintext transport to a service",
                    fix="Enable certificate verification and TLS 1.2+; use https:// and sslmode=require (or verify-full) for databases.",
                    snippet=_snip(line), check="tls",
                )

    CORS_WILD = re.compile(r"(?i)(origin\s*:\s*['\"]\*['\"]|allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]|Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]|AllowAllOrigins\s*=\s*true|allowedOrigins\(\s*\"\*\"\s*\)|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|cors\(\)\s*[;)])")
    CORS_CREDS = re.compile(r"(?i)credentials\s*:\s*true|allow_credentials\s*=\s*True|AllowCredentials\s*=\s*true|allowCredentials\(\s*true|CORS_ALLOW_CREDENTIALS\s*=\s*True")

    def check_cors(self, rp: str, text: str):
        has_creds = bool(self.CORS_CREDS.search(text))
        for i, line in enumerate(text.splitlines(), 1):
            if self.CORS_WILD.search(line):
                self.add(
                    requirement="API-06", severity="high" if has_creds else "medium", confidence="medium", file=rp, line=i,
                    message="CORS allows any origin" + (" while credentials are enabled" if has_creds else ""),
                    fix="Use an explicit origin allow-list from config; never combine wildcard origins with credentials.",
                    snippet=_snip(line), check="cors",
                )

    DEBUG_ON = re.compile(r"(?i)^\s*DEBUG\s*=\s*True\b|debug\s*=\s*True\s*\)|app\.run\([^)]*debug\s*=\s*True|\bdebug\s*:\s*true\b|\"debug\"\s*:\s*true|--inspect\b|NODE_ENV\s*=\s*['\"]?development['\"]?|^\s*[A-Z_]*DEBUG\s*=\s*(1|true|on)\s*$|^\s*(APP_|DJANGO_|RAILS_)?DEBUG\s*=\s*['\"]?(1|true|on)['\"]?\s*$")

    def check_debug(self, rp: str, text: str):
        if re.search(r"(^|/)(test|tests|spec|dev|local|scripts?)(/|$)|settings/(dev|local)", rp):
            return
        if os.path.basename(rp) in DEBUG_ALLOWED_NAMES:
            return
        for i, line in enumerate(text.splitlines(), 1):
            if self.DEBUG_ON.search(line) and not re.search(r"(?i)os\.environ|getenv|process\.env|if\s+.*\b(dev|development|debug)\b", line):
                self.add(
                    requirement="SEC-06", severity="medium", confidence="low", file=rp, line=i,
                    message="Debug mode appears enabled unconditionally",
                    fix="Drive debug from an environment variable that is false in production; ensure verbose errors are disabled.",
                    snippet=_snip(line), check="debug",
                )

    # Route detection per framework -------------------------------------------------
    AUTHISH = re.compile(r"(?i)(auth|jwt|passport|protect|requireLogin|loginRequired|login_required|jwt_required|Depends\(|isAuthenticated|ensureLoggedIn|verifyToken|bearer|session|guard|@PreAuthorize|@Secured|@RolesAllowed|permission|current_user|get_current_user|authenticate|authorize|@UseGuards|checkJwt|requiresAuth|ApiKey|apiKey|hmac|signature)")
    ROUTE_PATTERNS = {
        "express": re.compile(r"\b(app|router|r|server|api|v\d)\.(get|post|put|patch|delete|all)\(\s*['\"`]([^'\"`]+)['\"`]"),
        "fastapi": re.compile(r"@(app|router|api|[a-z_]+_router)\.(get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]"),
        "flask": re.compile(r"@(app|bp|blueprint|[a-z_]+)\.route\(\s*['\"]([^'\"]+)['\"]"),
        "go": re.compile(r"\b(r|router|mux|e|g|api|v\d|group)\.(Get|Post|Put|Patch|Delete|GET|POST|PUT|PATCH|DELETE|HandleFunc|Handle)\(\s*\"([^\"]+)\""),
        "spring": re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(value\s*=\s*)?[\"']([^\"']+)[\"']"),
        "rails": re.compile(r"^\s*(get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]"),
    }

    def check_routes(self, rp: str, text: str, ext: str):
        lines = text.splitlines()
        file_has_auth = bool(self.AUTHISH.search(text))
        file_level_auth = bool(re.search(r"(?i)(router|app|r|group)\.(use|Use)\([^)]*(auth|jwt|protect|session)|dependencies\s*=\s*\[|@login_required\s*$|before_action|r\.Group\(|\.With\(\s*\w*[Aa]uth|\.Use\(\s*\w*[Aa]uth|@PreAuthorize\s*\(\s*\"(hasRole|isAuthenticated)", text))
        if ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
            fws = ["express"]
        elif ext == ".py":
            fws = ["fastapi", "flask"]
        elif ext == ".go":
            fws = ["go"]
        elif ext in (".java", ".kt"):
            fws = ["spring"]
        elif ext == ".rb":
            fws = ["rails"]
        else:
            return
        for fw in fws:
            pat = self.ROUTE_PATTERNS[fw]
            for i, line in enumerate(lines, 1):
                m = pat.search(line)
                if not m:
                    continue
                if fw == "flask":
                    method, path = "*", m.group(2)
                elif fw == "rails":
                    method, path = m.group(1).upper(), m.group(2)
                elif fw == "spring":
                    method = m.group(1).upper() if m.group(1) != "Request" else "*"
                    path = m.group(3)
                else:
                    method, path = m.group(2).upper(), m.group(3)
                    if method in ("HANDLEFUNC", "HANDLE", "ALL"):
                        method = "*"
                norm_path = path.rstrip("/") or "/"
                if f"{method} {norm_path}" in self.public_routes or f"* {norm_path}" in self.public_routes:
                    continue
                if re.search(r"(?i)(webhook|callback|/hooks?/|/events?/(stripe|github|slack|twilio|paddle|shopify))", norm_path):
                    self._check_webhook(rp, text, i, line, method, path)
                    continue
                if re.search(r"(?i)(health|ready|live|ping|metrics|status|login|signup|register|forgot|reset[-_]?password|oauth|\.well-known|docs|openapi|swagger|public|static)", norm_path):
                    continue
                window = "\n".join(lines[max(0, i - 4): i + 3])
                if self.AUTHISH.search(window):
                    continue
                if fw == "spring" and ("java" in self.stack) and self.global_auth:
                    continue  # Spring Security secures everything by default when configured
                if file_level_auth:
                    continue
                if self.global_auth:
                    sev, conf, msg = "low", "low", "Route has no visible auth in its file; a global auth middleware exists, confirm it covers this route"
                elif file_has_auth:
                    sev, conf, msg = "medium", "low", "Route has no auth guard on or near the handler; other routes in this file do"
                else:
                    sev, conf, msg = "high", "medium", "Route has no visible authentication and no global auth middleware was detected"
                self.add(
                    requirement="AUTH-01", severity=sev, confidence=conf, file=rp, line=i,
                    message=f"{msg}: {method} {path}",
                    fix="Apply the auth middleware/dependency/guard at router or app level (deny by default) and list intentionally public routes in .soc2/config.yml public_routes.",
                    snippet=_snip(line), check="route-auth",
                )

    WEBHOOK_VERIFY = re.compile(r"(?i)(timingSafeEqual|compare_digest|hmac\.Equal|MessageDigest\.isEqual|constructEvent|verifyWebhook|verify_signature|verifySignature|validateRequest|X-Hub-Signature|Stripe-Signature|Twilio-Signature|X-Slack-Signature|Paddle-Signature|X-Shopify-Hmac|webhooks\.verify|WebhookSignature|createHmac|hmac\.new|hmac\.New|Mac\.getInstance)")

    def _check_webhook(self, rp: str, text: str, i: int, line: str, method: str, path: str):
        if self.WEBHOOK_VERIFY.search(text):
            return
        self.add(
            requirement="API-11", severity="high", confidence="medium", file=rp, line=i,
            message=f"Webhook/callback route has no signature verification in its file: {method} {path}",
            fix="Verify an HMAC or provider signature over the raw body with a constant-time compare, reject stale timestamps, and dedupe on event ID before processing.",
            snippet=_snip(line), check="webhook-verify",
        )

    PII_URL = re.compile(r"(?i)['\"`/](:|\{|<)?(ssn|social_security|email|phone|dob|date_of_birth|card_number|password|token)[}>]?['\"`/?]")

    def check_pii_in_url(self, rp: str, text: str):
        for i, line in enumerate(text.splitlines(), 1):
            if any(self.ROUTE_PATTERNS[k].search(line) for k in ("express", "fastapi", "flask", "go", "spring")) and self.PII_URL.search(line):
                self.add(
                    requirement="DATA-06", severity="medium", confidence="medium", file=rp, line=i,
                    message="Route places personal data or a credential in the URL path",
                    fix="Use opaque identifiers in paths; send personal data and tokens in the body or headers.",
                    snippet=_snip(line), check="pii-url",
                )

    # Infrastructure --------------------------------------------------------------
    INFRA_RULES = [
        (re.compile(r"\"?Action\"?\s*[:=]\s*\[?\s*\"\*\""), "INFRA-03", "critical", "IAM policy allows all actions (*)", "Scope actions to what the workload needs; no wildcards in production policies."),
        (re.compile(r"actions\s*=\s*\[\s*\"\*\"\s*\]|\"Resource\"\s*:\s*\"\*\"[\s\S]{0,200}\"Action\"\s*:\s*\"\*\""), "INFRA-03", "critical", "IAM policy uses wildcard actions or resources", "Scope actions and resources; no wildcards in production policies."),
        (re.compile(r"cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\"\s*\]"), "INFRA-02", "high", "Security group rule open to the internet", "Restrict ingress to load balancers and known CIDRs; deny by default. Only 80/443 on public edges."),
        (re.compile(r"(?i)publicly_accessible\s*=\s*true"), "INFRA-02", "critical", "Database is publicly accessible", "Place databases in private subnets; publicly_accessible = false."),
        (re.compile(r"(?i)acl\s*=\s*\"public-read(-write)?\"|\"PublicRead\"|block_public_acls\s*=\s*false"), "INFRA-02", "critical", "Object storage is public", "Block public access at the account and bucket level; serve via signed URLs or CDN."),
        (re.compile(r"(?i)\b(encrypted|storage_encrypted|encryption_enabled|kms_key_id\s*=\s*null|at_rest_encryption_enabled)\s*=\s*false"), "INFRA-04", "high", "Encryption at rest disabled", "Enable encryption with a KMS-managed key on every datastore, volume, bucket, and queue."),
        (re.compile(r"(?i)aws_iam_access_key\b|\"AccessKeyId\"|aws_access_key_id\s*="), "INFRA-03", "medium", "Long-lived IAM access key defined", "Use IAM roles, instance profiles, or workload identity instead of static keys."),
        (re.compile(r"(?i)skip_final_snapshot\s*=\s*true|backup_retention_period\s*=\s*0"), "DATA-07", "medium", "Backups disabled or final snapshot skipped", "Set backup_retention_period ≥ 7 and take final snapshots; document RPO/RTO."),
        (re.compile(r"(?i)(minimum_protocol_version|min_tls_version|ssl_policy)\s*=\s*\"?(TLSv1(\.0|\.1)?|TLS_1_0|TLS_1_1|ELBSecurityPolicy-2016)"), "DATA-03", "high", "TLS below 1.2 allowed", "Require TLS 1.2+ on load balancers, CDNs, and databases."),
        (re.compile(r"(?i)(root_password|master_password|password)\s*=\s*\"[^\"$]{6,}\""), "SEC-01", "critical", "Infrastructure password hardcoded", "Generate with random_password and store in Secrets Manager; reference by ARN."),
    ]

    def check_infra(self, rp: str, text: str):
        if "/.soc2/" in "/" + rp or rp.startswith(".soc2/"):
            return
        for i, line in enumerate(text.splitlines(), 1):
            for pat, req, sev, msg, fix in self.INFRA_RULES:
                if pat.search(line):
                    if req == "INFRA-02" and "0.0.0.0/0" in line and re.search(r"(?i)egress", "\n".join(text.splitlines()[max(0, i - 6): i])):
                        continue
                    self.add(requirement=req, severity=sev, confidence="medium", file=rp, line=i, message=msg, fix=fix, snippet=_snip(line), check="infra")

    def check_dockerfile(self, rp: str, text: str):
        lines = text.splitlines()
        if not any(re.match(r"(?i)^\s*USER\s+(?!root\b)", l) for l in lines):
            self.add(requirement="SEC-05", severity="medium", confidence="high", file=rp, line=1,
                     message="Container runs as root (no USER instruction)",
                     fix="Add a non-root user and `USER app` before CMD/ENTRYPOINT.", check="docker-root")
        for i, l in enumerate(lines, 1):
            if re.match(r"(?i)^\s*FROM\s+\S+:latest\b|^\s*FROM\s+[^:@\s]+\s*$", l) and "scratch" not in l:
                self.add(requirement="SEC-05", severity="low", confidence="high", file=rp, line=i,
                         message="Base image not pinned",
                         fix="Pin the base image to a version tag or digest and rebuild on updates.", snippet=_snip(l), check="docker-pin")
            if re.search(r"(?i)^\s*(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|API_KEY)\w*\s*[= ]\s*\S{6,}", l) and not self.PLACEHOLDER.search(l):
                self.add(requirement="SEC-01", severity="high", confidence="medium", file=rp, line=i,
                         message="Secret baked into image via ENV/ARG",
                         fix="Inject secrets at runtime; never in build args or image layers.", snippet=_snip(l), check="docker-secret")

    # Repo-level controls ---------------------------------------------------------
    def check_repo_controls(self):
        R = "(repo)"
        ci_text = ""
        for cand in (".github/workflows", ".gitlab-ci.yml", ".circleci", "Jenkinsfile", "bitbucket-pipelines.yml", "azure-pipelines.yml", ".buildkite"):
            p = os.path.join(self.root, cand)
            if os.path.isdir(p):
                for fn in os.listdir(p):
                    ci_text += self.read(os.path.join(p, fn))
            elif os.path.isfile(p):
                ci_text += self.read(p)
        precommit = self.read(os.path.join(self.root, ".pre-commit-config.yaml")) + self.read(os.path.join(self.root, ".pre-commit-config.yml"))
        has_ci = bool(ci_text.strip())
        code_present = any(os.path.splitext(f)[1].lower() in CODE_EXT for f in self.corpus)

        if not has_ci:
            self.add(requirement="CHG-02", severity="high", confidence="high", file=R, line=0,
                     message="No CI configuration found; merges are not gated by tests or scans",
                     fix="Add a CI pipeline (see templates/github-workflow-soc2.yml) and make its jobs required status checks.", check="ci")
        else:
            if not re.search(r"(?i)gitleaks|trufflehog|detect-secrets|secret[-_ ]scan", ci_text + precommit):
                self.add(requirement="SEC-01", severity="medium", confidence="high", file=R, line=0,
                         message="No secret scanning in CI or pre-commit", fix="Add gitleaks to pre-commit and CI.", check="ci-secrets")
            if not re.search(r"(?i)npm audit|pnpm audit|yarn audit|pip-audit|safety|govulncheck|nancy|dependency-check|snyk|trivy|grype|osv-scanner|dependabot|renovate|bundler-audit|dotnet list package --vulnerable", ci_text) and not self.exists(".github/dependabot.yml", "renovate.json", ".renovaterc", ".renovaterc.json"):
                self.add(requirement="SEC-03", severity="medium", confidence="high", file=R, line=0,
                         message="No dependency vulnerability scanning (SCA) in CI and no Dependabot/Renovate config",
                         fix="Add an SCA step for the stack and enable Dependabot or Renovate.", check="ci-sca")
            if not re.search(r"(?i)semgrep|codeql|bandit|gosec|sonar|spotbugs|brakeman|eslint-plugin-security|security-scan|checkmarx|snyk code", ci_text):
                self.add(requirement="SEC-04", severity="medium", confidence="high", file=R, line=0,
                         message="No static analysis (SAST) with security rules in CI",
                         fix="Add Semgrep (p/security-audit) or CodeQL and block on high findings.", check="ci-sast")
            if not re.search(r"(?i)\b(test|pytest|jest|vitest|mocha|go test|gradle test|mvn (verify|test)|rspec|dotnet test)\b", ci_text):
                self.add(requirement="CHG-02", severity="medium", confidence="medium", file=R, line=0,
                         message="CI does not appear to run tests", fix="Run the test suite in CI and require it to pass before merge.", check="ci-tests")
        if not self.exists(".github/pull_request_template.md", ".github/PULL_REQUEST_TEMPLATE.md", ".github/PULL_REQUEST_TEMPLATE", "PULL_REQUEST_TEMPLATE.md", "docs/pull_request_template.md", ".gitlab/merge_request_templates"):
            self.add(requirement="CHG-03", severity="medium", confidence="high", file=R, line=0,
                     message="No pull request template", fix="Add templates/pull_request_template.md to .github/.", check="pr-template")
        if not self.exists(".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
            self.add(requirement="CHG-04", severity="medium", confidence="high", file=R, line=0,
                     message="No CODEOWNERS file; security-sensitive paths have no required reviewer",
                     fix="Add templates/CODEOWNERS and enable 'require review from Code Owners' in branch protection.", check="codeowners")
        if not self.exists("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
            self.add(requirement="SEC-03", severity="low", confidence="high", file=R, line=0,
                     message="No SECURITY.md with disclosure process and patch SLAs", fix="Add templates/SECURITY.md.", check="security-md")
        if not self.exists(".soc2/CONTROL_MAP.md"):
            self.add(requirement="EVD-01", severity="medium", confidence="high", file=R, line=0,
                     message="No .soc2/CONTROL_MAP.md; controls are not mapped to evidence", fix="Run scripts/soc2_init.py.", check="control-map")
        if not self.exists(".soc2/EXCEPTIONS.md"):
            self.add(requirement="EVD-03", severity="low", confidence="high", file=R, line=0,
                     message="No .soc2/EXCEPTIONS.md", fix="Run scripts/soc2_init.py.", check="exceptions")
        # Lockfiles
        if "node" in self.stack and not self.exists("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"):
            self.add(requirement="SEC-03", severity="medium", confidence="high", file="package.json", line=0,
                     message="No lockfile; dependency versions are not pinned", fix="Commit package-lock.json (or yarn/pnpm lock) and use `npm ci` in CI.", check="lockfile")
        if "python" in self.stack and not self.exists("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock", "requirements.lock"):
            req = self.read(os.path.join(self.root, "requirements.txt"))
            if not req or not re.search(r"==", req):
                self.add(requirement="SEC-03", severity="medium", confidence="medium", file="(repo)", line=0,
                         message="Python dependencies are not pinned (no lockfile and no == pins)", fix="Use a lockfile (uv, poetry, pip-tools) and pin versions.", check="lockfile")
        if "go" in self.stack and not self.exists("go.sum"):
            self.add(requirement="SEC-03", severity="medium", confidence="high", file="go.mod", line=0,
                     message="go.sum missing", fix="Commit go.sum.", check="lockfile")
        # Presence heuristics for code-level primitives
        if code_present:
            if not self.any_file_matches(re.compile(r"(?i)audit[_-]?(log|event|trail)|AuditLog|audit_events|auditlogger"), CODE_EXT):
                self.add(requirement="LOG-01", severity="medium", confidence="medium", file=R, line=0,
                         message="No audit log primitive detected (no identifier containing 'audit')",
                         fix="Add an append-only audit logger and emit events for auth, permission, admin, and restricted-data actions (see logging-and-audit.md).", check="audit-primitive")
            routes_exist = any(self.ROUTE_PATTERNS[k].search(self.read(p)) for p in self.corpus for k in self.ROUTE_PATTERNS if os.path.splitext(p)[1].lower() in CODE_EXT)
            if routes_exist:
                if not self.any_file_matches(re.compile(r"(?i)express-rate-limit|rate-limiter-flexible|rateLimit\(|slowapi|@limiter|ratelimit|Bucket4j|golang\.org/x/time/rate|tollbooth|httprate|throttle|Rack::Attack|ThrottlerModule"), CODE_EXT | {".json", ".toml", ".txt", ".mod", ".xml", ".gradle", ".kts"}):
                    self.add(requirement="API-04", severity="medium", confidence="medium", file=R, line=0,
                             message="No rate limiting library detected", fix="Add rate limiting on public and auth endpoints.", check="ratelimit")
                if not self.any_file_matches(re.compile(r"(?i)\bhelmet\b|secure_headers|SecurityHeaders|Strict-Transport-Security|headers\(\)\.\w*(hsts|contentSecurityPolicy)|secure\.New\(|SecureHeaders|X-Content-Type-Options"), CODE_EXT | {".json", ".toml", ".txt", ".mod", ".xml"}):
                    self.add(requirement="API-06", severity="medium", confidence="medium", file=R, line=0,
                             message="No security headers middleware detected", fix="Add helmet / secure-headers equivalent and HSTS.", check="headers")
                if not self.any_file_matches(re.compile(r"(?i)\bzod\b|\bjoi\b|\byup\b|express-validator|class-validator|pydantic|marshmallow|go-playground/validator|@Valid\b|jakarta\.validation|javax\.validation|ActiveModel::Validations|FluentValidation"), CODE_EXT | {".json", ".toml", ".txt", ".mod", ".xml", ".gradle", ".kts"}):
                    self.add(requirement="API-01", severity="medium", confidence="medium", file=R, line=0,
                             message="No schema validation library detected", fix="Validate every request against a schema and reject unknown fields.", check="validation")
            if self.any_file_matches(re.compile(r"(?i)password"), CODE_EXT) and not self.any_file_matches(re.compile(r"(?i)\bargon2|bcrypt|scrypt|pbkdf2|PasswordHasher|password_hash\(|make_password|has_secure_password"), CODE_EXT | {".json", ".toml", ".txt", ".mod", ".xml", ".gradle", ".kts"}):
                self.add(requirement="AUTH-04", severity="high", confidence="low", file=R, line=0,
                         message="Code handles passwords but no password hashing library was detected",
                         fix="Hash with argon2id or bcrypt (cost ≥ 12); never store or compare plaintext.", check="pw-hash")
            if self.any_file_matches(re.compile(r"(?i)\b(jwt|session|login|signin)\b"), CODE_EXT) and not self.any_file_matches(re.compile(r"(?i)\b(mfa|totp|2fa|two[_-]?factor|webauthn|otp)\b"), CODE_EXT):
                self.add(requirement="AUTH-03", severity="medium", confidence="low", file=R, line=0,
                         message="Authentication code present but no MFA/TOTP/WebAuthn implementation detected",
                         fix="Require MFA for admin/privileged accounts; offer it to all users (or enforce at the IdP and record an exception).", check="mfa")
        # Out-of-scope downgrade
        for f in self.findings:
            if f.requirement in ("INFRA-06",) and not self.in_scope["A1"]:
                f.severity = "info"


def _snip(line: str, n: int = 140) -> str:
    s = line.strip()
    return (s[: n - 3] + "...") if len(s) > n else s


# --------------------------------------------------------------------------- output


def to_markdown(findings: list[Finding], root: str) -> str:
    out = [f"# SOC 2 heuristic scan — `{os.path.basename(os.path.abspath(root))}`", ""]
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    out.append("| Severity | Count |\n|---|---|")
    for k in ("critical", "high", "medium", "low", "info"):
        out.append(f"| {k} | {counts[k]} |")
    out.append("")
    out.append("Findings are leads for review, not proof of a control's absence. Confidence reflects how likely the heuristic is right.")
    out.append("")
    by_req: dict[str, list[Finding]] = {}
    for f in findings:
        by_req.setdefault(f.requirement, []).append(f)
    for req in sorted(by_req, key=lambda r: (-max(SEVERITY_ORDER[x.severity] for x in by_req[r]), r)):
        fs = by_req[req]
        out.append(f"## {req} ({len(fs)})")
        out.append("")
        out.append("| Sev | Conf | Location | Finding | Fix |")
        out.append("|---|---|---|---|---|")
        for f in fs:
            loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
            esc = f.snippet.replace("|", "\\|")
            snippet = f" — `{esc}`" if f.snippet else ""
            out.append(f"| {f.severity} | {f.confidence} | {loc} | {f.message}{snippet} | {f.fix} |")
        out.append("")
    if not findings:
        out.append("No findings. Proceed to manual review of AUTH-01, AUTH-02, LOG-01, DATA-02, DATA-08.")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--config", default=None, help="path to .soc2/config.yml (default: <root>/.soc2/config.yml)")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="critical")
    ap.add_argument("--min-severity", choices=["critical", "high", "medium", "low", "info"], default="info", help="hide findings below this severity")
    ap.add_argument("--staged", action="store_true",
                    help="scan only files staged in git and skip repo-posture checks (pre-commit mode)")
    args = ap.parse_args(argv)

    cfg_path = args.config or os.path.join(args.root, ".soc2", "config.yml")
    cfg = load_config(cfg_path)

    staged = None
    if args.staged:
        staged = git_staged_files(args.root)
        if not staged:
            if args.format == "json":
                print(json.dumps({"root": os.path.abspath(args.root), "staged": True, "findings": []}, indent=2))
            else:
                print("No staged files to scan.")
            return 0

    sc = Scanner(args.root, cfg, staged=staged)
    findings = [f for f in sc.run() if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[args.min_severity]]

    if args.format == "json":
        print(json.dumps({"root": os.path.abspath(args.root), "staged": bool(args.staged),
                          "stack": sorted(sc.stack), "global_auth_detected": sc.global_auth,
                          "counts": {k: sum(1 for f in findings if f.severity == k) for k in SEVERITY_ORDER},
                          "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print(to_markdown(findings, args.root))

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
