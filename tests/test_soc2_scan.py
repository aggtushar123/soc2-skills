"""Regression tests for scripts/soc2_scan.py. Standard library only: `python3 -m unittest -v`."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "soc2-dev" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import soc2_scan  # noqa: E402


def write(root: Path, rel: str, body: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body).lstrip("\n"), encoding="utf-8")
    return p


def scan(root: Path, *args: str) -> dict:
    out = subprocess.run(
        [sys.executable, str(SCRIPTS / "soc2_scan.py"), str(root), "--format", "json", "--fail-on", "none", *args],
        capture_output=True, text=True, check=True,
    ).stdout
    return json.loads(out)


def findings(d: dict, requirement: str | None = None, file: str | None = None) -> list[dict]:
    return [
        f for f in d["findings"]
        if (requirement is None or f["requirement"] == requirement)
        and (file is None or f["file"].endswith(file))
    ]


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        capture_output=True, text=True, check=True,
    ).stdout


class TruePositives(unittest.TestCase):
    """Each planted violation must be reported with the right requirement ID."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        r = Path(cls.tmp.name)
        write(r, "package.json", '{"name":"bad","dependencies":{"express":"^4"}}')
        write(r, "src/app.js", """
            const express = require('express');
            const crypto = require('crypto');
            const app = express();
            const dbPassword = "SuperSecretPassw0rd!";
            app.use(require('cors')({ origin: '*', credentials: true }));
            app.get('/users/:id', (req, res) => {
              db.query("SELECT * FROM users WHERE id = " + req.params.id);
              console.log("login attempt", req.body.password);
              res.json({});
            });
            app.post('/admin/reset', (req, res) => { res.send(eval(req.body.code)); });
            app.get('/health', (req, res) => res.send('ok'));
            const h = crypto.createHash('md5').update(password).digest('hex');
            const token = Math.random().toString(36);
            """)
        write(r, "src/hooks.js", """
            const r = require('express').Router();
            r.post('/webhooks/stripe', (req, res) => { handle(req.body); res.end(); });
            """)
        write(r, "api/main.py", """
            from fastapi import FastAPI, Depends
            import requests
            app = FastAPI()
            @app.get("/invoices/{id}")
            def get_invoice(id: int):
                cur.execute(f"SELECT * FROM invoices WHERE id={id}")
                cur.execute("DELETE FROM logins WHERE id = {}".format(id))
                cur.execute("UPDATE t SET a = 1 WHERE id = %s" % id)
            @app.delete("/invoices/{id}")
            def delete_invoice(id: int, user=Depends(get_current_user)):
                return {}
            requests.get("https://api.internal/x", verify=False)
            AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            print(user_secret)
            DEBUG = True
            """)
        write(r, "infra/main.tf", """
            resource "aws_security_group_rule" "db" {
              type = "ingress"
              cidr_blocks = ["0.0.0.0/0"]
            }
            resource "aws_db_instance" "db" {
              publicly_accessible = true
              storage_encrypted = false
              master_password = "hunter22hunter22"
            }
            resource "aws_iam_policy" "admin" {
              policy = jsonencode({ Statement = [{ Action = "*", Resource = "*" }] })
            }
            """)
        write(r, "Dockerfile", "FROM node:latest\nENV API_TOKEN=abcdef1234567890\nCMD [\"node\"]\n")
        write(r, ".env", "DATABASE_URL=postgres://admin:s3cretpass@db.prod.internal:5432/app\n")
        write(r, ".gitignore", "node_modules\n")
        cls.d = scan(r)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def assert_hit(self, requirement, file, line=None, check=None):
        hits = findings(self.d, requirement, file)
        if line is not None:
            hits = [h for h in hits if h["line"] == line]
        if check is not None:
            hits = [h for h in hits if h["check"] == check]
        self.assertTrue(hits, f"expected {requirement} in {file} line={line} check={check}")

    def test_secrets(self):
        self.assert_hit("SEC-01", "src/app.js", 4)            # hardcoded credential
        self.assert_hit("SEC-01", "api/main.py", 13)          # AWS secret key
        self.assert_hit("SEC-01", ".env", 1, "secret")        # connection string
        self.assert_hit("SEC-01", ".env", 1, "env-file")      # not git-ignored
        self.assert_hit("SEC-01", "Dockerfile", 2)            # ENV secret
        self.assert_hit("SEC-01", "infra/main.tf", 8)         # master_password

    def test_injection(self):
        self.assert_hit("API-03", "src/app.js", 7)            # concat
        self.assert_hit("API-03", "src/app.js", 11)           # eval
        self.assert_hit("API-03", "api/main.py", 6)           # f-string
        self.assert_hit("API-03", "api/main.py", 7)           # .format
        self.assert_hit("API-03", "api/main.py", 8)           # %-interp

    def test_auth_routes(self):
        self.assert_hit("AUTH-01", "src/app.js", 6)
        self.assert_hit("AUTH-01", "src/app.js", 11)
        self.assert_hit("AUTH-01", "api/main.py", 4)
        self.assertFalse(findings(self.d, "AUTH-01", "src/app.js") and [h for h in findings(self.d, "AUTH-01", "src/app.js") if h["line"] == 12], "/health must not be flagged")
        self.assertFalse([h for h in findings(self.d, "AUTH-01", "api/main.py") if h["line"] == 9], "route with Depends must not be flagged")

    def test_webhook(self):
        self.assert_hit("API-11", "src/hooks.js", 2)

    def test_logging_pii(self):
        self.assert_hit("LOG-03", "src/app.js", 8)
        self.assert_hit("LOG-03", "api/main.py", 14)          # bare print(user_secret)

    def test_crypto_tls_cors_debug(self):
        self.assert_hit("SEC-07", "src/app.js", 13)
        self.assert_hit("SEC-07", "src/app.js", 14)
        self.assert_hit("DATA-03", "api/main.py", 12)
        self.assert_hit("API-06", "src/app.js", 5)
        self.assert_hit("SEC-06", "api/main.py", 15)

    def test_infra_and_docker(self):
        self.assert_hit("INFRA-02", "infra/main.tf", 3)
        self.assert_hit("INFRA-02", "infra/main.tf", 6)
        self.assert_hit("INFRA-04", "infra/main.tf", 7)
        self.assert_hit("INFRA-03", "infra/main.tf", 11)
        self.assert_hit("SEC-05", "Dockerfile", check="docker-root")
        self.assert_hit("SEC-05", "Dockerfile", check="docker-pin")

    def test_repo_posture(self):
        for req in ("CHG-02", "CHG-03", "CHG-04", "EVD-01", "SEC-03"):
            self.assertTrue(findings(self.d, req, "(repo)") or findings(self.d, req), req)

    def test_exit_code_gate(self):
        r = subprocess.run([sys.executable, str(SCRIPTS / "soc2_scan.py"), self.tmp.name, "--fail-on", "critical"], capture_output=True)
        self.assertEqual(r.returncode, 1)
        r = subprocess.run([sys.executable, str(SCRIPTS / "soc2_scan.py"), self.tmp.name, "--fail-on", "none"], capture_output=True)
        self.assertEqual(r.returncode, 0)


class FalsePositives(unittest.TestCase):
    """Ordinary, correct code must produce no file-level findings."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        r = Path(cls.tmp.name)
        write(r, "package.json", """
            { "name": "clean", "scripts": { "dev": "node --inspect src/index.js" },
              "dependencies": { "express": "^4", "helmet": "^7", "zod": "^3", "express-rate-limit": "^7", "argon2": "^0.40" } }
            """)
        write(r, "package-lock.json", "{}")
        write(r, "src/index.js", """
            const app = require('express')();
            app.use(require('./middleware/auth').requireAuth);
            async function listAll(pageToken) {
              const resp = await client.list({ next_token: pageToken });
              logger.info('listed page', { next_token: resp.next_token });
              logger.info(`request ${req.method} ${req.path} took ${ms}ms`);
              await http.request({ method: "DELETE", url: "/items/" + id });
              const label = "DELETE " + resourceName;
              const csrf_token = generateToken();
              console.log('csrf ok', csrf_token.length);
              const awsAccountId = "123456789012aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
              const q = sql`SELECT * FROM users WHERE id = ${id}`;
              return db.query("SELECT * FROM users WHERE id = $1", [id]);
            }
            app.get('/reports/:id', async (req, res) => res.json(await listAll()));
            """)
        write(r, "src/middleware/auth.js", "exports.requireAuth = (req, res, next) => next(); // SOC2:AUTH-01\n")
        write(r, "src/config.py", """
            import os, hashlib
            DEBUG = os.environ.get("DEBUG", "0") == "1"
            etag = hashlib.md5(body).hexdigest()  # cache_key only
            cursor.execute("SELECT * FROM t WHERE id = %s", (id,))
            print("Usage: run --with-secret-scan to enable secret scanning")
            logger.info("user %s logged in", user_id)
            password = os.environ["DB_PASSWORD"]
            """)
        write(r, "docker-compose.yml", "services:\n  app:\n    environment:\n      - NODE_ENV=development\n      - DEBUG=true\n")
        write(r, ".env.example", "DEBUG=true\nAWS_SECRET_ACCESS_KEY=your-secret-here\n")
        write(r, ".gitignore", ".env\n.env.*\n!.env.example\n")
        cls.d = scan(r)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_no_file_level_findings_at_medium_or_above(self):
        bad = [f for f in self.d["findings"] if f["file"] != "(repo)" and soc2_scan.SEVERITY_ORDER[f["severity"]] >= 2]
        self.assertEqual(bad, [], "\n".join(f"{f['severity']} {f['requirement']} {f['file']}:{f['line']} {f['snippet']}" for f in bad))

    def test_global_auth_detected(self):
        self.assertTrue(self.d["global_auth_detected"])


class Suppressions(unittest.TestCase):
    def test_inline_and_next_line(self):
        # Assembled at runtime so the test source never contains a string that
        # matches a live-key pattern (GitHub push protection rejects it otherwise).
        fake_key = "sk_" + "live_" + "51H" + "abcdefghijklmnopqrstuv"
        with tempfile.TemporaryDirectory() as t:
            r = Path(t)
            write(r, "a.js", f"""
                const k = "{fake_key}";  // soc2:ignore fixture value
                // soc2:ignore-next-line vendor SDK needs it
                console.log(req.headers.authorization);
                console.log(refresh_token);
                const j = "{fake_key}";  # pragma: allowlist secret
                """)
            d = scan(r)
            self.assertEqual([f["line"] for f in findings(d, file="a.js")], [4])


class StagedMode(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.r = Path(self.tmp.name)
        git(self.r, "init", "-q", "-b", "main")
        write(self.r, "src/ok.js", "module.exports = 1;\n")
        write(self.r, "package.json", '{"name":"x"}')
        git(self.r, "add", "-A")
        git(self.r, "commit", "-q", "-m", "base")
        write(self.r, "src/leak.js", 'const password = "Sup3rSecretValue!";\n')
        write(self.r, "docs/leak.js", 'const password = "An0therSecretValue!";\n')
        git(self.r, "add", "src/leak.js", "docs/leak.js")

    def tearDown(self):
        self.tmp.cleanup()

    def test_staged_scans_only_staged_and_skips_posture(self):
        d = scan(self.r, "--staged")
        self.assertTrue(d["staged"])
        self.assertEqual(sorted(f["file"] for f in d["findings"]), ["docs/leak.js", "src/leak.js"])
        self.assertFalse(findings(d, file="(repo)"))

    def test_staged_from_subdirectory_resolves_git_paths(self):
        d = scan(self.r / "src", "--staged")
        self.assertEqual([f["file"] for f in d["findings"]], ["leak.js"])

    def test_staged_with_nothing_staged(self):
        git(self.r, "reset", "-q")
        d = scan(self.r, "--staged")
        self.assertEqual(d["findings"], [])


class Config(unittest.TestCase):
    def test_public_routes_and_ignores_from_mini_yaml(self):
        with tempfile.TemporaryDirectory() as t:
            r = Path(t)
            write(r, ".soc2/config.yml", """
                tsc:
                  security: true
                public_routes:
                  - "GET /open"
                scan_ignore:
                  - legacy
                """)
            write(r, "app.js", "const app = require('express')();\napp.get('/open', h);\napp.get('/closed', h);\n")
            write(r, "legacy/old.js", 'const password = "Sup3rSecretValue!";\n')
            d = scan(r)
            self.assertEqual([f["line"] for f in findings(d, "AUTH-01", "app.js")], [3])
            self.assertFalse(findings(d, file="legacy/old.js"))

    def test_mini_yaml_parser(self):
        cfg = soc2_scan._mini_yaml("a:\n  b: 1\n  c: [x, y]\n  d:\n    - p\n    - q\n  e: \"s\"\nf: true\ng:\n- r\n- s\nh: 2\n")
        self.assertEqual(cfg, {"a": {"b": 1, "c": ["x", "y"], "d": ["p", "q"], "e": "s"}, "f": True, "g": ["r", "s"], "h": 2})
        # The shipped template must round-trip through the fallback parser.
        tpl = soc2_scan._mini_yaml((SCRIPTS.parent / "templates" / "soc2.config.yml").read_text())
        self.assertEqual(tpl["tsc"]["security"], True)
        self.assertEqual(tpl["auth"]["password_min_length"], 12)
        self.assertIn("GET /health", tpl["public_routes"])
        self.assertIn("node_modules", tpl["scan_ignore"])


if __name__ == "__main__":
    unittest.main()
