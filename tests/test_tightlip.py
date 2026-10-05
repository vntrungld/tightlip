"""Tests for tightlip.py.  Run from the repo root:  python3 -m unittest discover -v tests

Every fake credential is generated at runtime, so this file contains no literal
token that a secret scanner (or GitHub push protection) would flag.
"""

import json
import os
import random
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugins", "tightlip", "scripts")
os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp()  # keep the HMAC key out of the real ~/.config
os.environ["XDG_STATE_HOME"] = tempfile.mkdtemp()   # and the gate markers out of ~/.local/state
sys.path.insert(0, HERE)
import tightlip as sg  # noqa: E402

RNG = random.Random(1337)
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
HEX = "0123456789abcdef"
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
URLSAFE = ALNUM + "-_"


def rnd(n, alphabet=ALNUM):
    return "".join(RNG.choice(alphabet) for _ in range(n))


def p(*parts):
    """Join prefix parts so token prefixes never appear literally in this file."""
    return "".join(parts)


SAMPLES = {
    "aws-access-key-id": p("AK", "IA") + rnd(16, B32),
    "github-token": p("gh", "p_") + rnd(36),
    "github-pat": p("github", "_pat_") + rnd(82, ALNUM + "_"),
    "gitlab-token": p("gl", "pat-") + rnd(20, URLSAFE),
    "slack-token": p("xo", "xb-") + "-".join([rnd(12, "0123456789"), rnd(12, "0123456789"), rnd(24)]),
    "slack-webhook": p("https://hooks.", "slack.com/services/") + "T" + rnd(10) + "/B" + rnd(10) + "/" + rnd(24),
    "stripe-key": p("sk", "_live_") + rnd(24),
    "google-api-key": p("AI", "za") + rnd(35, URLSAFE),
    "llm-api-key": p("sk-", "proj-") + rnd(48, URLSAFE) + "9Z1",
    "digitalocean-token": p("do", "p_v1_") + rnd(64, HEX),
    "shopify-token": p("shp", "at_") + rnd(32, HEX),
    "sendgrid-key": p("S", "G.") + rnd(22, URLSAFE) + "." + rnd(43, URLSAFE),
    "npm-token": p("np", "m_") + rnd(36),
    "telegram-bot-token": rnd(9, "123456789") + ":" + p("A", "A") + rnd(33, URLSAFE),
    "sentry-token": p("sntr", "ys_") + rnd(60),
    "huggingface-token": p("h", "f_") + rnd(34),
    "atlassian-api-token": p("ATA", "TT3") + rnd(186, URLSAFE),
    "laravel-app-key": p("base", "64:") + rnd(43, ALNUM + "+/") + "=",
    "jwt": p("ey", "J") + rnd(20, URLSAFE) + "." + p("ey", "J") + rnd(30, URLSAFE) + "." + rnd(43, URLSAFE),
}

PEM = (p("-----BEGIN ", "RSA PRIVATE KEY-----") + "\n"
       + "\n".join(rnd(64, ALNUM + "+/") for _ in range(5)) + "\n"
       + p("-----END ", "RSA PRIVATE KEY-----"))

DB_PW = rnd(20)
LARAVEL_ENV = f"""APP_NAME=Laravel
APP_ENV=local
APP_KEY={SAMPLES['laravel-app-key']}
APP_DEBUG=true
APP_URL=http://localhost
LOG_CHANNEL=stack
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=teeinblue
DB_USERNAME=root
DB_PASSWORD={DB_PW}
SESSION_DRIVER=database
SESSION_LIFETIME=120
BCRYPT_ROUNDS=12
REDIS_PASSWORD=null
MAIL_PASSWORD=null
MAIL_FROM_ADDRESS="hello@example.com"
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
PUSHER_APP_KEY=
VITE_PUSHER_APP_KEY="${{PUSHER_APP_KEY}}"
SHOPIFY_API_SECRET={rnd(32, HEX)}
STRIPE_SECRET="{SAMPLES['stripe-key']}"
CACHE_PREFIX=
JWT_TTL=60
"""

# Things an agent reads all the time that must come through untouched.
NOT_SECRETS = [
    # Python / Ruby module constants
    "METADATA_KEY = 'pydantic-mypy-metadata'",
    "    ACCESS_KEY = 'AWS_ACCESS_KEY_ID'",
    "EMRFS_SSE_KEY = 'fs.s3.enableServerSideEncryption'",
    "SALT_CHARS = \"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\"",
    "ROLE_POLICY_NAME = 'AmazonElasticMapReduceforEC2Role'",
    # docs placeholders
    "KEY=value", "pass --config KEY=VALUE", "API_TOKEN=changeme",
    # parser state names in bundled JS
    'lastSignificantToken = "?ArrowFunctionParamsJSX";',
    # grep -rn output of source and config
    "src/app.py:12:MAX_RETRIES=3",
    "src/app.js:4:const RESET_TOKEN = 'passwords.token';",
    "./.env:3:DB_PASSWORD=${DB_PASSWORD_FROM_VAULT}",
    "./.env-7-REDIS_PASSWORD=null",
    # Laravel validation, config, migrations, factories
    "'password' => 'required|string|min:8|confirmed',",
    "'password' => ['required', Password::defaults()],",
    "'key' => env('APP_KEY'),",
    "'secret' => env('STRIPE_SECRET'),",
    "'password' => Hash::make($request->password),",
    "'password_confirmation' => 'required',",
    "$table->string('password');",
    "$table->rememberToken();",
    "'table' => 'password_reset_tokens',",
    "'password' => 'The provided password is incorrect.',",
    # JS / TS
    "const apiKey = process.env.OPENAI_API_KEY;",
    "  apiKey: process.env.STRIPE_KEY,",
    "  password: string | null;",
    "  token: req.headers.authorization,",
    "secret: config.get('jwt.secret'),",
    # Python
    "SECRET_KEY = os.environ['SECRET_KEY']",
    "api_key = settings.OPENAI_API_KEY",
    "token = None",
    "password = getpass.getpass()",
    # translation files
    '{"password": "Mật khẩu", "Password": "Password", "token": "Token"}',
    # lock files, hashes, ids
    '"integrity": "sha512-' + rnd(86, ALNUM + "+/") + '==",',
    "commit " + rnd(40, HEX),
    "id: 3f2c9a8e-1b7d-4c5e-9f0a-2d6b8e4c1a7f",
    "GIT_SHA=" + rnd(40, HEX),
    # compose / CI with references
    "      DB_PASSWORD: ${DB_PASSWORD}",
    "      password: ${{ secrets.DOCKER_PASSWORD }}",
    "DATABASE_URL=postgres://user:${DB_PASSWORD}@db:5432/app",
    "export GITHUB_TOKEN=$(gh auth token)",
    # URLs, docs, placeholders
    "https://example.com:8080/path?page=2&sort=name",
    "https://docs.example.com/search?key=react-hooks",
    "Authorization: Bearer <token>",
    "API_KEY=your_api_key_here",
    "TOKEN=xxxxxxxxxxxxxxxxxxxx",
    # k8s describe output
    "password:  16 bytes",
    "Type:  Opaque",
    # regressions found by scanning laravel/framework, CPython and npm
    "const INVALID_TOKEN = 'passwords.token';",
    'LOOKUP_KEY = "SELECT value FROM Dict WHERE key = CAST(? AS BLOB)"',
    "MAX_KEY_PARTS: Final = sys.getrecursionlimit()",
    "KEY_LEFT = Ctrl-B, KEY_RIGHT = Ctrl-F, KEY_UP = Ctrl-P,",
    "TOKEN_ENDS = TSPECIALS | WSP",
    "    'pwd': 'pwd#module-pwd',",
    "const { regKey: scopeAuthKey, authKey: _authKey } = regFromURI(registry, opts)",
    "state.output += token.output != null ? token.output : token.value;",
    "askPassSetInConfig: config?.core?.askpass !== undefined,",
    'key="-----BEGIN PRIVATE KEY-----\\nXXXX\\nXXXX\\n-----END PRIVATE KEY-----"',
    "SOABI=\t\tcpython-313-x86_64-linux-gnu",
    "LIBHACL_SHA2_A= Modules/_hacl/libHacl_Hash_SHA2.a",
    "'password' => '--password='.$connection['password'],",
    "$this->p->setPath('http://website.com?key=value%20with%20spaces');",
]


def redact(text):
    r = sg.Redactor(key=b"k" * 32)
    return r.redact_text(text), r


def run_hook(payload, env=None):
    proc = subprocess.run(
        [sys.executable, os.path.join(HERE, "tightlip.py")],
        input=json.dumps(payload).encode(), capture_output=True,
        env={**os.environ, **(env or {})}, timeout=20,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    out = proc.stdout.decode().strip()
    return json.loads(out) if out else None


class FormatRules(unittest.TestCase):
    def test_each_known_format_is_redacted(self):
        for name, secret in SAMPLES.items():
            with self.subTest(rule=name):
                out, r = redact(f"value: {secret} end")
                self.assertNotIn(secret, out)
                self.assertRegex(out, sg.PLACEHOLDER_RE)

    def test_private_key_block_keeps_line_count(self):
        text = "before\n" + PEM + "\nafter"
        out, r = redact(text)
        self.assertNotIn("PRIVATE KEY", out)
        self.assertEqual(text.count("\n"), out.count("\n"))
        self.assertTrue(out.endswith("\nafter"))

    def test_truncated_private_key(self):
        head = "\n".join(PEM.splitlines()[:3])
        out, _ = redact(head)
        self.assertNotIn(PEM.splitlines()[1], out)

    def test_private_key_inside_json_service_account(self):
        sa = json.dumps({"type": "service_account", "private_key": PEM + "\n"})
        out, _ = redact(sa)
        self.assertNotIn(PEM.splitlines()[2], out)
        json.loads(out)  # still valid JSON

    def test_placeholder_ids_are_stable_and_distinct(self):
        a, b = SAMPLES["github-token"], p("gh", "p_") + rnd(36)
        out, _ = redact(f"{a} {a} {b}")
        ids = sg.PLACEHOLDER_RE.findall(out)
        self.assertEqual(ids[0], ids[1])
        self.assertNotEqual(ids[0], ids[2])

    def test_idempotent(self):
        text = LARAVEL_ENV + "\n" + PEM + "\n" + " ".join(SAMPLES.values())
        once, _ = redact(text)
        twice, r2 = redact(once)
        self.assertEqual(once, twice)
        self.assertEqual(r2.hits, [])

    def test_example_values_are_ignored(self):
        out, r = redact(p("AK", "IA") + "IOSFODNN7" + "EXAMPLE")
        self.assertEqual(r.hits, [])


class ContextRules(unittest.TestCase):
    def test_url_credentials(self):
        pw = rnd(16)
        out, _ = redact(f"DATABASE_URL=mysql://forge:{pw}@10.0.0.5:3306/app")
        self.assertNotIn(pw, out)
        self.assertIn("mysql://forge:[REDACTED:", out)
        self.assertIn("@10.0.0.5:3306/app", out)

    def test_auth_headers(self):
        t1, t2 = rnd(40, URLSAFE), rnd(32)
        out, _ = redact(f'curl -H "Authorization: Bearer {t1}" -H "X-Shopify-Access-Token: {t2}"')
        self.assertNotIn(t1, out)
        self.assertNotIn(t2, out)

    def test_cli_flag_and_query(self):
        pw, sig = rnd(14), rnd(64, HEX)
        out, _ = redact(f"mysql --password={pw} db\nhttps://bucket.s3.amazonaws.com/x?X-Amz-Signature={sig}&a=1")
        self.assertNotIn(pw, out)
        self.assertNotIn(sig, out)

    def test_k8s_env_list_and_artisan_dump(self):
        v1, v2 = rnd(18), rnd(18)
        yaml = f"    env:\n    - name: DB_PASSWORD\n      value: {v1}\n    - name: APP_ENV\n      value: production\n"
        dots = f"  connections.mysql.password ................................ {v2}\n  connections.mysql.port ........ 3306\n"
        out, _ = redact(yaml + dots)
        self.assertNotIn(v1, out)
        self.assertNotIn(v2, out)
        self.assertIn("value: production", out)
        self.assertIn("3306", out)


class GenericRules(unittest.TestCase):
    def test_laravel_env(self):
        out, r = redact(LARAVEL_ENV)
        self.assertNotIn(DB_PW, out)
        self.assertNotIn(SAMPLES["laravel-app-key"], out)
        self.assertNotIn(SAMPLES["stripe-key"], out)
        for line in ["APP_NAME=Laravel", "DB_HOST=127.0.0.1", "DB_PORT=3306", "REDIS_PASSWORD=null",
                     "SESSION_LIFETIME=120", 'VITE_PUSHER_APP_KEY="${PUSHER_APP_KEY}"', "JWT_TTL=60",
                     "AWS_SECRET_ACCESS_KEY=\n", "DB_USERNAME=root"]:
            self.assertIn(line, out)
        self.assertEqual(len(r.hits), 4)  # APP_KEY, DB_PASSWORD, SHOPIFY_API_SECRET, STRIPE_SECRET

    def test_quoted_and_json_and_yaml(self):
        v = [rnd(20) for _ in range(4)]
        text = (f'export OPENAI_API_KEY="{v[0]}"\n'
                f'{{"client_secret":"{v[1]}","token_type":"bearer"}}\n'
                f"  password: {v[2]}\n"
                f"'secret' => '{v[3]}',\n")
        out, _ = redact(text)
        for s in v:
            self.assertNotIn(s, out)
        self.assertIn('"token_type":"bearer"', out)

    def test_inline_env_assignment_in_command(self):
        pw = rnd(16)
        out, _ = redact(f"DB_PASSWORD={pw} php artisan migrate")
        self.assertNotIn(pw, out)
        self.assertIn("php artisan migrate", out)

    def test_python_constants(self):
        tok, conf, pw = rnd(28), rnd(32), rnd(12)
        out, _ = redact(f"    AUTH_TOKEN = '{tok}'\nSERVICE_CONF = \"{conf}\"\nDB_PASSWORD=\"{pw}\"\n")
        for s in (tok, conf, pw):
            self.assertNotIn(s, out)

    def test_constants_across_languages(self):
        forms = [
            "{k} = '{v}'", "const {k} = '{v}';", "export const {k}: string = '{v}';",
            "    public const {k} = '{v}';", "define('{k}', '{v}');",
            '    private static final String {k} = "{v}";', 'const val {k} = "{v}"',
            '    public const string {c} = "{v}";', 'const {c} = "{v}"', '\t{k} = "{v}"',
            'const {k}: &str = "{v}";', "{k} = '{v}'.freeze", '#define {k} "{v}"',
            'let {l} = "{v}"', 'let {l}: String = "{v}"', '@{s} "{v}"', 'readonly {k}="{v}"',
        ]
        secret = rnd(28)
        for form in forms:
            with self.subTest(form=form):
                safe = form.format(k="METADATA_KEY", c="MetadataKey", l="metadataKey", s="metadata_key",
                                   v="metadata-config-key")
                self.assertEqual(redact(safe)[0], safe)
                out, _ = redact(form.format(k="API_KEY", c="ApiKey", l="apiKey", s="api_key", v=secret))
                self.assertNotIn(secret, out)

    def test_grep_and_cat_n_line_prefixes(self):
        pw = rnd(16)
        for prefix in ("49:", "48-", "./.env:49:", "./.env-48-", "./.env:", "    49\t", "conf/app.ini:3:"):
            for line in (f"DB_PASSWORD={pw}", f"password = {pw}"):
                with self.subTest(prefix=prefix, line=line):
                    out, _ = redact(prefix + line)
                    self.assertNotIn(pw, out)
                    self.assertTrue(out.startswith(prefix), out)

    def test_high_entropy_value_without_keyword(self):
        v = rnd(32)
        out, _ = redact(f"MY_SERVICE_CONF={v}")
        self.assertNotIn(v, out)

    def test_real_world_config_files(self):
        v = [rnd(24) for _ in range(5)]
        npm_legacy = "3f2c9a8e-1b7d-4c5e-9f0a-" + rnd(12, HEX)
        text = (f"services:\n  db:\n    environment:\n      MYSQL_ROOT_PASSWORD: {v[0]}\n"
                f"users:\n- name: admin\n  user:\n    client-key-data: {v[1]}9\n    token: {SAMPLES['jwt']}\n"
                f"//registry.npmjs.org/:_authToken={npm_legacy}\n"
                f'{{"access_token":"{v[2]}","expires_in":3600}}\n'
                f'{{"http-basic": {{"nova.laravel.com": {{"username": "a@b.c", "password": "{v[3]}"}}}}}}\n'
                f"spring.datasource.password={v[4]}\n")
        out, _ = redact(text)
        for s in v + [npm_legacy, SAMPLES["jwt"]]:
            self.assertNotIn(s, out)
        self.assertIn('"expires_in":3600', out)

    def test_false_positives(self):
        for text in NOT_SECRETS:
            with self.subTest(text=text):
                out, r = redact(text)
                self.assertEqual(out, text, r.hits)


class ShapeAndWalk(unittest.TestCase):
    def test_bash_response_shape(self):
        resp = {"stdout": LARAVEL_ENV, "stderr": "", "interrupted": False, "isImage": False}
        r = sg.Redactor(key=b"k" * 32)
        new = r.walk(resp)
        self.assertEqual(set(new), set(resp))
        self.assertIs(new["interrupted"], False)
        self.assertNotIn(DB_PW, new["stdout"])

    def test_read_response_line_count(self):
        content = "line1\n" + PEM + "\nline3\n"
        resp = {"type": "text", "file": {"filePath": "/x/key.pem", "content": content,
                                         "numLines": content.count("\n"), "startLine": 1, "totalLines": 9}}
        new = sg.Redactor(key=b"k" * 32).walk(resp)
        self.assertEqual(new["file"]["content"].count("\n"), content.count("\n"))
        self.assertEqual(new["file"]["numLines"], resp["file"]["numLines"])

    def test_base64_blob_is_skipped(self):
        blob = rnd(20000, ALNUM + "+/")
        resp = {"type": "image", "file": {"base64": blob, "type": "image/png"}}
        self.assertEqual(sg.Redactor(key=b"k" * 32).walk(resp), resp)

    def test_performance(self):
        big = (LARAVEL_ENV + "\n".join(NOT_SECRETS) + "\n") * 120  # ~250 KB
        t = time.time()
        redact(big)
        self.assertLess(time.time() - t, 3.0)


class PreToolUse(unittest.TestCase):
    def decide(self, tool, tool_input, env=None):
        old = dict(os.environ)
        os.environ.update(env or {})
        try:
            out = sg.on_pre_tool_use({"tool_name": tool, "tool_input": tool_input, "cwd": "/home/u/app"})
        finally:
            os.environ.clear()
            os.environ.update(old)
        return out and out["hookSpecificOutput"]["permissionDecision"]

    def bash(self, cmd, env=None):
        return self.decide("Bash", {"command": cmd}, env)

    def test_denied_commands(self):
        for cmd in ["env", "printenv", "env -0", "printenv -0", "env | grep -i aws", "export -p", "set",
                    "gh auth token", "gh auth status --show-token", "gh auth token | cat",
                    "gcloud auth print-access-token", "aws configure get aws_secret_access_key",
                    "kubectl get secret db -o yaml", "kubectl get secrets -n prod -ojson",
                    "kubectl -n prod get configmap,secret -o=yaml",
                    "cat ~/.ssh/id_ed25519", "sudo -u deploy cat /home/deploy/.ssh/id_rsa",
                    "head -5 ~/.aws/credentials", "grep -r token ~/.aws", "cat ~/.kube/config",
                    "docker exec app env", "kubectl exec pod -- printenv",
                    "secret-tool lookup service github", "op read op://vault/item/password",
                    "echo $DB_PASSWORD", 'echo "token is ${GITHUB_TOKEN}"', "printenv OPENAI_API_KEY",
                    "cat /proc/1/environ", "cat ~/.claude/.credentials.json",
                    "cd app && cat storage/oauth-private.key"]:
            with self.subTest(cmd=cmd):
                self.assertEqual(self.bash(cmd), "deny")

    def test_allowed_commands(self):
        for cmd in ["printenv HOME", "env | cut -d= -f1", "env FOO=1 npm test", "cat .env",
                    "GH_TOKEN=$(gh auth token) gh api user",
                    "aws ecr get-login-password | docker login --password-stdin 123.dkr.ecr.aws",
                    "gh auth token > /tmp/t", "kubectl get secrets", "kubectl describe secret db",
                    "kubectl get secret db -o name", "cat ~/.ssh/id_ed25519.pub", "cat ~/.ssh/config",
                    "ssh -i ~/.ssh/id_rsa deploy@host uptime", '[ -n "$DB_PASSWORD" ] && echo set',
                    "echo ${#DB_PASSWORD}", 'echo "DB_PASSWORD=$DB_PASSWORD" >> .env.testing',
                    "php artisan migrate --force 2>&1 | tail -20", "git log --oneline -5"]:
            with self.subTest(cmd=cmd):
                self.assertIsNone(self.bash(cmd))

    def test_dotenv_strict_mode(self):
        self.assertEqual(self.bash("cat .env", {"TIGHTLIP_BLOCK_DOTENV": "1"}), "deny")
        self.assertEqual(self.decide("Read", {"file_path": "/home/u/app/.env.production"},
                                     {"TIGHTLIP_BLOCK_DOTENV": "1"}), "deny")
        self.assertIsNone(self.decide("Read", {"file_path": "/home/u/app/.env.example"},
                                      {"TIGHTLIP_BLOCK_DOTENV": "1"}))
        self.assertIsNone(self.decide("Read", {"file_path": "/home/u/app/.env"}))

    def test_read_and_grep_tools(self):
        home = os.path.expanduser("~")
        self.assertEqual(self.decide("Read", {"file_path": home + "/.aws/credentials"}), "deny")
        self.assertEqual(self.decide("Read", {"file_path": home + "/.docker/config.json"}), "deny")
        self.assertEqual(self.decide("Grep", {"pattern": "x", "path": home + "/.ssh"}), "deny")
        self.assertIsNone(self.decide("Read", {"file_path": "/home/u/app/config/database.php"}))

    def test_placeholder_cannot_be_written_back(self):
        ph = "[REDACTED:env-secret:0a1b2c3d]"
        self.assertEqual(self.decide("Write", {"file_path": "/a/.env", "content": f"DB_PASSWORD={ph}\n"}), "deny")
        self.assertEqual(self.decide("Edit", {"file_path": "/a/.env", "old_string": f"X={ph}",
                                              "new_string": "Y=1"}), "deny")
        self.assertEqual(self.bash(f"curl -H 'Authorization: Bearer {ph}' https://api"), "deny")
        self.assertEqual(self.decide("mcp__slack__send", {"text": ph}), "deny")
        self.assertIsNone(self.decide("Edit", {"file_path": "/a/x.php", "old_string": "a", "new_string": "b"}))


class Handlers(unittest.TestCase):
    def test_post_tool_use_rewrites_only_when_needed(self):
        payload = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "cat .env"},
                   "tool_response": {"stdout": LARAVEL_ENV, "stderr": "", "interrupted": False, "isImage": False}}
        out = run_hook(payload)
        new = out["hookSpecificOutput"]["updatedToolOutput"]
        self.assertNotIn(DB_PW, json.dumps(out))
        self.assertEqual(set(new), {"stdout", "stderr", "interrupted", "isImage"})
        self.assertIn("[REDACTED:", out["hookSpecificOutput"]["additionalContext"])
        self.assertIn("tightlip", out["systemMessage"])
        payload["tool_response"]["stdout"] = "nothing to see"
        self.assertIsNone(run_hook(payload))

    def test_post_tool_use_mcp_list_output(self):
        tok = SAMPLES["github-token"]
        payload = {"hook_event_name": "PostToolUse", "tool_name": "mcp__atlassian__getJiraIssue",
                   "tool_input": {}, "tool_response": [{"type": "text", "text": f"creds: {tok}"}]}
        out = run_hook(payload, {"TIGHTLIP_QUIET": "1"})
        self.assertNotIn(tok, json.dumps(out))
        self.assertNotIn("systemMessage", out)
        self.assertIsInstance(out["hookSpecificOutput"]["updatedToolOutput"], list)

    def test_batch_gate_blocks_unredacted_results(self):
        leaked = {"hook_event_name": "PostToolBatch", "session_id": "gate-test", "tool_calls": [
            {"tool_name": "Read", "tool_input": {}, "tool_response": "1\tAPP_NAME=x"},
            {"tool_name": "Bash", "tool_input": {}, "tool_response": f"Exit code 1\nDB_PASSWORD={DB_PW}"}]}
        out = run_hook(leaked)
        self.assertEqual(out["decision"], "block")
        self.assertIn("Bash", out["reason"])
        self.assertNotIn(DB_PW, json.dumps(out))
        clean = {"hook_event_name": "PostToolBatch", "tool_calls": [
            {"tool_name": "Bash", "tool_input": {},
             "tool_response": "DB_PASSWORD=[REDACTED:env-secret:0a1b2c3d]\nDB_HOST=127.0.0.1"}]}
        self.assertIsNone(run_hook(clean))

    def test_batch_gate_reason_points_at_files(self):
        out = run_hook({"hook_event_name": "PostToolBatch", "session_id": "gate-where", "tool_calls": [
            {"tool_name": "Bash", "tool_input": {"command": f"DB_PASSWORD={DB_PW} cat .env && exit 3"},
             "tool_response": f"Exit code 3\nAPP_ENV=local\nDB_PASSWORD={DB_PW}"},
            {"tool_name": "Grep", "tool_input": {"pattern": "PASSWORD", "path": "config"},
             "tool_response": f"config/.env.prod:12:DB_PASSWORD={DB_PW}\n2024-01-05 log line"},
            {"tool_name": "Read", "tool_input": {"file_path": "/srv/app/.env"},
             "tool_response": f"40\tAPP_ENV=x\n41\tDB_PASSWORD={DB_PW}"}]})
        reason = out["reason"]
        self.assertNotIn(DB_PW, json.dumps(out))
        self.assertIn("cat .env && exit 3`: dòng 3 của output", reason)
        self.assertIn("config/.env.prod:12", reason)
        self.assertIn("/srv/app/.env:41", reason)

    def test_next_prompt_after_gate_block_warns_once(self):
        state = {"XDG_STATE_HOME": tempfile.mkdtemp()}
        sid = {"session_id": "s-123"}
        run_hook({"hook_event_name": "PostToolBatch", **sid, "tool_calls": [
            {"tool_name": "Bash", "tool_input": {}, "tool_response": f"DB_PASSWORD={DB_PW}"}]}, state)
        prompt = {"hook_event_name": "UserPromptSubmit", **sid, "prompt": "tiếp tục đi"}
        first = run_hook(prompt, state)
        self.assertEqual(first["decision"], "block")
        self.assertIn("/rewind", first["reason"])
        self.assertIsNone(run_hook(prompt, state))  # second time goes through
        other = {"hook_event_name": "UserPromptSubmit", "session_id": "other", "prompt": "hi"}
        self.assertIsNone(run_hook(other, state))

    def test_prompt_with_secret_is_blocked(self):
        out = run_hook({"hook_event_name": "UserPromptSubmit",
                        "prompt": f"deploy with token {SAMPLES['digitalocean-token']}"})
        self.assertEqual(out["decision"], "block")
        self.assertTrue(out["hookSpecificOutput"]["suppressOriginalPrompt"])
        self.assertNotIn(SAMPLES["digitalocean-token"], json.dumps(out))
        self.assertIsNone(run_hook({"hook_event_name": "UserPromptSubmit",
                                    "prompt": "why does the password reset email not send?"}))

    def test_session_start_names_new_sessions_only(self):
        start = {"hook_event_name": "SessionStart", "source": "startup", "cwd": "/home/u/teeinblue-backend"}
        out = run_hook(start)
        self.assertTrue(out["hookSpecificOutput"]["sessionTitle"].startswith("teeinblue-backend "))
        self.assertIsNone(run_hook({**start, "source": "resume"}))
        self.assertIsNone(run_hook({**start, "session_title": "my name"}))
        self.assertIsNone(run_hook(start, {"TIGHTLIP_NAME_SESSIONS": "0"}))
        self.assertIsNone(run_hook(start, {"CLAUDE_PLUGIN_OPTION_NAME_SESSIONS": "false"}))

    def test_plugin_options(self):
        resp = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {},
                "tool_response": {"stdout": f"DB_PASSWORD={DB_PW}", "stderr": "", "interrupted": False, "isImage": False}}
        self.assertNotIn("systemMessage", run_hook(resp, {"CLAUDE_PLUGIN_OPTION_QUIET": "true"}))
        self.assertIsNone(run_hook(resp, {"CLAUDE_PLUGIN_OPTION_ALLOW_REGEX": DB_PW}))
        read = {"hook_event_name": "PreToolUse", "tool_name": "Read", "cwd": "/a", "tool_input": {"file_path": "/a/.env"}}
        self.assertIsNone(run_hook(read, {"CLAUDE_PLUGIN_OPTION_BLOCK_DOTENV": "false"}))
        out = run_hook(read, {"CLAUDE_PLUGIN_OPTION_BLOCK_DOTENV": "true"})
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_disable_and_garbage_input(self):
        payload = {"hook_event_name": "UserPromptSubmit", "prompt": SAMPLES["github-token"]}
        self.assertIsNone(run_hook(payload, {"TIGHTLIP_DISABLE": "1"}))
        proc = subprocess.run([sys.executable, os.path.join(HERE, "tightlip.py")],
                              input=b"not json", capture_output=True)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"")

    def test_filter_cli(self):
        proc = subprocess.run([sys.executable, os.path.join(HERE, "tightlip.py"), "--filter"],
                              input=LARAVEL_ENV.encode(), capture_output=True)
        self.assertNotIn(DB_PW.encode(), proc.stdout)
        self.assertIn(b"DB_HOST=127.0.0.1", proc.stdout)


if __name__ == "__main__":
    unittest.main()
