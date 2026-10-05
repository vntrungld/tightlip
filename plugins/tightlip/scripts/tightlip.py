#!/usr/bin/env python3
"""tightlip: a Claude Code hook that keeps secrets out of the model's context
(named after "tight-lipped": Claude works with your secrets but never sees them).

One script handles five hook events, dispatched on ``hook_event_name``:

  SessionStart        Name new sessions after their folder, so Claude Code doesn't
                      send the first prompt to a small model to generate a title
                      (that request runs before UserPromptSubmit can block it).

  PreToolUse          Deny commands and file reads that dump credentials wholesale
                      (env dumps, `gh auth token`, `kubectl get secret -o yaml`,
                      ~/.ssh/id_*, ...). Deny tool inputs that contain a
                      [REDACTED:...] placeholder, so a placeholder can never be
                      written back over a real secret.
  PostToolUse         Redact secrets in every tool result via `updatedToolOutput`.
                      The result keeps its original JSON shape (Claude Code ignores
                      a replacement that doesn't match the tool's output schema).
  PostToolBatch       Last gate before each model request: if any tool result the
                      model is about to receive still contains a secret (failed
                      commands, whose output hooks can't rewrite; a rejected
                      rewrite; a timed-out hook), stop the agentic loop so the user
                      can /rewind.
  UserPromptSubmit    Block prompts that contain a secret.

Requirements: Claude Code >= 2.1.121, Python >= 3.8, standard library only.

Options. Installed as a plugin, set them in /config (plugin options); installed
standalone, set the environment variable in the shell that launches `claude`:
  quiet          TIGHTLIP_QUIET=1           no status line when something is redacted
  block_dotenv   TIGHTLIP_BLOCK_DOTENV=1    deny reading .env files instead of redacting
  allow_regex    TIGHTLIP_ALLOW_REGEX=...   values fully matching this are never redacted
  name_sessions  TIGHTLIP_NAME_SESSIONS=0   keep Claude Code's generated session titles
                 TIGHTLIP_DISABLE=1         turn the hook off

CLI, for testing or piping:
  tightlip.py --filter < some.log      prints the input with secrets redacted
"""

import hashlib
import hmac
import json
import math
import os
import posixpath
import re
import shlex
import sys
import time
import urllib.parse
from collections import Counter

VERSION = "1.0.6"

PLACEHOLDER_RE = re.compile(r"\[REDACTED:[a-z0-9-]+:[0-9a-f]{8}\]")

# Tools whose result is pure bookkeeping; nothing to scan.
SKIP_POST_TOOLS = {
    "TodoWrite", "TaskCreate", "TaskUpdate", "TaskGet", "TaskList", "TaskStop",
    "EnterPlanMode", "ExitPlanMode", "EnterWorktree", "ExitWorktree",
}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
SHELL_TOOLS = {"Bash", "PowerShell"}


# --------------------------------------------------------------------------- options

def option(name, default=None):
    """TIGHTLIP_<NAME> (standalone) or CLAUDE_PLUGIN_OPTION_<NAME> (plugin userConfig)."""
    for var in ("TIGHTLIP_" + name.upper(), "CLAUDE_PLUGIN_OPTION_" + name.upper()):
        value = os.environ.get(var)
        if value not in (None, ""):
            return value
    return default


def flag(name, default=False):
    value = option(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


# --------------------------------------------------------------------------- helpers

def entropy(s):
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def repetitive(s):
    """True for filler such as xxxxxxxx or ghp_000000000000."""
    return bool(s) and Counter(s).most_common(1)[0][1] > 0.5 * len(s)


_ALPHABET_RUN_RE = re.compile(r"abcdefgh|ABCDEFGH|01234567")


def alphabet(s):
    """True for character pools such as SALT_CHARS = "abc...XYZ0123456789"."""
    return bool(_ALPHABET_RUN_RE.search(s))


_ALLOW_RE = None


def allowed_by_env(value):
    global _ALLOW_RE
    pattern = option("allow_regex")
    if not pattern:
        return False
    if _ALLOW_RE is None:
        try:
            _ALLOW_RE = re.compile(pattern)
        except re.error:
            _ALLOW_RE = re.compile(r"(?!)")
    return _ALLOW_RE.fullmatch(value) is not None


def unquote(val):
    """Return (inner, offset) where inner is val without surrounding quotes."""
    if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'`":
        return val[1:-1], 1
    return val, 0


def load_key():
    """Per-machine HMAC key, so placeholder ids are stable but can't be used to
    test guesses against a secret. Falls back to a per-process key."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    path = os.path.join(base, "tightlip", "key")
    for _ in range(10):
        try:
            with open(path, "rb") as f:
                key = f.read().strip()
            if len(key) >= 32:
                return key
            time.sleep(0.02)  # another hook process may be writing it right now
            continue
        except FileNotFoundError:
            pass
        except OSError:
            break
        try:
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            key = os.urandom(32).hex().encode()
            with os.fdopen(fd, "wb") as f:
                f.write(key)
            return key
        except FileExistsError:
            continue
        except OSError:
            break
    return os.urandom(32)


# --------------------------------------------------------------------------- value heuristics

NON_SECRET_LITERALS = {
    "null", "none", "nil", "undefined", "true", "false", "yes", "no", "on", "off",
    "empty", "required", "optional", "string", "number", "boolean",
    "value", "changeme",
}
PLACEHOLDER_MARKERS = (
    "example", "placeholder", "your_", "your-", "yourkey", "yourtoken", "xxxx", "****",
    "....", "redacted", "replace_me", "replace-me", "replaceme", "insert_", "_here",
    "-here", "dummy", "<", ">",
)
REFERENCE_MARKERS = (
    "${", "{{", "$(", "%(", "env(", "getenv(", "process.env", "os.environ",
    "import.meta.env", "op://", "vault:", "arn:aws:secretsmanager", "secretsmanager:",
)
IDENTIFIER_RE = re.compile(
    r"[_$]*(?:[a-z]+(?:[_\-. ][a-z]+)*"            # snake / kebab / dotted words
    r"|[A-Z]+(?:_[A-Z]+)*"                  # CONSTANT_NAME
    r"|[a-z]+(?:[A-Z][a-z]+)+"              # camelCase
    r"|(?:[A-Z][a-z]+)+)"                   # PascalCase
)
_WORD_DIGITS_RE = re.compile(r"[a-z]+\d+")


def dotted_name(v):
    """Setting / property names: 'fs.s3.enableServerSideEncryption'."""
    return "." in v and all(IDENTIFIER_RE.fullmatch(p) or _WORD_DIGITS_RE.fullmatch(p) for p in v.split("."))


def wordy(v):
    """Identifier-ish words with acronyms or markers: '?ArrowFunctionJSX'. Random
    strings switch case every char or two; identifiers have long lowercase runs."""
    core = v.strip("?!:")
    if core == v and not re.search(r"[A-Z]{2,}", v):
        return False  # plain mixed case is IDENTIFIER_RE's call; random strings look wordy too
    runs = re.findall(r"[a-z]+", core)
    if not core.isalpha() or not runs or len(re.findall(r"[A-Z]{2,}", core)) > 1:
        return False  # one acronym at most: 'ParseJSX', not 'aoYWSQnpTJrlEK'
    upper = sum(c.isupper() for c in core) / len(core)
    return sum(map(len, runs)) / len(runs) >= 3.5 and upper <= 0.35


CODE_ATTR_RE = re.compile(r"[A-Za-z_]\w*(?:(?:\.|::|->)[A-Za-z_]\w*)+")
PATH_RE = re.compile(r"(?:/|~/|\./|\.\./|[A-Za-z]:\\)")


def _common_non_secret(v, quoted):
    if not v or PLACEHOLDER_RE.search(v):
        return True
    low = v.lower()
    if low in NON_SECRET_LITERALS:
        return True
    if v[0] in "$%{[(" or any(m in low for m in REFERENCE_MARKERS):
        return True
    if any(m in low for m in PLACEHOLDER_MARKERS):
        return True
    if repetitive(v) or alphabet(v) or allowed_by_env(v):
        return True
    if PATH_RE.match(v):
        return True
    if not quoted and (re.search(r"[(\[]", v) or CODE_ATTR_RE.fullmatch(v)):
        return True  # looks like code: config('app.key'), ENV["X"], settings.SECRET
    return False


def strict_value_is_secret(v, quoted, key=""):
    """For dotenv/shell style UPPER_CASE=value: any real literal counts."""
    if _common_non_secret(v, quoted) or re.search(r"\s", v):
        return False  # whitespace: SQL, prose, display names
    if not quoted and re.fullmatch(r"[A-Z][A-Z_]+", v):
        return False  # another constant / enum name
    if v.isdigit():
        return len(v) >= 6
    return len(v) >= 4


def loose_value_is_secret(v, quoted, key=""):
    """For code/JSON/YAML keys: the value must look random, not like prose, an
    identifier, a translation key or a validation rule."""
    if not quoted:
        v = v.rstrip(";,")
    if _common_non_secret(v, quoted):
        return False
    if len(v) < 8 or re.search(r"\s", v) or "|" in v or v.startswith("-"):
        return False
    if IDENTIFIER_RE.fullmatch(v) or wordy(v):
        return False
    if dotted_name(v):
        return False
    low = v.lower()
    words = set(re.split(r"[^a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", v).lower()))
    if any(len(part) >= 3 and part in words for part in key_parts(key)):
        return False  # 'pwd' => 'pwd#module-pwd', 'token' => 'passwords.token'
    if not quoted:  # unquoted in code is usually a variable; in YAML it must look random
        mixed = len(v) >= 16 and re.search(r"[a-z]", v) and re.search(r"[A-Z]", v)
        # Short strings can't reach high entropy: 16 random chars average ~3.7 bits.
        return bool(re.search(r"\d", v) or mixed) and entropy(v) >= min(3.5, 0.8 * math.log2(len(v)))
    return entropy(v) >= 3.0


def random_looking(v, min_len=16, min_entropy=3.5):
    if _common_non_secret(v, True) or len(v) < min_len or re.search(r"\s", v):
        return False
    return entropy(v) >= min_entropy


def high_entropy_literal(v, quoted, key=""):
    """UPPER_CASE=value with a non-sensitive key name: only very random values."""
    if _common_non_secret(v, quoted) or len(v) < 24 or dotted_name(v):
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=_\-.]+", v) or v.count("/") > 1 or re.search(r"\.[a-z0-9]{1,4}$", v):
        return False  # paths and file names
    upper = sum(c.isupper() for c in v) / len(v)
    if not (re.search(r"[a-z]", v) and upper and (re.search(r"\d", v) or 0.25 <= upper <= 0.75)):
        return False  # random tokens mix cases (and digits); slugs, SHAs and PascalCase don't
    return entropy(v) > 4.0  # strictly above hex's maximum: skips SHAs and md5s


# --------------------------------------------------------------------------- key heuristics

STRONG_KEY_PARTS = {
    "secret", "secrets", "password", "passwords", "passwd", "passphrase", "pwd", "pass",
    "token", "tokens", "credential", "credentials", "creds", "dsn", "salt",
    "apikey", "privatekey", "secretkey", "accesskey", "signingkey", "encryptionkey",
    "masterkey", "appkey", "clientsecret", "authtoken", "accesstoken", "refreshtoken",
}
KEY_QUALIFIERS = {
    "api", "access", "private", "secret", "app", "client", "signing", "sign",
    "encryption", "encrypt", "master", "license", "auth", "account", "service", "ssh",
    "deploy", "consumer", "webhook", "hmac", "jwt", "session", "cookie", "crypt", "cipher",
}
SKIP_KEY_SUFFIX = {
    "ttl", "lifetime", "timeout", "expire", "expires", "expiry", "expiration", "length",
    "len", "min", "max", "minimum", "maximum", "driver", "algo", "algorithm", "path", "file",
    "dir", "directory", "prefix", "suffix", "header", "name", "type", "enabled", "enable",
    "disabled", "mode", "url", "uri", "endpoint", "host", "hostname", "port", "broker",
    "guard", "store", "connection", "table", "column", "field", "param", "rounds", "cost",
    "id", "ids", "count", "size", "policy", "rule", "rules", "label", "hint", "placeholder",
    "format", "version", "strategy", "provider", "method", "location", "reset",
    "confirmation", "confirm", "validation", "regex", "pattern", "chars", "attempts",
    "limit", "interval", "visible", "hidden", "input",
}
UPPER_KEY_RE = re.compile(r"[A-Z][A-Z0-9_]*")


def key_parts(key):
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key.strip("\"'"))
    return [p for p in re.split(r"[_.\-\s]+", key.lower()) if p]


def is_sensitive_key(key, strict):
    parts = key_parts(key)
    if not parts or parts[-1] in SKIP_KEY_SUFFIX:
        return False
    for i, part in enumerate(parts):
        if part in STRONG_KEY_PARTS:
            return True
        if part == "key" and ((strict and i == len(parts) - 1)  # APP_KEY, STRIPE_KEY
                              or (i > 0 and parts[i - 1] in KEY_QUALIFIERS)):
            return True
    return False


# --------------------------------------------------------------------------- rules

def _pem_check(s):
    body = re.sub(r"-----[A-Z0-9 _-]+-----|\\[rn]|\s|Proc-Type:.*|DEK-Info:.*", "", s)
    return len(body) >= 40 and not repetitive(body)


def _sk_check(s):
    body = s[3:]
    return sum(c.isdigit() for c in body) >= 2 and entropy(body) >= 3.5


class Rule:
    __slots__ = ("name", "rx", "group", "check")

    def __init__(self, name, pattern, flags=0, check=None):
        self.name = name
        self.rx = re.compile(pattern, flags)
        self.group = "s" if "(?P<s>" in pattern else 0
        self.check = check


# Known token formats; whole match (or group "s") is the secret.
FORMAT_RULES = [
    Rule("private-key",
         r"-----BEGIN[A-Z0-9 _-]{0,64}PRIVATE KEY(?: BLOCK)?-----.{0,16384}?"
         r"-----END[A-Z0-9 _-]{0,64}PRIVATE KEY(?: BLOCK)?-----", re.S, check=_pem_check),
    Rule("private-key",  # truncated block with no END line, e.g. `head -5 id_rsa`
         r"-----BEGIN[A-Z0-9 _-]{0,64}PRIVATE KEY(?: BLOCK)?-----"
         r"(?:(?:\\[rn]|\s)+[A-Za-z0-9+/=:,\-]{8,})+", check=_pem_check),
    Rule("aws-access-key-id", r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b"),
    Rule("aws-secret-access-key",
         r"(?i)aws.{0,24}?(?:secret|private)[\w.\-]{0,24}[\"']?\s*[:=]\s*[\"']?"
         r"(?P<s>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
    Rule("github-token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b"),
    Rule("github-pat", r"\bgithub_pat_[A-Za-z0-9_]{50,255}\b"),
    Rule("gitlab-token", r"\bgl(?:pat|ptt|dt|rt|cbt|imt|soat|ffct|oas)-[A-Za-z0-9_\-]{20,}"),
    Rule("slack-token", r"\bxox[abposr]-[A-Za-z0-9\-]{10,250}"),
    Rule("slack-app-token", r"\bxapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+\b"),
    Rule("slack-webhook", r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_\-]{20,}"),
    Rule("discord-webhook", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{50,}"),
    Rule("stripe-key", r"\b(?:sk|rk)_(?:live|test|prod)_[A-Za-z0-9]{10,247}\b"),
    Rule("stripe-webhook-secret", r"\bwhsec_[A-Za-z0-9+/=]{24,}"),
    Rule("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"),
    Rule("google-oauth-secret", r"\bGOCSPX-[A-Za-z0-9_\-]{28}"),
    Rule("google-oauth-token", r"\bya29\.[0-9A-Za-z_\-]{20,}"),
    Rule("llm-api-key",  # OpenAI, Anthropic, DeepSeek, OpenRouter...
         r"\bsk-(?:ant-|proj-|svcacct-|admin-|or-v1-)?[A-Za-z0-9_\-]{32,}", check=_sk_check),
    Rule("digitalocean-token", r"\bdo[opr]_v1_[a-f0-9]{64}\b"),
    Rule("shopify-token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b"),
    Rule("atlassian-api-token", r"\bATATT3[A-Za-z0-9_\-=]{150,}"),
    Rule("sendgrid-key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}(?![\w\-])"),
    Rule("twilio-api-key", r"(?<![A-Za-z0-9+/])SK[0-9a-f]{32}(?![A-Za-z0-9+/])"),
    Rule("mailgun-key", r"(?<![A-Za-z0-9+/])key-[0-9a-zA-Z]{32}(?![A-Za-z0-9+/])"),
    Rule("mailchimp-key", r"(?<![A-Za-z0-9+/])[0-9a-f]{32}-us\d{1,2}(?![A-Za-z0-9+/])"),
    Rule("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    Rule("pypi-token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}"),
    Rule("docker-hub-pat", r"\bdckr_pat_[A-Za-z0-9_\-]{27,}"),
    Rule("telegram-bot-token", r"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}(?![\w\-])"),
    Rule("sentry-token", r"\bsntry[su]_[A-Za-z0-9+/=_\-]{40,}"),
    Rule("posthog-personal-key", r"\bphx_[A-Za-z0-9]{40,}\b"),
    Rule("huggingface-token", r"\bhf_[A-Za-z0-9]{34,}\b"),
    Rule("grafana-token", r"\bgl(?:sa|c)_[A-Za-z0-9+/_=]{32,}"),
    Rule("linear-key", r"\blin_api_[A-Za-z0-9]{40}\b"),
    Rule("notion-token", r"\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b"),
    Rule("figma-token", r"\bfigd_[A-Za-z0-9_\-]{40,}"),
    Rule("groq-key", r"\bgsk_[A-Za-z0-9]{48,}\b"),
    Rule("xai-key", r"\bxai-[A-Za-z0-9]{70,}\b"),
    Rule("heroku-key", r"\bHRKU-[A-Za-z0-9_\-]{60,}"),
    Rule("postman-key", r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"),
    Rule("pulumi-token", r"\bpul-[a-f0-9]{40}\b"),
    Rule("terraform-token", r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}"),
    Rule("vault-token", r"\bhv[sbr]\.[A-Za-z0-9_\-]{24,}"),
    Rule("doppler-token", r"\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}"),
    Rule("onepassword-token", r"\bops_eyJ[A-Za-z0-9+/=_\-]{100,}"),
    Rule("age-secret-key", r"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b"),
    Rule("facebook-token", r"(?<![A-Za-z0-9+/])EAA[A-Za-z0-9]{90,}(?![A-Za-z0-9+/])"),
    Rule("firebase-fcm-key", r"(?<![A-Za-z0-9+/])AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}(?![A-Za-z0-9+/])"),
    Rule("azure-storage-key", r"(?i)\b(?:AccountKey|SharedAccessKey)=(?P<s>[A-Za-z0-9+/=]{40,})"),
    Rule("laravel-app-key", r"\bbase64:[A-Za-z0-9+/]{40,}={0,2}"),
    Rule("jwt", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
]

# Secrets recognised by their surroundings; group "s" is the secret.
CONTEXT_RULES = [
    Rule("url-credentials",
         r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,30}://[^\s:/@'\"<>]{0,256}:(?P<s>[^\s@/'\"<>]{3,256})@[^\s'\"<>]",
         check=lambda s: strict_value_is_secret(s, True)
         and s.lower() not in {"password", "pass", "pwd", "secret", "token"}),
    Rule("auth-header",
         r"(?i)\b(?:proxy-)?authorization\b[\"']?\s*[:=]\s*[\"']?"
         r"(?:bearer|token|basic|digest|apikey|api-key|sso-key)\s+(?P<s>[A-Za-z0-9._~+/=:\-]{12,})",
         check=lambda s: random_looking(s, 12, 3.0)),
    Rule("api-key-header",
         r"(?i)(?<![\w-])(?:x-api-key|api-key|x-auth-token|x-access-token|private-token|"
         r"x-shopify-access-token|x-figma-token|x-goog-api-key|x-api-token|x-apikey)\b[\"']?"
         r"\s*[:=]\s*[\"']?(?P<s>[A-Za-z0-9._~+/=\-]{12,})",
         check=lambda s: random_looking(s, 12, 3.0)),
    Rule("url-query-secret",
         r"(?i)[?&](?:access_token|refresh_token|id_token|token|api_key|apikey|key|secret|"
         r"client_secret|password|passwd|pwd|auth|sig|signature|x-amz-signature|"
         r"x-amz-security-token|x-goog-signature)=(?P<s>[^&\s\"'#<>]{8,})",
         check=lambda s: random_looking(urllib.parse.unquote(s), 16, 3.5)),
    Rule("cli-secret-flag",
         r"(?i)(?<![\w-])--(?:password|passwd|token|secret|api-key|apikey|access-token|"
         r"auth-token|client-secret)(?:=|[ \t]+)(?P<s>\"[^\"\n]+\"|'[^'\n]+'|[^\s'\"\-][^\s'\"]*)",
         check=lambda s: strict_value_is_secret(s, True) and not re.search(r"[$()]", s)
         and not (len(s) < 12 and IDENTIFIER_RE.fullmatch(s))),
    Rule("npmrc-auth", r"(?m):_auth(?:Token)?[ \t]*=[ \t]*(?P<s>[^\s\"']{8,})",
         check=lambda s: strict_value_is_secret(s, False)),
    Rule("netrc-password", r"\bmachine\s+\S+\s+login\s+\S+\s+password\s+(?P<s>\S+)"),
    Rule("curl-user", r"(?<![\w-])(?:-u|--user)[ \t]+['\"]?[^\s:'\"]+:(?P<s>[^\s'\"]{3,})",
         check=lambda s: strict_value_is_secret(s, True)),
]

_VAL = r"(?P<val>\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'"
_QVAL = _VAL + r")"  # quoted values only
# Line prefixes added by line-oriented tools, so `grep -rn PASSWORD .` is
# scanned like the file itself: `cat -n` (`    49\t`), `grep -n`/`-C` (`49:`,
# `48-`), `grep -rn` (`./.env:49:`, `./.env-48-`) and `grep -r` (`./.env:`).
_LINE_PREFIX = r"(?:[ \t]*\d+\t|(?:[^\s:=\"']+[:-])?\d+[:-]|[^\s:=\"']+:)?"
# key=value, key: value and 'key' => 'value' forms.
KV_RULES = [
    ("upper", re.compile(  # dotenv / shell / docker-compose: DB_PASSWORD=..., anywhere on a line
        r"(?:^" + _LINE_PREFIX + r"|(?<=[\s;&|(\"'`]))(?P<key>[A-Z][A-Z0-9_]*)[ \t]*=[ \t]*(?!=)"
        + _VAL + r"|[^\s\"'#;&|)`]+)", re.M)),
    ("line", re.compile(  # ini / toml / properties / python: key = value at line start
        r"^" + _LINE_PREFIX + r"[ \t]*(?:-[ \t]+)?(?:export[ \t]+)?(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)[ \t]*=[ \t]*(?!=)"
        + _VAL + r"|[^\s\"'#;]+)", re.M)),
    ("namevalue", re.compile(  # k8s / ECS env lists: name: DB_PASSWORD + value: ...
        r"[\"']?name[\"']?[ \t]*:[ \t]*[\"']?(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)[\"']?"
        r"[ \t]*(?:,[ \t]*|\r?\n[ \t]*-?[ \t]*)[\"']?value[\"']?[ \t]*:[ \t]*"
        + _VAL + r"|[^\s,}\]#\"'][^\s,}\]#]*)")),
    ("dots", re.compile(  # `php artisan config:show`: connections.mysql.password ..... secret
        r"^[ \t]*(?P<key>[A-Za-z_][\w.\-]*)[ \t]+\.{3,}[ \t]+(?P<val>\S+)[ \t]*$", re.M)),
    ("colon", re.compile(  # yaml / json / js objects
        r"(?:^|(?<=[\s{,\[]))(?P<q>[\"']?)(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)(?P=q)[ \t]*:[ \t]*"
        + _VAL + r"|[^\s,}\]#\"'][^\s,}\]#]*)", re.M)),
    ("arrow", re.compile(  # php arrays: 'password' => 'literal'
        r"(?P<q>[\"'])(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)(?P=q)\s*=>\s*"
        + _VAL + r")(?!\s*\.)")),
    ("decl", re.compile(  # code, any naming style, optional type: const apiKey: string = "...", ApiKey = "..."
        r"(?<![\w.$\-'\"])(?P<key>[A-Za-z_]\w*)[ \t]*(?::[ \t]*[\w&<>\[\]?.,' ]{1,40}?[ \t]*)?=[ \t]*" + _QVAL)),
    ("define", re.compile(  # php: define('API_KEY', '...')
        r"\bdefine\([ \t]*(?P<q>[\"'])(?P<key>\w+)(?P=q)[ \t]*,[ \t]*" + _QVAL)),
    ("cdefine", re.compile(  # c / c++: #define API_KEY "..."
        r"^[ \t]*#[ \t]*define[ \t]+(?P<key>\w+)[ \t]+" + _QVAL, re.M)),
    ("attr", re.compile(  # elixir module attributes: @api_key "..."
        r"^[ \t]*@(?P<key>[a-z_]\w*)[ \t]+" + _QVAL, re.M)),
]
CODE_MODES = ("decl", "define", "cdefine", "attr")


# --------------------------------------------------------------------------- redactor

_BLOB_RE = re.compile(r"[A-Za-z0-9+/=_\-]+")
_CODE_PREFIX_RE = re.compile(
    r"\b(?:const|let|var|static|final|public|private|protected|readonly|define|val|case)\b")


def _looks_like_code_stmt(m, mode):
    """`const INVALID_TOKEN = 'passwords.token';` or `MAX_KEY: Final = ...` is source
    code, not a dotenv/YAML line. So is `METADATA_KEY = 'pydantic-mypy-metadata'`:
    spaces around `=` plus a quoted value is Python/Ruby style, which shells
    reject and .env files rarely use."""
    s = m.string
    after = s[m.end():m.end() + 4].lstrip(" \t")[:1]
    if mode == "colon":
        return after == "="
    eq = s[m.end("key"):m.start("val")]
    if eq[:1] in " \t" and eq[-1:] in " \t" and m.group("val")[:1] in "\"'":
        return True
    line_start = s.rfind("\n", 0, m.start()) + 1
    return after in (";", ".", "+", ",", "|") or bool(_CODE_PREFIX_RE.search(s[line_start:m.start()]))


class Redactor:
    def __init__(self, key=None):
        self.key = key or load_key()
        self.hits = []  # rule names, one entry per redacted value

    def placeholder(self, rule, secret):
        digest = hmac.new(self.key, secret.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:8]
        # Keep the line count so line numbers in Read output stay correct.
        return "[REDACTED:%s:%s]%s" % (rule, digest, "\n" * secret.count("\n"))

    def _replace(self, m, group, rule_name, secret, offset=0):
        whole = m.group(0)
        start = m.start(group) - m.start(0) + offset
        self.hits.append(rule_name)
        return whole[:start] + self.placeholder(rule_name, secret) + whole[start + len(secret):]

    def _sub_rule(self, rule):
        def sub(m):
            raw = m.group(rule.group)
            secret, offset = unquote(raw)
            if not secret or PLACEHOLDER_RE.search(secret):
                return m.group(0)
            if "EXAMPLE" in secret or "example" in secret or repetitive(secret) or allowed_by_env(secret):
                return m.group(0)
            if rule.check and not rule.check(secret):
                return m.group(0)
            return self._replace(m, rule.group, rule.name, secret, offset)
        return sub

    def _sub_kv(self, mode):
        def sub(m):
            key, val = m.group("key"), m.group("val")
            inner, offset = unquote(val)
            quoted = offset == 1
            if val[:1] in "\"'" and not quoted:
                return m.group(0)  # unbalanced quote: multi-line value, leave it
            code = False
            if mode in CODE_MODES:
                strict, code = False, True  # source code: the value must look random
            elif mode == "dots":
                strict = True  # an explicit config dump: every value is a literal
            else:
                strict = mode != "arrow" and UPPER_KEY_RE.fullmatch(key) is not None
                if strict and mode in ("upper", "line", "colon") and _looks_like_code_stmt(m, mode):
                    strict, code = False, True
            if is_sensitive_key(key, strict):
                check = strict_value_is_secret if strict else loose_value_is_secret
                rule = "env-secret" if strict else "config-secret"
            elif (mode in ("upper", "line") or (mode in CODE_MODES and UPPER_KEY_RE.fullmatch(key))) \
                    and (strict or (code and key_parts(key)[-1] not in SKIP_KEY_SUFFIX)):
                check, rule = high_entropy_literal, "high-entropy-value"
            else:
                return m.group(0)
            if not check(inner, quoted, key):
                return m.group(0)
            return self._replace(m, "val", rule, inner, offset)
        return sub

    def redact_text(self, text):
        if not isinstance(text, str) or len(text) < 8:
            return text
        for rule in FORMAT_RULES:
            text = rule.rx.sub(self._sub_rule(rule), text)
        for rule in CONTEXT_RULES:
            text = rule.rx.sub(self._sub_rule(rule), text)
        for mode, rx in KV_RULES:
            text = rx.sub(self._sub_kv(mode), text)
        return text

    def walk(self, obj):
        """Redact every string inside a JSON value, keeping its shape."""
        if isinstance(obj, str):
            head = obj[:4096]
            if len(obj) > 4096 and _BLOB_RE.fullmatch(head):
                return obj  # base64 image/PDF payload: nothing readable in it
            return self.redact_text(obj)
        if isinstance(obj, list):
            return [self.walk(x) for x in obj]
        if isinstance(obj, dict):
            return {k: self.walk(v) for k, v in obj.items()}
        return obj

    def summary(self):
        counts = Counter(self.hits)
        return ", ".join(name if n == 1 else "%s x%d" % (name, n) for name, n in counts.items())


# --------------------------------------------------------------------------- PreToolUse checks

HOME = os.path.expanduser("~")

CRED_PATH_RES = [re.compile(p) for p in (
    r"/\.ssh/id_[^/]*(?<!\.pub)$",
    r"/\.ssh/[^/]*_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?$",
    r"/\.aws/credentials$", r"/\.aws/(?:sso|cli)/cache/",
    r"/\.kube/(?!cache/|http-cache/)[^/]+$",
    r"/\.docker/config\.json$",
    r"/[._]netrc$", r"/\.git-credentials$", r"/\.pgpass$", r"/\.my\.cnf$",
    r"/\.config/gh/hosts\.ya?ml$", r"/\.config/hub$",
    r"/\.pypirc$", r"/\.vault-token$",
    r"/(?:\.composer|\.config/composer)/auth\.json$",
    r"/\.config/doctl/config\.yaml$",
    r"/\.config/gcloud/(?:credentials\.db|access_tokens\.db|legacy_credentials/|application_default_credentials\.json)",
    r"/\.azure/(?:accessTokens\.json|msal_token_cache)",
    r"/\.terraform\.d/credentials\.tfrc\.json$",
    r"/\.gnupg/", r"/\.password-store/", r"\.kdbx$",
    r"/\.local/share/(?:kwalletd|keyrings)/",
    r"/\.config/op/", r"/\.op/",
    r"/\.claude/\.credentials\.json$", r"/\.codex/auth\.json$", r"/\.gemini/oauth_creds\.json$",
    r"/\.config/github-copilot/(?:hosts|apps)\.json$",
    r"\.(?:p12|pfx|jks|keystore)$", r"(?:^|/)[^/]*private[^/]*\.(?:pem|key)$", r"/oauth-private\.key$",
    r"^/proc/[^/]+/environ$",
)]
CRED_DIRS = ("/.ssh", "/.aws", "/.gnupg", "/.password-store", "/.kube", "/.config/op")
DOTENV_RE = re.compile(r"(?:^|/)\.env(?:\.[\w.-]+)?$")
DOTENV_SAFE_RE = re.compile(r"\.(?:example|sample|template|dist|defaults?)$")

READERS = {
    "cat", "bat", "batcat", "less", "more", "most", "head", "tail", "nl", "tac", "xxd", "od",
    "hexdump", "strings", "base64", "grep", "egrep", "fgrep", "rg", "ag", "ack", "awk", "gawk",
    "sed", "cut", "tr", "sort", "uniq", "jq", "yq", "tee", "column", "diff", "vim", "vi", "view",
    "nano", "openssl", "python", "python3", "node", "php", "ruby", "perl", "cp", "scp", "rsync",
}
WRAPPERS = {"sudo", "command", "builtin", "exec", "time", "nice", "nohup", "doas", "stdbuf", "timeout"}
ENV_DUMP_MSG = (
    "Blocked by tightlip: this prints the whole environment, which contains secrets. "
    "List variable names only with `env | cut -d= -f1`, read a specific non-secret variable "
    "(e.g. `printenv HOME`), or check that a secret is set without printing it: "
    "`[ -n \"$DB_PASSWORD\" ] && echo set`."
)
SECRET_VAR_MSG = (
    "Blocked by tightlip: this would print the value of $%s. To check it is set: "
    "`[ -n \"$%s\" ] && echo set`; to check its length: `echo ${#%s}`. To use it, reference it "
    "directly in the command that needs it."
)
SECRET_CLI_MSG = (
    "Blocked by tightlip: `%s` prints a credential to the output. Use it inside command "
    "substitution so the value never reaches the output (e.g. `GH_TOKEN=$(gh auth token) gh api user`), "
    "or pipe it into a command that reads it from stdin (`... | docker login --password-stdin`)."
)
K8S_SECRET_MSG = (
    "Blocked by tightlip: `kubectl get secret` with -o yaml/json/jsonpath prints base64-encoded "
    "secret values, which the redactor can't recognise. `kubectl describe secret <name>` shows the "
    "keys and their sizes without the values."
)
CRED_FILE_MSG = (
    "Blocked by tightlip: %s is a credential file. Ask the user if something in it is needed. "
    "Safer alternatives: `ssh-add -l` (SSH keys), `kubectl config get-contexts` (kubeconfig), "
    "`aws configure list-profiles` (AWS), `gh auth status` (GitHub CLI)."
)
DOTENV_MSG = (
    "Blocked by tightlip: reading .env files is disabled by the user's tightlip settings. "
    "Read .env.example for the list of variables, or ask the user."
)
PLACEHOLDER_WRITE_MSG = (
    "Blocked by tightlip: the input contains a [REDACTED:...] placeholder. Placeholders stand in "
    "for values hidden from you; the real values are unchanged on disk and in the environment, and "
    "writing a placeholder would overwrite a real secret with a dummy string. Edit around those lines, "
    "or ask the user to make that part of the change."
)
PLACEHOLDER_CMD_MSG = (
    "Blocked by tightlip: the command contains a [REDACTED:...] placeholder, which is not the real "
    "value, so it would not do what you intend. Reference the secret through its environment variable "
    "(e.g. \"$GITHUB_TOKEN\") or ask the user."
)


def normalize_path(path, cwd):
    path = path.replace("\\", "/")
    path = re.sub(r"^(?:~|\$HOME|\$\{HOME\})(?=/|$)", HOME.replace("\\", "/"), path)
    if not path.startswith("/") and cwd:
        path = posixpath.join(cwd.replace("\\", "/"), path)
    return posixpath.normpath(path)


def credential_path_reason(path, cwd):
    p = normalize_path(path, cwd)
    for rx in CRED_PATH_RES:
        if rx.search(p):
            return CRED_FILE_MSG % path
    if os.path.basename(p) == "auth.json" and os.path.exists(os.path.join(os.path.dirname(p), "composer.json")):
        return CRED_FILE_MSG % path  # project-level composer auth.json
    if flag("block_dotenv") and DOTENV_RE.search(p) and not DOTENV_SAFE_RE.search(p):
        return DOTENV_MSG
    return None


def credential_dir(path, cwd):
    p = normalize_path(path, cwd)
    home = HOME.replace("\\", "/")
    return any(p == home + d for d in CRED_DIRS)


_SUBST_RE = re.compile(r"\$\([^()]*\)|`[^`]*`")
_OPERATORS = {"|", "||", "&&", ";", "&", "|&", ";;"}


def split_segments(cmd):
    """Split a shell command into (argv, stdout_consumed) segments.

    Command substitutions are blanked out first: their output feeds another
    command instead of reaching the tool result. stdout_consumed is True when a
    segment's stdout goes to a file or into a pipe."""
    prev = None
    while prev != cmd:
        prev, cmd = cmd, _SUBST_RE.sub(" __subst__ ", cmd)
    cmd = cmd.replace("\n", " ; ")
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        tokens = cmd.split()
    segments, argv, consumed, i = [], [], False, 0
    while i < len(tokens):
        t = tokens[i]
        if t in _OPERATORS:
            segments.append((argv, consumed or t in ("|", "|&")))
            argv, consumed = [], False
        elif t in (">", ">>", ">|", "&>", "&>>"):
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            stderr_only = argv[-1:] == ["2"]
            if stderr_only:
                argv = argv[:-1]
            elif target not in ("&2", "/dev/stderr", "/dev/tty"):
                consumed = True
            i += 1
        elif t in ("<", "<<", "<<<", ">&", "<&"):
            if t == ">&" and argv[-1:] == ["2"]:
                argv = argv[:-1]
            i += 1
        else:
            argv.append(t)
        i += 1
    segments.append((argv, consumed))
    return [(a, c) for a, c in segments if a]


def strip_wrappers(argv):
    argv = list(argv)
    while argv:
        head = posixpath.basename(argv[0])
        if re.fullmatch(r"[A-Za-z_]\w*=.*", argv[0]):
            argv.pop(0)
        elif head in WRAPPERS:
            argv.pop(0)
            while argv and argv[0].startswith("-"):
                flag = argv.pop(0)
                if head in ("sudo", "doas") and flag in ("-u", "-g", "-C", "-p", "-r", "-t", "-U", "-h") and argv:
                    argv.pop(0)
            if head == "timeout" and argv and re.fullmatch(r"[\d.]+[smhd]?", argv[0]):
                argv.pop(0)
        elif head == "env" and len(argv) > 1:
            argv.pop(0)
            while argv and (argv[0].startswith("-") or "=" in argv[0]):
                argv.pop(0)
            if not argv:
                return ["env"]  # `env -0`, `env FOO=1`: still prints the environment
        else:
            break
    return argv


def is_env_dump(argv):
    head = posixpath.basename(argv[0])
    if head in ("env", "printenv") and all(a.startswith("-") for a in argv[1:]):
        return True
    if head in ("export", "declare", "typeset") and (len(argv) == 1 or argv[1:] in (["-p"], ["-x"], ["-px"])):
        return True
    if head == "set" and len(argv) == 1:
        return True
    if head in ("docker", "podman", "kubectl", "oc", "ssh", "docker-compose", "nerdctl") \
            and posixpath.basename(argv[-1]) in ("env", "printenv"):
        return True
    return False


def secret_cli(argv):
    """Return a short label if argv prints a credential, else None."""
    a = [x.lower() for x in argv]
    head = posixpath.basename(a[0])
    rest = " ".join(a[1:])

    def has(*words):
        return all(w in a for w in words)

    if head == "gh" and (rest.startswith("auth token")
                         or (rest.startswith("auth status") and ("--show-token" in a or "-t" in a))):
        return "gh auth token"
    if head == "gcloud" and re.search(r"\bauth (?:application-default )?print-(?:access|identity)-token", rest):
        return "gcloud auth print-access-token"
    if head == "az" and rest.startswith("account get-access-token"):
        return "az account get-access-token"
    if head == "aws":
        if rest.startswith("configure export-credentials") or rest.startswith("ecr get-login-password") \
                or rest.startswith("ecr-public get-login-password") \
                or re.match(r"configure get \S*(?:secret|key|token)", rest):
            return "aws " + " ".join(a[1:3])
    if head == "doctl" and rest.startswith("auth token"):
        return "doctl auth token"
    if head == "op" and (a[1:2] == ["read"] or (has("item", "get") and "--reveal" in a)):
        return "op read"
    if head == "vault" and (rest.startswith("kv get") or a[1:2] == ["read"] or rest.startswith("print token")):
        return "vault read"
    if head == "secret-tool" and a[1:2] == ["lookup"]:
        return "secret-tool lookup"
    if head == "kwallet-query" and ("-r" in a or "--read-password" in a):
        return "kwallet-query -r"
    if head == "security" and re.match(r"find-(?:generic|internet)-password", rest) and ("-w" in a or "-g" in a):
        return "security find-generic-password -w"
    if head in ("pass", "gopass") and a[1:2] == ["show"]:
        return head + " show"
    if head == "bw" and a[1:2] == ["get"]:
        return "bw get"
    if head == "doppler" and (rest.startswith("secrets get") or rest.startswith("secrets download")):
        return "doppler secrets get"
    if head == "heroku" and rest.startswith("auth:token"):
        return "heroku auth:token"
    if head in ("kubectl", "oc"):
        if a[1:2] == ["view-secret"]:
            return "kubectl view-secret"
        if "get" in a and any(re.fullmatch(r"(?:[\w.-]+,)*secrets?(?:/[\w.-]+)?(?:,[\w.-]+)*", x) for x in a):
            fmt = None
            for j, x in enumerate(a):
                if x in ("-o", "--output") and j + 1 < len(a):
                    fmt = a[j + 1]
                elif x.startswith(("-o=", "--output=")):
                    fmt = x.split("=", 1)[1]
                elif x.startswith("-o") and len(x) > 2:
                    fmt = x[2:]
            if fmt and not fmt.startswith(("name", "wide")):
                return "kubectl-secret"
    return None


NAMES_ONLY_RE = re.compile(
    r"(?:cut\b.*-d\s*=.*-f\s*1\b|cut\b.*-f\s*1\b.*-d\s*=|awk\b.*-F\s*=.*\$1\b|sed\b.*s/=\.\*//|wc\b|sort\b.*-u)"
)
_VAR_REF_RE = re.compile(r"\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})")


def check_command(cmd, cwd):
    if PLACEHOLDER_RE.search(cmd):
        return PLACEHOLDER_CMD_MSG
    segments = [(strip_wrappers(a), c) for a, c in split_segments(cmd)]
    for idx, (argv, consumed) in enumerate(segments):
        if not argv:
            continue
        head = posixpath.basename(argv[0])
        if is_env_dump(argv):
            nxt = segments[idx + 1][0] if idx + 1 < len(segments) else []
            if not (consumed and nxt and NAMES_ONLY_RE.match(" ".join(nxt))):
                return ENV_DUMP_MSG
        if head in ("echo", "printf", "print") and not consumed:
            for arg in argv[1:]:
                for m in _VAR_REF_RE.finditer(arg):
                    var = m.group(1) or m.group(2)
                    if is_sensitive_key(var, True):
                        return SECRET_VAR_MSG % (var, var, var)
        if head == "printenv" and not consumed:
            for var in argv[1:]:
                if is_sensitive_key(var, True):
                    return SECRET_VAR_MSG % (var, var, var)
        label = secret_cli(argv)
        if label == "kubectl-secret":
            return K8S_SECRET_MSG
        if label and not consumed:
            return SECRET_CLI_MSG % label
        if label and consumed and "--password-stdin" not in cmd and "--with-token" not in cmd \
                and not re.search(r"(?<![2&])>{1,2}\s*\S", cmd):
            return SECRET_CLI_MSG % label  # piped into something that would print it
        if head in READERS:
            for arg in argv[1:]:
                if arg.startswith("-") and "/" not in arg:
                    continue
                reason = credential_path_reason(arg, cwd)
                if reason:
                    return reason
                if head in ("grep", "egrep", "fgrep", "rg", "ag", "ack") and credential_dir(arg, cwd):
                    return CRED_FILE_MSG % arg
    return None


def deny(reason):
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}


# --------------------------------------------------------------------------- handlers

CONTEXT_NOTE = (
    "tightlip (a hook configured by the user) replaced %d value(s) in this tool result with "
    "placeholders of the form [REDACTED:<type>:<id>]. The real values are unchanged on disk and in the "
    "environment; identical ids mean identical values. A placeholder is not a usable value: file edits, "
    "shell commands and MCP calls that contain one are rejected. Commands can use a secret through its "
    "environment variable (e.g. \"$DB_PASSWORD\") without reading it."
)


def quiet():
    return flag("quiet")


def on_session_start(data):
    """Give a new session a name up front. Unnamed sessions get a title generated from
    the first prompt by a background model request that runs before UserPromptSubmit,
    so a secret pasted as the first prompt would reach the API even though the hook
    blocks the prompt itself."""
    if data.get("source") != "startup" or data.get("session_title") or not flag("name_sessions", True):
        return None
    folder = os.path.basename(os.path.normpath(data.get("cwd") or os.getcwd())) or "session"
    return {"hookSpecificOutput": {
        "hookEventName": "SessionStart",
        "sessionTitle": "%s %s" % (folder, time.strftime("%m-%d %H:%M")),
    }}


def on_pre_tool_use(data):
    tool = data.get("tool_name") or ""
    ti = data.get("tool_input") or {}
    cwd = data.get("cwd") or os.getcwd()
    if tool in WRITE_TOOLS or tool.startswith("mcp__"):
        if PLACEHOLDER_RE.search(json.dumps(ti, ensure_ascii=False)):
            return deny(PLACEHOLDER_WRITE_MSG)
        return None
    if tool in SHELL_TOOLS:
        reason = check_command(ti.get("command") or "", cwd)
        return deny(reason) if reason else None
    if tool == "Read":
        reason = credential_path_reason(ti.get("file_path") or "", cwd)
        return deny(reason) if reason else None
    if tool == "Grep" and ti.get("path"):
        path = ti["path"]
        if credential_dir(path, cwd):
            return deny(CRED_FILE_MSG % path)
        reason = credential_path_reason(path, cwd)
        return deny(reason) if reason else None
    return None


def on_post_tool_use(data):
    tool = data.get("tool_name") or ""
    if tool in SKIP_POST_TOOLS or "tool_response" not in data:
        return None
    r = Redactor()
    new = r.walk(data["tool_response"])
    if not r.hits:
        return None
    out = {"hookSpecificOutput": {
        "hookEventName": "PostToolUse",
        "updatedToolOutput": new,
        "additionalContext": CONTEXT_NOTE % len(r.hits),
    }}
    if not quiet():
        out["systemMessage"] = "tightlip: đã che %d giá trị (%s) trong output của %s" % (
            len(r.hits), r.summary(), tool)
    return out


def _blocked_marker(data):
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    sid = re.sub(r"[^A-Za-z0-9_-]", "_", str(data.get("session_id") or "default"))[:100]
    return os.path.join(base, "tightlip", "blocked-" + sid)


_GREP_LOC_RE = re.compile(r"([^\s:=\"']*[./][^\s:=\"']*)[:-](\d+)[:-]")  # grep -rn / Grep: path:12:
_NUMBERED_RE = re.compile(r"[ \t]*(\d+)\t")                   # Read tool / cat -n: "    12\t"


def _leak_lines(obj, key):
    """Line number and text of every line in a tool result that still holds a secret.
    Secrets spanning lines (PEM blocks) may not show up here; the caller copes."""
    found = []
    if isinstance(obj, str):
        for i, line in enumerate(obj.split("\n"), 1):
            r = Redactor(key)
            r.redact_text(line)
            if r.hits:
                found.append((i, line))
    elif isinstance(obj, list):
        for x in obj:
            found += _leak_lines(x, key)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(obj.get("startLine"), int) and k == "content":
                found += [(n + obj["startLine"] - 1, "%d\t%s" % (n + obj["startLine"] - 1, s))
                          for n, s in _leak_lines(v, key)]  # Read's structured form
            else:
                found += _leak_lines(v, key)
    return found


def _describe_leak(call, key):
    """Say where a secret is (`Bash cat .env: dòng 2 của output`), never what it is.
    Every piece taken from the call is redacted again, in case it holds a secret too."""
    name = call.get("tool_name") or "tool"
    inp = call.get("tool_input") if isinstance(call.get("tool_input"), dict) else {}
    target = inp.get("command") or inp.get("file_path") or inp.get("notebook_path") or inp.get("path") or ""
    if name == "Grep" and inp.get("pattern"):
        target = "%s in %s" % (inp["pattern"], inp.get("path") or ".")
    target = " ".join(str(target).split())
    if len(target) > 100:
        target = target[:97] + "..."
    where = []
    for n, line in _leak_lines(call.get("tool_response"), key):
        m = _GREP_LOC_RE.match(line)
        if m:
            where.append("%s:%s" % (m.group(1), m.group(2)))
            continue
        m = _NUMBERED_RE.match(line)
        if m and inp.get("file_path"):
            where.append("%s:%s" % (inp["file_path"], m.group(1)))
        else:
            where.append("dòng %d của output" % n)
    where = list(dict.fromkeys(where))
    if len(where) > 8:
        where = where[:8] + ["và %d chỗ khác" % (len(where) - 8)]
    text = name + (" `%s`" % target if target else "") + (": " + ", ".join(where) if where else "")
    return Redactor(key).redact_text(text)


def on_post_tool_batch(data):
    """Last gate before the next model request. tool_response here is exactly what the
    model is about to receive, after PostToolUse rewrites. Anything still secret got
    past the rewrite: a failed command (Claude Code doesn't let hooks rewrite failure
    output), a rewrite Claude Code rejected, or a PostToolUse hook that timed out."""
    r = Redactor()
    leaks = []
    for call in data.get("tool_calls") or []:
        before = len(r.hits)
        r.walk(call.get("tool_response"))
        if len(r.hits) > before:
            leaks.append(_describe_leak(call, r.key))
    if not leaks:
        return None
    try:  # remember, so the next prompt in this session gets a one-time warning
        marker = _blocked_marker(data)
        os.makedirs(os.path.dirname(marker), mode=0o700, exist_ok=True)
        open(marker, "w").close()
    except OSError:
        pass
    return {
        "decision": "block",
        "reason": (
            "tightlip: kết quả tool vẫn còn secret (%s) mà hook không che được (thường là output "
            "của lệnh bị lỗi). Đã dừng trước khi gửi lên model.\nNơi chứa secret:\n%s\n"
            "Hãy dùng /rewind (hoặc Esc Esc) quay về trước lượt này rồi mới tiếp tục: nếu nhắn tiếp "
            "ngay, nội dung đó sẽ được gửi lên model."
            % (r.summary(), "\n".join("- " + leak for leak in leaks))
        ),
    }


def on_user_prompt_submit(data):
    r = Redactor()
    r.redact_text(data.get("prompt") or "")
    if not r.hits:
        marker = _blocked_marker(data)
        if not os.path.exists(marker):
            return None
        try:
            os.remove(marker)
        except OSError:
            pass
        return {
            "decision": "block",
            "reason": (
                "tightlip: lượt trước bị dừng vì một kết quả tool còn chứa secret. Nội dung đó vẫn nằm "
                "trong hội thoại, nên nếu tiếp tục, nó sẽ được gửi lên model. Hãy dùng /rewind (hoặc Esc Esc) "
                "quay về trước lượt đó. Nếu đã rewind, hoặc chấp nhận gửi, hãy gửi lại prompt này "
                "(cảnh báo chỉ hiện một lần)."
            ),
        }
    return {
        "decision": "block",
        "reason": (
            "tightlip: prompt có giá trị giống secret (%s) nên đã bị chặn, chưa gửi lên model. "
            "Thay giá trị đó bằng tên biến môi trường (vd. $DB_PASSWORD) rồi gửi lại. Lưu ý: prompt vẫn "
            "có thể nằm trong history/transcript trên máy." % r.summary()
        ),
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True},
    }


HANDLERS = {
    "SessionStart": on_session_start,
    "PreToolUse": on_pre_tool_use,
    "PostToolUse": on_post_tool_use,
    "PostToolBatch": on_post_tool_batch,
    "UserPromptSubmit": on_user_prompt_submit,
}


def emit(obj):
    sys.stdout.buffer.write(json.dumps(obj, ensure_ascii=True).encode("ascii"))
    sys.stdout.flush()


def main(argv):
    if len(argv) > 1 and argv[1] in ("--filter", "-f"):
        text = sys.stdin.buffer.read().decode("utf-8", "replace")
        sys.stdout.buffer.write(Redactor().redact_text(text).encode("utf-8"))
        return 0
    if len(argv) > 1 and argv[1] == "--version":
        print(VERSION)
        return 0
    if flag("disable"):
        return 0
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8", "replace"))
    except ValueError:
        return 0
    event = data.get("hook_event_name")
    handler = HANDLERS.get(event)
    if handler is None:
        return 0
    try:
        out = handler(data)
    except Exception as exc:  # never break the session; tell the user the scan didn't run
        print("tightlip internal error in %s: %r" % (event, exc), file=sys.stderr)
        if event in ("PostToolUse", "PostToolBatch"):
            emit({"systemMessage": "tightlip lỗi nội bộ (%s), output này CHƯA được quét." % type(exc).__name__})
        return 0
    if out:
        emit(out)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
