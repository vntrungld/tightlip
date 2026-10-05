#!/usr/bin/env python3
"""Install tightlip without the plugin system: copies tightlip.py to
~/.claude/hooks/ and merges settings.example.json into ~/.claude/settings.json.
Use this OR the plugin, not both.

Existing hooks, env vars and permission rules are kept; a timestamped backup of
settings.json is written first. Running it again updates the installed copy and
doesn't duplicate entries.

  python3 install.py              install
  python3 install.py --dry-run    print the merged settings.json, change nothing
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "plugins", "tightlip", "scripts", "tightlip.py")
MARK = "tightlip.py"


def merge(current, snippet, with_deny=True):
    merged = json.loads(json.dumps(current))
    hooks = merged.setdefault("hooks", {})
    for event, groups in snippet["hooks"].items():
        existing = hooks.setdefault(event, [])
        # drop any earlier tightlip handler, then add the current one
        for group in existing:
            group["hooks"] = [h for h in group.get("hooks", []) if MARK not in h.get("command", "")]
        existing[:] = [g for g in existing if g.get("hooks")]
        existing.extend(json.loads(json.dumps(groups)))
    if with_deny:
        deny = merged.setdefault("permissions", {}).setdefault("deny", [])
        for rule in snippet.get("permissions", {}).get("deny", []):
            if rule not in deny:
                deny.append(rule)
    return merged


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="print the merged settings and exit")
    ap.add_argument("--claude-dir", default=os.path.join(os.path.expanduser("~"), ".claude"))
    ap.add_argument("--no-deny", action="store_true", help="don't add the permissions.deny rules")
    args = ap.parse_args()

    claude_dir = os.path.abspath(os.path.expanduser(args.claude_dir))
    settings_path = os.path.join(claude_dir, "settings.json")
    target = os.path.join(claude_dir, "hooks", MARK)

    snippet = json.load(open(os.path.join(HERE, "settings.example.json"), encoding="utf-8"))
    if claude_dir != os.path.join(os.path.expanduser("~"), ".claude"):
        cmd = 'python3 "%s"' % target
        for groups in snippet["hooks"].values():
            for g in groups:
                for h in g["hooks"]:
                    h["command"] = cmd

    current = {}
    if os.path.exists(settings_path):
        try:
            current = json.load(open(settings_path, encoding="utf-8"))
        except ValueError as exc:
            sys.exit("Không đọc được %s (JSON lỗi: %s). Sửa file rồi chạy lại." % (settings_path, exc))

    merged = merge(current, snippet, with_deny=not args.no_deny)
    if any("tightlip@" in k and v for k, v in current.get("enabledPlugins", {}).items()):
        print("Lưu ý: plugin tightlip đang bật. Chỉ nên dùng một trong hai cách cài.")
    if args.dry_run:
        print(json.dumps(merged, indent=2, ensure_ascii=False))
        return

    os.makedirs(os.path.dirname(target), exist_ok=True)
    shutil.copy2(SCRIPT, target)
    os.chmod(target, 0o755)
    if os.path.exists(settings_path):
        backup = "%s.bak-%s" % (settings_path, time.strftime("%Y%m%d-%H%M%S"))
        n = 1
        while os.path.exists(backup):
            backup = "%s.bak-%s-%d" % (settings_path, time.strftime("%Y%m%d-%H%M%S"), n)
            n += 1
        shutil.copy2(settings_path, backup)
        print("Backup: " + backup)
    tmp = settings_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, settings_path)

    probe = subprocess.run(["python3", target, "--filter"], input=b"DB_PASSWORD=hunter2hunter2\n",
                           capture_output=True)
    ok = b"[REDACTED:" in probe.stdout
    print("Đã cài %s" % target)
    print("Đã cập nhật %s" % settings_path)
    print("Tự kiểm tra: %s" % ("OK" if ok else "LỖI: " + probe.stderr.decode(errors="replace")))
    print("Mở /hooks trong Claude Code để xác nhận, hoặc khởi động lại phiên đang chạy.")


if __name__ == "__main__":
    main()
