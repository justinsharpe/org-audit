#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
org_audit.py — recurring GitHub org hygiene sweep.

Audits every repo in a GitHub org via the GitHub API only — recursive trees, no
clones, no new credentials beyond `gh`. Compares against a committed baseline and
reports only what changed or what is alarming.

Design laws:
  L1  No clones. A whole org audits in ~2 minutes with no disk and no new
      credentials — `gh api` only.
  L2  Baseline is a COMMITTED file, so drift is reviewable in git history rather
      than hidden in local state.
  L3  Silent when healthy (watchdog contract): nothing to say -> no output.
  L4  A credential detector must test VOCABULARY, not shape. Shape alone produced
      a false alarm: `changeme-generate-a-long-random-value` is 37 chars of
      base64-ish text and looks exactly like a generated secret, but it is a
      placeholder. Any detector that judges by length and entropy will cry wolf
      and then be ignored — which is worse than not having one.

Usage:
  org_audit.py --org YOUR-ORG          # audit, print changes + alarms
  org_audit.py --org YOUR-ORG --save-baseline   # accept current state as normal
  org_audit.py --org YOUR-ORG --quiet           # silent unless something needs a decision
  org_audit.py --org YOUR-ORG --json            # machine-readable
  org_audit.py --self-test              # offline self-test (no gh, no network)
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import io
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RULES = os.path.join(HERE, "rules.json")
DEFAULT_BASELINE = os.path.join(HERE, "baseline.json")
ACCEPTED = os.path.join(HERE, "accepted.json")

# Built-in defaults used only when the self-test has no rules file on disk; the
# real default ships in rules.json so it can be edited without touching code.
_DEFAULT_RULES_RAW = {
    "size_alert_mb": 50,
    "placeholder_words": [
        "changeme", "change_me", "change-me", "your_", "your-", "example",
        "placeholder", "xxx", "todo", "dummy", "sample", "replace", "insert",
        "fill", "redacted", "notreal", "fake", "test-only",
    ],
    "cred_path": r"(^|/)(\.env(\.(local|production|prod|dev|development|staging))?|"
                 r"id_rsa|id_ed25519|credentials\.json|"
                 r"[^/]+\.(pem|p12|pfx|keystore))$",
    "deps_path": r"(^|/)(node_modules|\.venv|venv|vendor|__pycache__)/",
    "generated_path": r"(^|/)[^/]+\.(generated|min)\.(js|css|py)$",
}


def run(cmd):
    """Run a command and return (stdout, returncode, stderr). A missing `gh`
    binary is a hard, clearly-explained failure — not a silent empty result."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        sys.stderr.write(
            "error: '%s' not found. Install the GitHub CLI (gh) and log in.\n"
            % cmd[0])
        sys.exit(1)
    return proc.stdout, proc.returncode, proc.stderr


def build_parser():
    ap = argparse.ArgumentParser(
        description="GitHub org hygiene sweep: API-only, no clones.",
        epilog="--org is required on purpose: there is no silent default org.")
    ap.add_argument("--org", required=True,
                    help="GitHub org to audit (required; no default exists)")
    ap.add_argument("--rules", default=None,
                    help="path to rules.json (default: rules.json next to this script)")
    ap.add_argument("--baseline", default=None,
                    help="path to baseline.json (default: baseline.json next to this script)")
    ap.add_argument("--save-baseline", action="store_true",
                    help="record the current state as the baseline")
    ap.add_argument("--quiet", action="store_true",
                    help="print only if something needs a decision")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output")
    ap.add_argument("--self-test", action="store_true",
                    help="run the offline self-test (no gh, no network) and exit")
    return ap


# --------------------------------------------------------------------------- #
# rules
# --------------------------------------------------------------------------- #

def _compile_rules(raw):
    """Compile a rules dict (raw JSON) into the runtime shape. Raises KeyError
    or re.error on a bad spec so callers can report it clearly."""
    return {
        "size_alert_mb": int(raw.get("size_alert_mb", 50)),
        "placeholder_words": tuple(
            w.lower() for w in raw.get("placeholder_words", [])),
        "cred_path": re.compile(raw["cred_path"], re.I),
        "deps_path": re.compile(raw["deps_path"], re.I),
        "generated_path": re.compile(raw["generated_path"], re.I),
    }


def load_rules(path):
    path = path or DEFAULT_RULES
    if not os.path.exists(path):
        sys.stderr.write(
            "error: rules file not found: %s\n"
            "(recreate it, or point at it with --rules PATH)\n" % path)
        sys.exit(2)
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception as e:
        sys.stderr.write("error: could not parse rules file %s: %s\n" % (path, e))
        sys.exit(2)
    try:
        return _compile_rules(raw)
    except (KeyError, re.error) as e:
        sys.stderr.write(
            "error: rules file %s is missing an invalid key: %s\n" % (path, e))
        sys.exit(2)


# --------------------------------------------------------------------------- #
# gh plumbing
# --------------------------------------------------------------------------- #

def org_repos(org):
    out, rc, err = run(["gh", "api", "orgs/%s/repos" % org, "--paginate",
                        "-q", '.[] | "\\(.name)\\t\\(.visibility)\\t\\(.archived)"'])
    if rc != 0:
        sys.stderr.write(
            "error: could not list repos for org '%s': %s\n"
            "(is `gh` authenticated, and does the org exist?)\n"
            % (org, (err or out).strip()))
        sys.exit(1)
    repos = {}
    for line in out.strip().split("\n"):
        parts = line.split("\t")
        if len(parts) >= 2:
            repos[parts[0]] = (parts[1],
                               parts[2].strip() == "true" if len(parts) > 2
                               else False)
    return repos


def tree(org, name):
    raw, rc, err = run(["gh", "api",
                        "repos/%s/%s/git/trees/HEAD?recursive=1" % (org, name)])
    try:
        data = json.loads(raw)
    except Exception:
        data = None
    if isinstance(data, dict) and "tree" in data:
        return data["tree"]
    if rc != 0:
        # An empty repo has no HEAD; GitHub returns an error body for it. That
        # is a normal, expected result — not a defect. Anything else is a real
        # problem, surfaced as a warning so one broken repo doesn't sink the run.
        msg = data.get("message", "") if isinstance(data, dict) else ""
        if "empty" in msg.lower():
            return []
        sys.stderr.write("warning: could not fetch tree for %s: %s\n"
                         % (name, (err or msg or raw).strip()))
    return []


def gh_fetcher(org):
    """Return a fetch(repo, path) -> str|None callable backed by `gh`. Content
    is fetched on demand so the alarm pass can judge placeholder vocabulary."""
    import base64

    def fetch(repo, path):
        raw, rc, _ = run(["gh", "api",
                          "repos/%s/%s/contents/%s" % (org, repo, path)])
        if rc != 0:
            return None                     # unreadable -> caller decides
        try:
            return base64.b64decode(json.loads(raw)["content"]).decode(
                "utf-8", "replace")
        except Exception:
            return None

    return fetch


# --------------------------------------------------------------------------- #
# pure detection logic (offline-testable)
# --------------------------------------------------------------------------- #

def extract_values(text):
    """Return the right-hand-side values of KEY=VALUE lines, skipping comments
    and stripping one layer of surrounding quotes."""
    values = []
    for line in text.split("\n"):
        if "=" in line and not line.strip().startswith("#"):
            values.append(line.partition("=")[2].strip().strip('"').strip("'"))
    return values


def values_are_placeholder(values, placeholder_words):
    """L4: decide by VOCABULARY, not length/entropy. Empty or placeholder-valued
    entries are not secrets; anything else is treated as a candidate secret."""
    if not values:
        return True
    return all(any(w in v.lower() for w in placeholder_words) or not v
               for v in values)


def content_is_placeholder(fetcher, repo, path, placeholder_words):
    """Fetch a candidate secret and decide by VOCABULARY (L4). True means it
    reads like a placeholder, so the caller can downgrade instead of alarming.
    None means unreadable — the caller must verify by hand."""
    text = fetcher(repo, path)
    if text is None:
        return None
    return values_are_placeholder(extract_values(text), placeholder_words)


def accepted():
    """Deliberate dispositions, so a settled decision stops alarming every week.

    An alarm that fires on an accepted state is the fastest way to train people
    to ignore the report. Archiving an empty repo, or keeping design assets that
    are the only copy, are decisions — not defects."""
    if not os.path.exists(ACCEPTED):
        return {"archived": [], "size_ok": {}}
    try:
        with open(ACCEPTED, encoding="utf-8") as fh:
            d = json.load(fh)
        return {"archived": d.get("archived", []),
                "size_ok": d.get("size_ok", {})}
    except Exception:
        return {"archived": [], "size_ok": {}}


def audit(org, rules):
    """One tree fetch per repo; the paths are returned alongside the state so the
    alarm pass never re-fetches (halves the API calls)."""
    repos = org_repos(org)
    state, trees = {}, {}
    for name, (vis, arch) in sorted(repos.items()):
        blobs = [(b.get("size", 0), b["path"]) for b in tree(org, name)
                 if b.get("type") == "blob"]
        state[name] = {
            "visibility": vis,
            "archived": arch,
            "files": len(blobs),
            "bytes": sum(s for s, _ in blobs),
        }
        trees[name] = [p for _, p in blobs]
    return state, trees


def inspect(name, state, paths, rules, fetcher):
    """Per-repo alarm pass. Aggregated: one line per (repo, kind, target), with a
    count — never one line per file. A detector that prints 250 KB is a detector
    nobody reads."""
    if not paths:
        return ["%s: repo is EMPTY" % name], []

    alarms, notes = [], []
    vis = state.get(name, {}).get("visibility", "private")
    creds, deps, gen = [], collections.Counter(), []

    for p in paths:
        cm = rules["cred_path"].search(p)
        if cm:
            creds.append(p)
            continue
        dm = rules["deps_path"].search(p)
        if dm:
            deps[dm.group(2)] += 1          # the MATCHED dir, not the top-level one
            continue
        if rules["generated_path"].search(p):
            gen.append(p)

    for p in creds:
        if vis == "public":
            ph = content_is_placeholder(fetcher, name, p,
                                        rules["placeholder_words"])
            if ph is False:
                alarms.append("%s [PUBLIC]: %s holds a NON-placeholder value"
                              % (name, p))
            elif ph is True:
                notes.append("%s: %s is placeholder-valued (ok)" % (name, p))
            else:
                alarms.append("%s [PUBLIC]: %s unreadable — verify by hand"
                              % (name, p))
        else:
            notes.append("%s: %s (private — lower risk)" % (name, p))

    for d, n in deps.most_common():
        alarms.append("%s: dependency dir '%s/' is tracked (%d file%s)"
                      % (name, d, n, "" if n == 1 else "s"))

    for p in gen[:5]:
        alarms.append("%s: generated build output tracked (%s)" % (name, p))
    if len(gen) > 5:
        alarms.append("%s: +%d more generated file(s) tracked"
                      % (name, len(gen) - 5))

    return alarms, notes


def compute_changes(cur, prev):
    """Diff current state against the baseline; one line per interesting repo."""
    changes = []
    for name in sorted(set(cur) | set(prev)):
        if name not in prev:
            changes.append("NEW repo: %s" % name)
        elif name not in cur:
            changes.append("REMOVED repo: %s" % name)
        else:
            d = cur[name]["bytes"] - prev[name]["bytes"]
            if abs(d) > 2 * 1024 * 1024:
                changes.append("%s: %+.1f MB (now %.1f MB)"
                               % (name, d / 1048576,
                                  cur[name]["bytes"] / 1048576))
            if cur[name]["files"] != prev[name]["files"]:
                changes.append("%s: %+d files (now %d)"
                               % (name, cur[name]["files"] - prev[name]["files"],
                                  cur[name]["files"]))
    return changes


def size_alarms(cur, acc, size_alert_mb):
    alarms, settled = [], []
    for name, s in cur.items():
        if name in acc["archived"] or s.get("archived"):
            continue
        if s["bytes"] > size_alert_mb * 1048576:
            if name in acc["size_ok"]:
                settled.append("%s: %.1f MB (accepted — %s)"
                               % (name, s["bytes"] / 1048576,
                                  acc["size_ok"][name]))
                continue
            alarms.append("%s: %.1f MB (over the %d MB threshold)"
                          % (name, s["bytes"] / 1048576, size_alert_mb))
    return alarms, settled


# --------------------------------------------------------------------------- #
# self-test
# --------------------------------------------------------------------------- #

def _walk_paths(root):
    """List relative paths (forward slashes) under root, excluding nothing — the
    detector decides what matters. Used by the offline self-test."""
    paths = []
    for dirpath, _dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
        for fn in filenames:
            paths.append(fn if rel == "." else "%s/%s" % (rel, fn))
    return paths


def self_test():
    import shutil
    import tempfile

    failures = []

    def check(name, cond, detail=""):
        tag = "ok  " if cond else "FAIL"
        print("  %s  %s%s" % (tag, name, (" — " + detail) if detail else ""))
        if not cond:
            failures.append(name)

    print("org_audit self-test (offline — no gh, no network)")
    print("=" * 60)

    # 1. default rules load and compile
    try:
        with open(DEFAULT_RULES, encoding="utf-8") as fh:
            rules = _compile_rules(json.load(fh))
        check("default rules.json loads and compiles", True)
    except Exception as e:
        rules = None
        check("default rules.json loads and compiles", False, str(e))

    if rules is None:
        print("\n%d check(s) FAILED" % len(failures))
        return 1

    words = rules["placeholder_words"]

    # 2. the headline insight: vocabulary, not shape
    placeholder = "changeme-generate-a-long-random-value"   # 37 chars, base64-ish
    real_secret = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    check("placeholder phrase is NOT flagged as a secret",
          values_are_placeholder([placeholder], words) is True)
    check("a real-looking secret IS flagged as a secret",
          values_are_placeholder([real_secret], words) is False)
    check("empty value is treated as placeholder (no false alarm)",
          values_are_placeholder([""], words) is True)

    # 3. CRED_PATH matches real env/secret files only, never .env.example
    cred = rules["cred_path"]
    for p, want in [
            (".env", True), (".env.local", True), (".env.production", True),
            (".env.example", False), (".env.sample", False), (".env.test", False),
            ("config/id_rsa", True), ("certs/tls.pem", True),
            ("README.md", False)]:
        check("cred_path %s '%s'" % ("matches" if want else "ignores", p),
              bool(cred.search(p)) is want)

    # 4. extract_values parses KEY=VALUE and skips comments/quotes
    text = "# a comment\nKEY1=value1\nKEY2='quoted'\nKEY3=\"dq\"\nNOEQUALS\n"
    got = extract_values(text)
    check("extract_values pulls only RHS values, strips quotes",
          got == ["value1", "quoted", "dq"], str(got))

    # 5. offline end-to-end: build a throwaway tree on disk and run the detector
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "node_modules", "lodash"))
        os.makedirs(os.path.join(td, "webpack"))
        files = {
            ".env": "REAL_SECRET=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n",
            ".env.example": "API_KEY=changeme\n",
            "node_modules/lodash/index.js": "// x\n",
            "webpack/app.min.js": "var x=1;\n",
            "README.md": "# hi\n",
        }
        for rel, body in files.items():
            full = os.path.join(td, *rel.split("/"))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as fh:
                fh.write(body)

        def disk_fetcher(root):
            def fetch(repo, path):
                try:
                    with open(os.path.join(root, *path.split("/")),
                              encoding="utf-8") as fh:
                        return fh.read()
                except Exception:
                    return None
            return fetch

        paths = _walk_paths(td)
        state = {"fixture-repo": {"visibility": "public", "archived": False}}
        alarms, notes = inspect("fixture-repo", state, paths, rules,
                                disk_fetcher(td))
        joined = "\n".join(alarms)
        check(".env with a real secret raises a NON-placeholder alarm",
              any("NON-placeholder" in a for a in alarms))
        check(".env.example does NOT raise a credential alarm",
              not any(".env.example" in a for a in alarms))
        check("tracked node_modules/ raises an alarm",
              any("node_modules" in a for a in alarms))
        check("tracked *.min.js raises a generated-output alarm",
              any("generated build output" in a for a in alarms))

        # 6. private repos downgrade credentials to notes, never alarms
        priv_state = {"fixture-repo": {"visibility": "private", "archived": False}}
        p_alarms, p_notes = inspect("fixture-repo", priv_state, paths, rules,
                                    disk_fetcher(td))
        check("private repo credentials become notes, not alarms",
              not any("NON-placeholder" in a for a in p_alarms)
              and any("private" in n for n in p_notes))

        # 7. empty repo is flagged
        e_alarms, _ = inspect("empty-repo",
                              {"empty-repo": {"visibility": "public",
                                              "archived": False}},
                              [], rules, disk_fetcher(td))
        check("an empty repo is flagged", any("EMPTY" in a for a in e_alarms))

    # 8. change diff and size threshold
    prev = {"a": {"bytes": 1_000_000, "files": 10}}
    cur = {"a": {"bytes": 10_000_000, "files": 10},
           "b": {"bytes": 5, "files": 1}}
    changes = compute_changes(cur, prev)
    check("size drift and NEW/REMOVED repos are detected",
          any("NEW repo: b" in c for c in changes)
          and any("a:" in c for c in changes))
    acc = {"archived": ["big-ok"], "size_ok": {"kept": "deliberately kept"}}
    st = {"big": {"bytes": 60 * 1048576, "archived": False},
          "big-ok": {"bytes": 60 * 1048576, "archived": True},
          "kept": {"bytes": 60 * 1048576, "archived": False},
          "small": {"bytes": 5, "archived": False}}
    a2, settled = size_alarms(st, acc, 50)
    check("size threshold flags over-limit repos and honours dispositions",
          any("big:" in a for a in a2)
          and any("kept:" in s for s in settled)
          and not any("big-ok" in a for a in a2))

    # 9. --org is required (argparse exits 2 with a clear message)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stderr(buf):
            build_parser().parse_args(["--json"])
        check("--org is required (absent -> error exit 2)", False)
    except SystemExit as e:
        check("--org is required (absent -> error exit 2)", e.code == 2)

    print("-" * 60)
    if failures:
        print("%d check(s) FAILED: %s" % (len(failures), ", ".join(failures)))
        return 1
    print("all checks passed")
    return 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    # The self-test is offline and never needs an org; run it before the parser
    # (which would otherwise reject a --self-test invocation for missing --org).
    if "--self-test" in argv:
        return self_test()

    a = build_parser().parse_args(argv)

    org = (a.org or "").strip()
    if not org:
        sys.stderr.write(
            "error: --org must not be empty. There is no default org — pass the "
            "org you want to audit, e.g. --org your-org-name.\n")
        return 2

    rules = load_rules(a.rules)
    baseline = a.baseline or DEFAULT_BASELINE
    fetcher = gh_fetcher(org)

    cur, trees = audit(org, rules)

    if a.save_baseline:
        with open(baseline, "w", encoding="utf-8") as fh:
            json.dump(cur, fh, indent=1, sort_keys=True)
        print("baseline saved: %d repo(s) -> %s" % (len(cur), baseline))
        return 0

    prev = {}
    if os.path.exists(baseline):
        try:
            with open(baseline, encoding="utf-8") as fh:
                prev = json.load(fh)
        except Exception:
            prev = {}

    changes = compute_changes(cur, prev)
    acc = accepted()

    alarms, notes = [], []
    settled = []
    for name in sorted(cur):
        if name in acc["archived"] or cur[name].get("archived"):
            settled.append("%s: archived (accepted — no longer implies a service)"
                           % name)
            continue
        al, nt = inspect(name, cur, trees.get(name, []), rules, fetcher)
        alarms += al
        notes += nt

    s_alarms, s_settled = size_alarms(cur, acc, rules["size_alert_mb"])
    alarms += s_alarms
    settled += s_settled

    if a.json:
        print(json.dumps({"changes": changes, "alarms": alarms,
                          "notes": notes, "state": cur}, indent=1))
        return 0

    if a.quiet and not changes and not alarms:
        return 0                                            # healthy: say nothing

    total = sum(s["bytes"] for s in cur.values())
    print("org audit — %s: %d repos, %s files, %.1f MB"
          % (org, len(cur),
             "{:,}".format(sum(s["files"] for s in cur.values())),
             total / 1048576))
    if changes:
        print("\nCHANGED since baseline:")
        for c in changes:
            print("  " + c)
    else:
        print("\n  no size/file changes since baseline")
    if settled:
        print("\nsettled (accepted — will not alarm):")
        for x in settled:
            print("  - " + x)
    if alarms:
        print("\nALARMS:")
        for x in alarms:
            print("  ! " + x)
    if notes and not a.quiet:
        print("\nchecked and fine:")
        for n in notes[:10]:
            print("  - " + n)
    print("\n(re-run with --save-baseline to accept the current state as normal)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
