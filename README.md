# org-audit — recurring GitHub org hygiene sweep

A single Python script that audits every repo in a GitHub org **through the
GitHub API only** — recursive trees, no clones, no new credentials beyond `gh`
— and reports only what changed or what is alarming.

## Why this exists

Two failure modes, each solved by a rule that is easy to state and easy to get
wrong:

1. **A secret detector that judges shape will cry wolf, and a detector that
   cries wolf gets ignored.** An earlier revision flagged a public repo's
   `.env.example` as containing a likely-live `RCON_PASSWORD`. It looked
   convincing: 37 characters, base64-ish, entropy 3.6. It was wrong — the value
   was `changeme-generate-a-long-random-value`, a textbook placeholder. Length
   and entropy cannot distinguish a secret from a placeholder, because a
   placeholder written as a hyphenated phrase has both. So the credential check
   here tests **vocabulary, not shape**: a candidate file's values are fetched
   and each one is tested for placeholder words (`changeme`, `your_`,
   `example`, `xxx`, …). Only a value that fails that test raises an alarm.

2. **A detector that prints everything is a detector nobody reads.** The first
   version of this script emitted 253 KB of alarms for one org because it
   printed one line per offending file. The same run now produces ~1 KB and a
   handful of alarms, because output is aggregated to one line per
   (repo, kind, target) with a count. Output discipline is a feature, not a
   nicety.

The rest is a hygiene sweep: tracked dependency directories, tracked generated
build output, empty repos that imply a service that isn't there, and size drift
against a committed baseline.

## Usage

```bash
# Audit an org: changes since baseline + alarms
python3 org_audit.py --org YOUR-ORG

# Accept the current state as normal (writes baseline.json)
python3 org_audit.py --org YOUR-ORG --save-baseline

# Silent unless something needs a decision (watchdog-friendly)
python3 org_audit.py --org YOUR-ORG --quiet

# Machine-readable
python3 org_audit.py --org YOUR-ORG --json

# Offline self-test — no `gh`, no network, no auth
python3 org_audit.py --self-test
```

`--org` is **required on purpose**. There is no silent default org, so an
audit can never quietly run against the wrong account.

Requires the [GitHub CLI](https://cli.github.com/) (`gh`) to be installed and
authenticated.

## Mechanism

The checklist is **config-driven** via [`rules.json`](rules.json) — no code
edits needed to tune it:

- `cred_path` — regex for real secret files only (`.env`, `.env.local`,
  `.env.production`, `id_rsa`, `*.pem`, `*.p12`, `*.pfx`, `*.keystore`).
  `.env.example`, `.env.sample`, and `.env.test` are *correct practice* and are
  deliberately **not** matched.
- `placeholder_words` — the vocabulary that a value must contain to be
  downgraded from "candidate secret" to "placeholder".
- `deps_path` — dependency directories (`node_modules/`, `.venv/`, `vendor/`,
  `__pycache__/`).
- `generated_path` — generated/minified build output (`*.generated.js`,
  `*.min.js`, `*.min.css`, `*.min.py`).
- `size_alert_mb` — a repo crossing this threshold is flagged.

For each repo it lists the repo and fetches a recursive git tree (one API call
per repo, no clones, no disk), counts files and bytes, and then runs three
checks:

1. **Vocabulary-checked credentials.** Every path matching `cred_path` in a
   public repo has its content fetched; each `KEY=VALUE` is tested for
   placeholder vocabulary. A non-placeholder value raises an alarm; a
   placeholder is recorded as fine; an unreadable file asks for manual
   verification. Private repos are noted as lower risk rather than alarmed.
2. **Tracked dependency directories and generated output.**
3. **Size and drift.** Per-repo byte/file deltas against `baseline.json`, plus
   the `size_alert_mb` threshold.

**Dispositions** (`accepted.json`) let you permanently settle a decision so it
stops alarming: archive an empty repo, or acknowledge a large repo that is
deliberately kept. An alarm that keeps firing on an accepted state trains
people to ignore the whole report.

## Baseline

`baseline.json` is **committed**, so drift is reviewable in git history rather
than hidden in local state. Re-run with `--save-baseline` to accept a new
normal. (This repository ships no baseline — it is generated on first run for
your org.)

## Self-test

`python3 org_audit.py --self-test` exercises the full detection pipeline with
**no `gh`, no network, and no credentials**: it builds a throwaway directory
tree on disk (a `.env` with a real secret, a `.env.example` placeholder,
`node_modules/`, a `*.min.js`), runs the detector against it, and checks the
placeholder-vocabulary logic, the `cred_path` allowlist, change diffing, the
size threshold, and that `--org` is required. Exit code `0` means all checks
passed.

## License

MIT — see [LICENSE](LICENSE).
