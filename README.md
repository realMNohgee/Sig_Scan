# Sig_Scan 🔎

**A lightweight signature matcher (YARA-lite) in pure Python.** Define simple JSON rules with `ascii`, `hex`, or `regex` patterns, then scan files or whole directories and get back the file, the byte offset of the first hit, and the rule that fired. Zero dependencies, Python standard library only.

## Why it exists

You rarely need the full weight of YARA to answer "does this blob of files contain my string / these bytes / this pattern?" Sig_Scan keeps the 80% that matters — declarative rules, byte-accurate offsets, whole-directory scans — and drops the build step. Rules are plain JSON, so an agent or a CI job can generate them programmatically and read the results back as JSON.

## One tool, many domains

| Domain | What Sig_Scan does for you |
|---|---|
| **Incident response** | Grep a directory tree for known-bad markers (webshell strings, miner wallets, magic bytes) and log exact file offsets |
| **Malware triage** | Match `hex` signatures (magic bytes, embedded headers) against samples without running them |
| **DevOps / CI** | A JSON rule file in the repo gates secrets or forbidden patterns; `--format json` feeds the build |
| **Agentic AI** | Gives LLM agents a deterministic, machine-readable way to define a signature and cite every hit |
| **Forensics / DFIR** | Combine patterns under an `all` condition to require co-occurrence before a file is considered a match |

## Install

```bash
git clone <your-fork-url> Sig_Scan
cd Sig_Scan
python3 Sig_Scan.py --help
```

## Quick start

Define a rule, then scan a file for it:

```bash
python3 Sig_Scan.py define creds --ascii secret --dir /tmp/rules
python3 Sig_Scan.py scan /tmp/rules /tmp/sample.txt
```

```
Sig_Scan — signature match report
Rules:   1 (from /tmp/rules)
Scanned: 1 file(s)
Matches: 1
  /tmp/sample.txt offset=12 rule=creds type=ascii
```

The same scan as JSON:

```bash
python3 Sig_Scan.py scan /tmp/rules /tmp/sample.txt --format json
```

```json
{
  "rule_source": "/tmp/rules",
  "rules": 1,
  "scanned_files": 1,
  "total_matches": 1,
  "matches": [
    {
      "file": "/tmp/sample.txt",
      "rule": "creds",
      "type": "ascii",
      "offset": 12,
      "matched_patterns": 1,
      "total_patterns": 1
    }
  ]
}
```

### Pattern kinds

```bash
# ascii — literal text
python3 Sig_Scan.py define marker --ascii "MZ" --dir rules

# hex — raw bytes, spaces/colons tolerated
python3 Sig_Scan.py define png --hex "89504e470d0a1a0a" --dir rules

# regex — byte-compiled regular expression
python3 Sig_Scan.py define awskey --regex "AKIA[0-9A-Z]{16}" --dir rules
```

Repeat a kind flag to add multiple patterns, and choose how they combine:

```bash
python3 Sig_Scan.py define combo --ascii password --ascii root \
    --condition all --dir rules
```

- `--condition any` (default) — the rule fires when **any** pattern matches
- `--condition all` — the rule fires only when **every** pattern matches

### Rule file format

`define` writes this simple JSON shape; you can also hand-write it:

```json
{
  "name": "creds",
  "type": "ascii",
  "patterns": ["secret"],
  "condition": "any"
}
```

### Enumerate your rules

```bash
python3 Sig_Scan.py list rules
```

```
Rules in rules: 3
  creds  [ascii x1 any]  rules/creds.rule.json
  png    [hex x1 any]    rules/png.rule.json
  awskey [regex x1 any]  rules/awskey.rule.json
```

## Subcommands

| Command | What it does |
|---|---|
| `scan RULE FILE_OR_DIR` | Match the rule file (or every rule in a directory) against a file or directory tree |
| `define NAME [--ascii S] [--hex H] [--regex R]` | Write a JSON rule file |
| `list RULESDIR` | Enumerate the rules in a directory |

Every subcommand accepts `--format text|json`.

## License

MIT — see [LICENSE](LICENSE).

---

🧰 **[Tool on Hermtica Marketplace](https://hermtica.com/marketplace)**
