#!/usr/bin/env python3
"""Sig_Scan — a lightweight signature matcher (YARA-lite).

Define simple JSON rules with ascii, hex, or regex patterns and scan files or
whole directories for matches. Each hit reports the file, the byte offset of
the first match, and the rule that fired. A rule's patterns combine under an
'any' or 'all' condition, so one rule can express "contains any of these" or
"contains all of these".

Zero dependencies — Python standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

# Rule files carry this suffix so `list` can tell rules apart from other JSON.
RULE_SUFFIX = ".rule.json"

# The three supported pattern kinds.
PATTERN_KINDS = ("ascii", "hex", "regex")

# Condition keywords: match if any pattern hits, or only if every pattern hits.
CONDITIONS = ("any", "all")


def _fail(msg, code=2):
    """Print a clear error to stderr and return a non-zero exit code."""
    print("error: " + msg, file=sys.stderr)
    return code


def _literal_finder(needle):
    """Build a matcher that finds a literal byte sequence.

    bytes.find() returns -1 on a miss, so normalise that to None to keep the
    "match offset or None" contract the rest of the scanner relies on.
    """
    def find(data, needle=needle):
        if not needle:
            return None
        off = data.find(needle)
        return off if off >= 0 else None
    return find


def _compile_pattern(kind, value):
    """Compile one pattern into a byte matcher.

    Returns a callable that takes file bytes and returns the first match offset
    (int) or None. ascii/hex match literal byte sequences; regex matches a
    byte-compiled regular expression so reported offsets stay byte-accurate.
    """
    if kind == "ascii":
        return _literal_finder(value.encode("utf-8"))
    if kind == "hex":
        # Tolerate spaces and colons so "de ad be ef" and "de:ad:be:ef" work.
        cleaned = re.sub(r"[\s:]+", "", value)
        return _literal_finder(bytes.fromhex(cleaned))
    # kind == "regex": compile against bytes so offsets are byte offsets.
    rx = re.compile(value.encode("utf-8"))
    return lambda data, rx=rx: (m.start() if (m := rx.search(data)) else None)


def _load_rule(path):
    """Load and validate a single JSON rule file.

    Returns a normalised dict {name, type, patterns, condition}. Raises
    ValueError with a human-readable message on any structural problem.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except OSError as exc:
        raise ValueError("cannot read rule file {}: {}".format(path, exc))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSON in {}: {}".format(path, exc))
    if not isinstance(raw, dict):
        raise ValueError("rule {} must be a JSON object".format(path))
    # Fall back to the filename stem when the rule omits a name.
    name = raw.get("name") or os.path.basename(path).split(".")[0]
    kind = raw.get("type")
    if kind not in PATTERN_KINDS:
        raise ValueError(
            "rule {}: 'type' must be one of {}".format(name, ", ".join(PATTERN_KINDS))
        )
    patterns = raw.get("patterns")
    if isinstance(patterns, str):
        patterns = [patterns]  # tolerate a bare string instead of a list
    if not isinstance(patterns, list) or not patterns:
        raise ValueError("rule {}: 'patterns' must be a non-empty list".format(name))
    condition = raw.get("condition", "any")
    if condition not in CONDITIONS:
        raise ValueError("rule {}: 'condition' must be 'any' or 'all'".format(name))
    return {"name": name, "type": kind, "patterns": patterns, "condition": condition}


def _iter_rule_files(path):
    """Yield every rule file under `path` (a single file, or a directory tree)."""
    if os.path.isfile(path):
        yield path
        return
    for root, _dirs, files in os.walk(path):
        for fn in sorted(files):
            if fn.endswith(".json"):
                yield os.path.join(root, fn)


def _scan_file(path, rules):
    """Scan one file against compiled rules; return (hits, error).

    Exactly one of the two return values is non-None: on a read error the
    second element carries the message and hits is None.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return None, "cannot read {}: {}".format(path, exc)
    hits = []
    for rule in rules:
        offsets = []
        for matcher in rule["matchers"]:
            off = matcher(data)
            if off is not None:
                offsets.append(off)
        # Apply the rule's condition across all of its patterns.
        if rule["condition"] == "all":
            fired = len(offsets) == len(rule["matchers"])
        else:
            fired = len(offsets) > 0
        if fired:
            hits.append({
                "file": path,
                "rule": rule["name"],
                "type": rule["type"],
                # Report the earliest matching offset in the file.
                "offset": min(offsets) if offsets else -1,
                "matched_patterns": len(offsets),
                "total_patterns": len(rule["matchers"]),
            })
    return hits, None


def cmd_scan(args):
    """Match rules against a file or directory (`scan`)."""
    rule_path = args.rule
    if not os.path.exists(rule_path):
        return _fail("rule path not found: {}".format(rule_path))
    # Load every rule first so a malformed rule aborts before any scanning.
    rules = []
    for rp in _iter_rule_files(rule_path):
        try:
            rules.append(_load_rule(rp))
        except ValueError as exc:
            return _fail(str(exc))
    if not rules:
        return _fail("no rule files found at {}".format(rule_path))
    # Pre-compile each rule's matchers once (patterns are reused per file).
    for rule in rules:
        try:
            rule["matchers"] = [
                _compile_pattern(rule["type"], p) for p in rule["patterns"]
            ]
        except (ValueError, re.error) as exc:
            return _fail("bad pattern in rule {}: {}".format(rule["name"], exc))

    target = args.target
    if not os.path.exists(target):
        return _fail("target not found: {}".format(target))
    # Expand a directory into its file list; a single file scans as itself.
    if os.path.isdir(target):
        files = []
        for root, _dirs, names in os.walk(target):
            for n in sorted(names):
                files.append(os.path.join(root, n))
    else:
        files = [target]

    matches = []
    for f in files:
        hits, err = _scan_file(f, rules)
        if err:
            continue  # unreadable/binary file: skip but keep scanning the rest
        matches.extend(hits)

    result = {
        "rule_source": rule_path,
        "rules": len(rules),
        "scanned_files": len(files),
        "total_matches": len(matches),
        "matches": matches,
    }
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Sig_Scan — signature match report")
        print("Rules:   {} (from {})".format(len(rules), rule_path))
        print("Scanned: {} file(s)".format(len(files)))
        print("Matches: {}".format(len(matches)))
        for m in matches:
            print("  {} offset={} rule={} type={}".format(
                m["file"], m["offset"], m["rule"], m["type"]))
    return 0


def cmd_define(args):
    """Write a JSON rule file (`define`)."""
    # Determine which pattern kind the user supplied (exactly one is allowed).
    kinds_given = [k for k in PATTERN_KINDS if getattr(args, k)]
    if not kinds_given:
        return _fail("define needs at least one of --ascii, --hex, --regex")
    if len(kinds_given) > 1:
        return _fail("use only one of --ascii, --hex, --regex per rule")
    kind = kinds_given[0]
    values = getattr(args, kind)
    # Validate hex eagerly so bad input never lands in a rule file.
    if kind == "hex":
        for v in values:
            try:
                bytes.fromhex(re.sub(r"[\s:]+", "", v))
            except ValueError:
                return _fail("invalid hex value: {!r}".format(v))
    rule = {
        "name": args.name,
        "type": kind,
        "patterns": values,
        "condition": args.condition,
    }
    out_dir = args.dir
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, args.name + RULE_SUFFIX)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(rule, fh, indent=2)
        fh.write("\n")
    result = {"written": out_path, "rule": rule}
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("wrote rule {!r} -> {}".format(args.name, out_path))
        print("  type:      {}".format(kind))
        print("  patterns:  {}".format(", ".join(values)))
        print("  condition: {}".format(args.condition))
    return 0


def cmd_list(args):
    """Enumerate rule files in a directory (`list`)."""
    rules_dir = args.rulesdir
    if not os.path.isdir(rules_dir):
        return _fail("rules directory not found: {}".format(rules_dir))
    entries = []
    for rp in _iter_rule_files(rules_dir):
        try:
            rule = _load_rule(rp)
            entries.append({
                "file": rp,
                "name": rule["name"],
                "type": rule["type"],
                "patterns": len(rule["patterns"]),
                "condition": rule["condition"],
            })
        except ValueError as exc:
            # A broken rule is reported inline rather than aborting the listing.
            entries.append({"file": rp, "error": str(exc)})
    result = {"rulesdir": rules_dir, "count": len(entries), "rules": entries}
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("Rules in {}: {}".format(rules_dir, len(entries)))
        for e in entries:
            if "error" in e:
                print("  ! {}: {}".format(e["file"], e["error"]))
            else:
                print("  {}  [{} x{} {}]  {}".format(
                    e["name"], e["type"], e["patterns"], e["condition"], e["file"]))
    return 0


def main(argv=None):
    # Shared parent parser: --format is attached to EVERY subcommand, never
    # to the top-level parser, so it is only valid after the subcommand name.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )

    parser = argparse.ArgumentParser(
        prog="Sig_Scan",
        description="Lightweight YARA-lite signature matcher (stdlib only).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser(
        "scan", parents=[common],
        help="Match rules against a file or directory")
    p_scan.add_argument("rule", help="Rule file, or a directory of .rule.json files")
    p_scan.add_argument("target", help="File or directory to scan")
    p_scan.set_defaults(func=cmd_scan)

    p_define = sub.add_parser(
        "define", parents=[common], help="Write a JSON rule file")
    p_define.add_argument("name", help="Rule name (also the output filename stem)")
    p_define.add_argument("--ascii", action="append", metavar="S",
                          help="Ascii pattern (repeatable)")
    p_define.add_argument("--hex", action="append", metavar="H",
                          help="Hex byte pattern, e.g. 'deadbeef' (repeatable)")
    p_define.add_argument("--regex", action="append", metavar="R",
                          help="Regex pattern (repeatable)")
    p_define.add_argument("--condition", choices=CONDITIONS, default="any",
                          help="Match on any|all patterns (default: any)")
    p_define.add_argument("--dir", default=".", metavar="DIR",
                          help="Directory to write the rule into (default: .)")
    p_define.set_defaults(func=cmd_define)

    p_list = sub.add_parser(
        "list", parents=[common], help="Enumerate rules in a directory")
    p_list.add_argument("rulesdir", help="Directory containing rule files")
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args(argv)  # parse exactly once
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
