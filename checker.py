#!/usr/bin/env python3
"""
scan_firmware_risks.py — Find defect-prone sites in firmware C/C++ source.

This is a lead generator for black-box test design, not a verifier. It has no
type information and no call graph, so it deliberately over-reports: it is far
cheaper to discard a false positive during review than to miss a data-corruption
path. Every finding must be read in context before it becomes a test case.

Output: JSON with risk sites grouped by category, plus a candidate list of
externally reachable entry points.

Usage:
    python scan_firmware_risks.py <file_or_directory> [--output risks.json]
                                  [--category BOUNDARY,CONCURRENCY]
                                  [--min-severity medium]
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

SOURCE_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

# --------------------------------------------------------------------------
# Pattern definitions
# Each: (category, severity, compiled regex, explanation, test hint)
# --------------------------------------------------------------------------

PATTERNS = [
    # ---- Boundary / comparison ----
    (
        "BOUNDARY",
        "high",
        re.compile(
            r"\b(if|while|for)\s*\([^)]*?"
            r"(\b\w*(len|size|count|cnt|num|nlb|nsz|idx|index|offset|end|start|slba|lba|limit|max|blocks?|sectors?|entries)\w*\s*(<=|>=|<|>)\s*\w+"
            r"|\b\w+\s*(<=|>=|<|>)\s*\w*(len|size|count|cnt|num|nlb|nsz|capacity|limit|max|total|blocks?|sectors?|entries)\w*\b)",
            re.IGNORECASE,
        ),
        "Comparison against a length/size/count limit — classic off-by-one location",
        "Sweep this field with MAX-1, MAX, MAX+1 and a range whose end lands exactly on the limit",
    ),
    (
        "BOUNDARY",
        "high",
        re.compile(r"\w+\s*\[\s*\w*(idx|index|i|n|offset|id|slot|tag|num)\w*\s*\]", re.IGNORECASE),
        "Array indexed by a variable — check the index is validated against the array bound",
        "Drive the index field to its maximum legal value and one past it",
    ),
    (
        "BOUNDARY",
        "medium",
        re.compile(r"(?<![<>=!])=\s*\w+\s*[-+]\s*1\b"),
        "Explicit +1/-1 adjustment — inspect whether the boundary is inclusive or exclusive",
        "Test the exact endpoint the adjustment is meant to handle",
    ),

    # ---- Unbounded copy ----
    (
        "UNBOUNDED_COPY",
        "high",
        re.compile(r"\b(strcpy|strcat|sprintf|gets|memcpy|memmove)\s*\("),
        "Copy without an inherent bound (or with a length that may be host-controlled)",
        "Supply the maximum and an over-maximum transfer length; verify the full byte range afterwards",
    ),
    (
        "UNBOUNDED_COPY",
        "medium",
        re.compile(r"\b(memcpy|memmove|memset)\s*\([^;]*\b\w*(len|size|count|nlb)\w*\s*[*]\s*\w+"),
        "Copy length computed by multiplication — overflow can shrink the copy or overrun the buffer",
        "Use field values whose product crosses 2^16 and 2^32",
    ),

    # ---- Input validation ----
    (
        "UNCHECKED_INPUT",
        "high",
        re.compile(
            r"\b(cmd|command|req|request|sqe|cdw\d+|dw\d+|host|param|pkt|packet|msg)\b\s*(->|\.)\s*\w+",
            re.IGNORECASE,
        ),
        "Host-supplied field dereferenced — confirm it is range-checked before use",
        "Fuzz this field across boundary values and reserved/illegal encodings",
    ),
    (
        "UNCHECKED_INPUT",
        "medium",
        re.compile(r"\bassert\s*\([^)]*(cmd|param|len|size|input|arg)", re.IGNORECASE),
        "assert() used on input — asserts are usually compiled out in release builds, leaving no validation",
        "Send the illegal value the assert guards against and check the release build rejects it cleanly",
    ),
    (
        "UNCHECKED_INPUT",
        "low",
        re.compile(r"\breserved\b|\brsvd\b", re.IGNORECASE),
        "Reserved field referenced — spec usually requires validation or defined ignore behavior",
        "Set reserved fields to non-zero and confirm the specified behavior",
    ),

    # ---- State machine ----
    (
        "STATE_MACHINE",
        "medium",
        re.compile(r"\bswitch\s*\([^)]*\b(state|status|phase|mode|opcode|opc|cmd)\w*\s*\)", re.IGNORECASE),
        "Dispatch or state switch — check every case and whether default: exists",
        "Build the state x event matrix and attack the combinations with no explicit handler",
    ),
    (
        "STATE_MACHINE",
        "medium",
        re.compile(r"\b\w*(state|phase|mode)\w*\s*=\s*(?!=)\w+", re.IGNORECASE),
        "State assignment — verify it is guarded by the current state and cannot be reached out of order",
        "Issue the triggering command out of sequence, twice in a row, and during a long operation",
    ),

    # ---- Resources ----
    (
        "RESOURCE",
        "high",
        re.compile(r"\b(malloc|calloc|realloc|\w*[Aa]lloc\w*|\w*Acquire\w*|\w*GetBuf\w*)\s*\("),
        "Allocation site — confirm every path, especially error paths, releases it",
        "Repeat the operation (including its failure path) tens of thousands of times and watch for drift",
    ),
    (
        "RESOURCE",
        "medium",
        re.compile(r"\b(free|\w*Free\w*|\w*Release\w*|\w*PutBuf\w*)\s*\("),
        "Release site — used to detect allocation/free asymmetry within a function",
        "See the paired allocation finding",
    ),

    # ---- Concurrency ----
    (
        "CONCURRENCY",
        "high",
        re.compile(r"^\s*(static\s+)?volatile\b.*;", re.MULTILINE),
        "volatile shared variable — volatile prevents caching but provides no atomicity",
        "Saturate queue depth with overlapping commands that reach this path and verify each result individually",
    ),
    (
        "CONCURRENCY",
        "medium",
        re.compile(r"^\s*static\s+(?!const\b)(?!inline\b)\w[\w\s\*]*\b\w+\s*(\[[^\]]*\])?\s*=", re.MULTILINE),
        "Mutable file-scope state — a race candidate if reachable from more than one context",
        "Run the reaching commands concurrently from multiple queues, many iterations",
    ),
    (
        "CONCURRENCY",
        "high",
        re.compile(r"\b(ISR|Isr|_isr|IRQHandler|Interrupt\w*Handler|\w*_IRQ)\b"),
        "Interrupt context — state shared with task context here is a classic race",
        "Generate heavy interrupt load (high queue depth, many completions) while exercising the same path",
    ),
    (
        "CONCURRENCY",
        "low",
        re.compile(r"\b(\w*[Ll]ock\w*|\w*[Mm]utex\w*|\w*[Ss]emaphore\w*|EnterCritical\w*|DisableIrq\w*)\s*\("),
        "Synchronization primitive — check every exit path releases it",
        "Force the error paths inside the critical section, then confirm later commands still complete",
    ),

    # ---- Error handling ----
    (
        "ERROR_PATH",
        "medium",
        re.compile(r"\bgoto\s+\w*(err|fail|cleanup|exit|out)\w*", re.IGNORECASE),
        "Cleanup jump — verify each goto targets the correct label for its acquired resources",
        "Trigger each distinct failure and follow it with a valid command to check leftover state",
    ),
    (
        "ERROR_PATH",
        "medium",
        re.compile(r"\bstatus\s*=\s*\w+.*;\s*$", re.MULTILINE | re.IGNORECASE),
        "Status assignment — check it is not overwritten before return",
        "Verify the exact status code returned, not merely that the command failed",
    ),

    # ---- Integer / arithmetic ----
    (
        "INTEGER",
        "high",
        re.compile(r"\b\w*(len|size|count|offset|addr|lba)\w*\s*=\s*[^;]*[*][^;]*;", re.IGNORECASE),
        "Size/offset computed by multiplication — overflow candidate",
        "Choose field values whose product crosses 2^16 / 2^31 / 2^32 and verify the full transfer length",
    ),
    (
        "INTEGER",
        "medium",
        re.compile(r"\(\s*(u?int(8|16)_t|unsigned\s+(char|short)|BYTE|WORD)\s*\)\s*\w+"),
        "Narrowing cast — a wide host field truncated into a narrow local",
        "Send values above the narrow type's range and check for truncation in the returned data",
    ),
    (
        "INTEGER",
        "medium",
        re.compile(r"\b\w+\s*<<\s*\w+|\b\w+\s*>>\s*\w+"),
        "Variable shift — check the shift amount cannot reach or exceed the type width",
        "Drive the shift-controlling field to its maximum",
    ),

    # ---- Timing / retry ----
    (
        "TIMEOUT_RETRY",
        "high",
        re.compile(r"\bwhile\s*\(\s*(1|true|TRUE)\s*\)"),
        "Unbounded loop — confirm every exit condition is reachable",
        "Provoke the condition the loop waits on to never occur; verify the device gives up in bounded time",
    ),
    (
        "TIMEOUT_RETRY",
        "medium",
        re.compile(r"\b\w*(retry|timeout|tmo|wait|poll|delay)\w*\b", re.IGNORECASE),
        "Retry/timeout logic — check the counter cannot be reset inside the loop and the limit matches the spec",
        "Measure completion time against the spec limit, under contention",
    ),

    # ---- Power loss / atomicity ----
    (
        "POWER_LOSS",
        "high",
        re.compile(r"\b\w*(flush|commit|journal|checkpoint|sync|writeback|write_back|persist)\w*\b", re.IGNORECASE),
        "Durability operation — verify it returns only after data is genuinely persistent",
        "Cut power at randomized delays after the acknowledged flush; all acknowledged data must survive",
    ),
    (
        "POWER_LOSS",
        "high",
        re.compile(r"\b\w*(meta|map|l2p|p2l|table|mapping|ftl)\w*\s*(->|\.|\[)", re.IGNORECASE),
        "Metadata/mapping update — check data and its mapping are updated atomically",
        "Power-cut across the update window, then read back with self-identifying patterns",
    ),

    # ---- Developer breadcrumbs ----
    (
        "BREADCRUMB",
        "high",
        re.compile(r"(TODO|FIXME|XXX|HACK|BUG|WORKAROUND|WA\s*:|TEMP(ORARY)?|TBD|NOT\s+IMPLEMENTED)", re.IGNORECASE),
        "Developer note — the single highest-yield signal of a known-incomplete path",
        "Read the note, work out which host input reaches this line, and test that path first",
    ),

    # ---- Magic numbers ----
    (
        "MAGIC_NUMBER",
        "low",
        re.compile(r"(==|!=|<=|>=|<|>)\s*(0x[0-9A-Fa-f]{2,}|\d{3,})\b"),
        "Hardcoded limit in a comparison — may not match the spec or the configured capability",
        "Compare the constant against the device's advertised capability field and test right at it",
    ),
]

ENTRY_POINT_HINT = re.compile(
    r"\b\w*(Handle|Handler|Process|Dispatch|Execute|Cmd|Command|Opcode|Opc|Recv|Receive|OnHost|Doorbell|Submit)\w*\s*\(",
    re.IGNORECASE,
)

# Matches a function definition header. Firmware code uses both brace styles
# (same line and next line), so the trailing brace is optional here and the
# caller confirms it by looking ahead one line.
FUNC_DEF = re.compile(
    r"^[A-Za-z_][\w\s\*&:<>,]*?\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*(const\s*)?(\{\s*)?$"
)

CONTROL_KEYWORDS = {"if", "for", "while", "switch", "return", "else", "do", "catch", "sizeof"}

BREADCRUMB_ONLY = re.compile(r"(TODO|FIXME|XXX|HACK|BUG|WORKAROUND|TBD)", re.IGNORECASE)


def strip_comments_keep_lines(text):
    """Remove comment bodies but preserve line numbering and comment breadcrumbs.

    Breadcrumb comments are kept because TODO/FIXME markers are among the most
    reliable defect indicators in firmware; everything else in a comment would
    only create false matches against the code patterns.
    """
    out = []
    i = 0
    n = len(text)
    in_line_comment = False
    in_block_comment = False
    in_string = False
    in_char = False
    buf = []
    comment_buf = []

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if c == "\n":
                joined = "".join(comment_buf)
                if BREADCRUMB_ONLY.search(joined):
                    buf.append("//" + joined)
                comment_buf = []
                in_line_comment = False
                buf.append(c)
            else:
                comment_buf.append(c)
            i += 1
            continue

        if in_block_comment:
            if c == "*" and nxt == "/":
                joined = "".join(comment_buf)
                if BREADCRUMB_ONLY.search(joined):
                    buf.append("/*" + joined.replace("\n", " ") + "*/")
                comment_buf = []
                in_block_comment = False
                i += 2
            else:
                if c == "\n":
                    buf.append("\n")
                comment_buf.append(c)
                i += 1
            continue

        if in_string:
            buf.append(c)
            if c == "\\":
                if nxt:
                    buf.append(nxt)
                    i += 2
                    continue
            elif c == '"':
                in_string = False
            i += 1
            continue

        if in_char:
            buf.append(c)
            if c == "\\":
                if nxt:
                    buf.append(nxt)
                    i += 2
                    continue
            elif c == "'":
                in_char = False
            i += 1
            continue

        if c == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if c == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if c == '"':
            in_string = True
            buf.append(c)
            i += 1
            continue
        if c == "'":
            in_char = True
            buf.append(c)
            i += 1
            continue

        buf.append(c)
        i += 1

    out.append("".join(buf))
    return "".join(out)


def map_functions(lines):
    """Rough function-boundary map: line number -> enclosing function name.

    Brace counting is approximate but good enough to attribute a finding to a
    function, which is what reviewers need to locate it quickly.
    """
    owner = {}
    defs = []
    current = None
    depth = 0
    entered = False
    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip()
        if current is None:
            m = FUNC_DEF.match(line)
            if not m or m.group(1) in CONTROL_KEYWORDS:
                continue
            opens_here = "{" in line
            next_line = lines[idx].strip() if idx < len(lines) else ""
            if not opens_here and not next_line.startswith("{"):
                continue
            current = m.group(1)
            depth = line.count("{") - line.count("}")
            entered = opens_here
            owner[idx] = current
            defs.append((idx, current, line.strip()))
            if entered and depth <= 0:
                current = None
        else:
            owner[idx] = current
            depth += line.count("{") - line.count("}")
            if not entered and "{" in line:
                entered = True
            if entered and depth <= 0:
                current = None
    return owner, defs


def find_switch_without_default(lines):
    """Locate switch statements that have no default: label.

    A missing default is where unexpected states and opcodes disappear silently,
    which from the outside looks like a hang or an ignored command.
    """
    findings = []
    for idx, line in enumerate(lines, start=1):
        if not re.search(r"\bswitch\s*\(", line):
            continue
        depth = 0
        started = False
        has_default = False
        end = idx
        for j in range(idx - 1, min(idx + 400, len(lines))):
            depth += lines[j].count("{") - lines[j].count("}")
            if "{" in lines[j]:
                started = True
            if re.search(r"\bdefault\s*:", lines[j]):
                has_default = True
            if started and depth <= 0:
                end = j + 1
                break
        if not has_default:
            findings.append((idx, end, line.strip()))
    return findings


def analyze_file(path, root):
    rel = str(Path(path).relative_to(root)) if root else str(path)
    try:
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], [], {"file": rel, "error": str(exc)}

    cleaned = strip_comments_keep_lines(raw)
    lines = cleaned.split("\n")
    owner, func_defs = map_functions(lines)

    findings = []
    seen = set()

    for category, severity, regex, explanation, hint in PATTERNS:
        for m in regex.finditer(cleaned):
            line_no = cleaned.count("\n", 0, m.start()) + 1
            key = (category, severity, line_no)
            if key in seen:
                continue
            seen.add(key)
            snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else ""
            if not snippet:
                continue
            findings.append(
                {
                    "file": rel,
                    "line": line_no,
                    "function": owner.get(line_no, ""),
                    "category": category,
                    "severity": severity,
                    "snippet": snippet[:220],
                    "why": explanation,
                    "test_hint": hint,
                }
            )

    for start, end, snippet in find_switch_without_default(lines):
        findings.append(
            {
                "file": rel,
                "line": start,
                "function": owner.get(start, ""),
                "category": "STATE_MACHINE",
                "severity": "high",
                "snippet": snippet[:220],
                "why": "switch with no default: — unexpected values fall through silently",
                "test_hint": "Send an undefined/reserved value for the switched field and check for a defined error rather than silence",
            }
        )

    # Allocation / free asymmetry per function
    alloc_re = re.compile(r"\b(malloc|calloc|realloc|\w*[Aa]lloc\w*|\w*Acquire\w*)\s*\(")
    free_re = re.compile(r"\b(free|\w*Free\w*|\w*Release\w*)\s*\(")
    per_func = defaultdict(lambda: {"alloc": 0, "free": 0, "line": 0})
    for idx, line in enumerate(lines, start=1):
        fn = owner.get(idx)
        if not fn:
            continue
        if alloc_re.search(line):
            per_func[fn]["alloc"] += 1
            if not per_func[fn]["line"]:
                per_func[fn]["line"] = idx
        if free_re.search(line):
            per_func[fn]["free"] += 1

    for fn, counts in per_func.items():
        if counts["alloc"] > counts["free"]:
            findings.append(
                {
                    "file": rel,
                    "line": counts["line"],
                    "function": fn,
                    "category": "RESOURCE",
                    "severity": "high",
                    "snippet": f"{fn}(): {counts['alloc']} acquire vs {counts['free']} release",
                    "why": "More acquisitions than releases in this function — the gap is usually on an error path",
                    "test_hint": "Repeat this operation with deliberately failing parameters many thousands of times and watch for drift",
                }
            )

    entry_points = []
    for idx, name, header in func_defs:
        if ENTRY_POINT_HINT.search(header):
            entry_points.append({"file": rel, "line": idx, "symbol": name, "signature": header[:200]})

    stats = {"file": rel, "lines": len(lines), "functions": len(set(owner.values()))}
    return findings, entry_points, stats


def collect_sources(target):
    p = Path(target)
    if p.is_file():
        return [p], p.parent
    files = [f for f in sorted(p.rglob("*")) if f.suffix.lower() in SOURCE_EXT and f.is_file()]
    return files, p


def main():
    ap = argparse.ArgumentParser(description="Scan firmware source for defect-prone sites")
    ap.add_argument("target", help="Source file or directory")
    ap.add_argument("--output", "-o", default="risk_sites.json", help="Output JSON path")
    ap.add_argument("--category", help="Comma-separated categories to keep")
    ap.add_argument("--min-severity", choices=["low", "medium", "high"], default="low")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    files, root = collect_sources(args.target)
    if not files:
        print(f"No C/C++ source files found under {args.target}", file=sys.stderr)
        return 1

    keep = {c.strip().upper() for c in args.category.split(",")} if args.category else None
    min_sev = SEVERITY_ORDER[args.min_severity]

    all_findings, all_entries, all_stats = [], [], []
    for f in files:
        findings, entries, stats = analyze_file(f, root)
        all_findings.extend(findings)
        all_entries.extend(entries)
        all_stats.append(stats)

    filtered = [
        f
        for f in all_findings
        if (keep is None or f["category"] in keep) and SEVERITY_ORDER[f["severity"]] >= min_sev
    ]
    filtered.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["file"], f["line"]))

    by_category = Counter(f["category"] for f in filtered)
    by_severity = Counter(f["severity"] for f in filtered)

    result = {
        "target": str(args.target),
        "files_scanned": len(files),
        "file_stats": all_stats,
        "summary": {
            "total_findings": len(filtered),
            "by_category": dict(by_category),
            "by_severity": dict(by_severity),
        },
        "entry_point_candidates": all_entries,
        "findings": filtered,
        "note": (
            "Pattern-based leads only. No type or call-graph information was used, so "
            "false positives are expected. Read each site in context and discard the "
            "ones already guarded before turning any of them into a test case."
        ),
    }

    Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")

    if not args.quiet:
        print(f"Scanned {len(files)} file(s) → {len(filtered)} risk site(s)")
        print(f"Entry point candidates: {len(all_entries)}")
        for sev in ("high", "medium", "low"):
            if by_severity.get(sev):
                print(f"  {sev:6s}: {by_severity[sev]}")
        print("By category:")
        for cat, cnt in by_category.most_common():
            print(f"  {cat:16s} {cnt}")
        print(f"Written to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
