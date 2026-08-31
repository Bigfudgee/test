---
name: firmware-to-blackbox-test
description: "Derive black-box test cases from firmware source code so latent defects become detectable from outside the device. Use whenever the user has firmware source (.c/.cpp/.h) and wants to find bugs, design test cases, build a test plan, improve coverage, or catch a code-level weakness through host-visible behavior. Trigger on mentions of 'black-box test', 'blackbox', 'BBT', 'test case generation from code', 'defect detection', 'bug hunting from firmware', 'test plan from source', 'validation test design', 'risk-based testing', or questions about which tests would expose a suspicious code path. Works especially well with NVMe/SSD controller firmware, embedded C/C++, RTOS tasks, and ISR-driven code. This is the reverse of testcase-to-design-doc: that skill turns test code into a document, this one turns firmware code into test cases. Do NOT use for unit tests calling internal functions directly (white-box), for debugging one reproducible failure, or for documenting an existing test suite."
---

# Firmware Code → Black-Box Test Case Generator

## Purpose

Read firmware source code, find where defects are likely to hide, and turn each
suspicion into a **test that can be executed and judged from outside the device** —
using only the host interface, power control, and externally readable telemetry.

The hard part is not finding suspicious code. It is answering this question for
every suspicion:

> If this bug is real, **what changes at the boundary** that an outside observer can see?

A test that cannot answer that question is not a black-box test. Keeping this
discipline is what makes the output usable by a validation team that has no
debugger attached to the DUT.

## Core Principle: White-Box Insight, Black-Box Execution

Reading the code is allowed and encouraged — that is the whole advantage here.
But the resulting test must never depend on internal symbols, private functions,
debug hooks, or memory inspection. Every step must be expressible as:

- a command / request sent over the external interface (NVMe command, SCSI CDB, UART, register write via the host-facing path)
- a power or reset event (power cycle, sudden power loss, controller reset, link reset)
- a wait, a repetition, or a workload pattern
- an observation the host can make (status code, returned data, log page, SMART/health attribute, timing, timeout, link state, device presence)

If a suspected defect leaves no trace in any of those, say so explicitly in the
**Observability Gap** section rather than inventing a test that pretends to catch it.
Honest gaps are more valuable than fake coverage — they tell the team where a unit
test or an instrumented build is genuinely required.

## Workflow

### Step 1: Gather the Source and Understand the External Interface

1. Check `/mnt/user-data/uploads/` for source files, or use the path the user gives.
2. Before hunting for bugs, build an **interface map**: what can the outside world
   actually reach? Look for command dispatch tables, opcode switches, handler
   registration, doorbell/queue processing, register decode, and anything that
   consumes host-supplied fields.
3. Record, for each entry point: the input fields it accepts, their legal ranges
   per spec, and the status/response values it can return. This map is the
   vocabulary every later test step must be written in — a defect is only
   reachable if some input path leads to it.

If the code base is large, ask the user which module or feature area to focus on
rather than scanning everything shallowly. Depth beats breadth here.

### Step 2: Scan for Risk Sites

Run the bundled scanner to get a structured starting point:

```bash
python <skill-path>/scripts/scan_firmware_risks.py <file_or_directory> \
    --output /home/claude/risk_sites.json
```

It flags boundary comparisons, unchecked host-supplied fields, unbounded copies,
missing `default:` in state switches, allocation/free asymmetry, retry and timeout
loops, shared mutable state touched from ISR context, integer overflow candidates,
and developer breadcrumbs (`TODO`, `FIXME`, `HACK`, `WA`, `workaround`).

The scanner is a lead generator, not an oracle. It has no type information and no
call graph, so it over-reports. Read every flagged site in its real context and
discard the ones that are already guarded — a test plan full of non-defects
destroys the team's trust in the whole document. Also read the code yourself for
what the scanner structurally cannot see: wrong state transitions, spec
misinterpretation, ordering assumptions between tasks, and cache/metadata
coherency logic.

`references/defect_patterns.md` is the catalog that maps each firmware defect class
to its host-visible symptom and the test technique that provokes it. Read it before
writing test cases — it is the bridge between Step 2 and Step 4, and it covers the
patterns that matter most in storage firmware (power-loss atomicity, resource
leaks, queue races, aging counters, error-path status leakage).

### Step 3: Write Defect Hypotheses

Convert each surviving risk site into a falsifiable hypothesis. A good hypothesis
names the trigger condition, not just the location:

> **DH-007** — `HandleWriteZeroes()` computes the end LBA as `slba + nlb` and compares
> it against namespace size with `<=`. If the host issues a range ending exactly at
> the last LBA, the command is likely rejected with an out-of-range status even
> though the spec permits it. Trigger: `SLBA = NSZE - NLB`, boundary-aligned.

Assign each hypothesis a severity based on the consequence if true: data loss and
data corruption first, then device hang or unrecoverable state, then spec
non-compliance, then performance or cosmetic issues. Validation time is finite,
and this ranking is what decides which tests get run first.

### Step 4: Project Each Hypothesis onto Observable Behavior

For each hypothesis, work out three things before writing any steps:

1. **Trigger** — the exact external input, sequence, or environmental event that
   reaches the suspect code. Include the values, not a description of the values.
2. **Oracle** — how a failure is distinguished from a pass using only external
   observation. Be concrete: which status code, which byte offset differs, which
   log page field, what timing threshold. "Verify it works correctly" is not an oracle.
3. **Amplification** — what makes a rare or invisible bug become visible. Common
   levers: repeat the operation thousands of times (leaks, counter wrap), cut power
   at the vulnerable window and re-read (atomicity), saturate queue depth with
   mixed opcodes (races), run at temperature or after aging (throttling and
   wear-path logic), interleave the target command with resets.

If a hypothesis survives Steps 1–3 but has no workable oracle, move it to the
Observability Gap list with a note on what instrumentation would be needed.

### Step 5: Generate the Test Plan Document

Read `references/test_plan_template.md` for the full structure, then produce a
Markdown document containing:

1. **Overview** — target module, firmware version/commit if known, source files analyzed
2. **External Interface Map** — entry points, input fields, legal ranges, response space
3. **Defect Hypothesis Register** — ID, description, source location, severity, confidence
4. **Black-Box Test Cases** — detailed, each with trigger / steps / oracle / amplification
5. **Traceability Matrix** — hypothesis ↔ test case, both directions, plus source file:line
6. **Execution Priority** — ordered run list with rough cost, so a team can stop at any point and still have run the most valuable tests
7. **Observability Gap Analysis** — defects that are NOT black-box detectable, and what would be needed instead

Save to `/mnt/user-data/outputs/Blackbox_Test_Plan.md` and present it.

### Step 6 (optional): Emit Test Skeletons

If the user has an existing test suite, offer to generate compilable skeletons that
match its conventions — same framework macros, same fixture base class, same
naming and spec-reference style. Read a few existing test files first and imitate
them rather than importing a generic Google Test style; a skeleton that doesn't
match house style just becomes rework. Leave device-specific helper calls as clearly
marked `TODO` rather than inventing API names that may not exist.

## Test Case Quality Bar

Each generated test case should satisfy all of these. They are worth checking
explicitly before saving the document, because a plausible-looking test that
silently passes on buggy firmware is worse than no test at all.

- **Externally executable** — no internal function calls, no memory peeks, no debug builds
- **Deterministic trigger** — concrete values, not "a large value" or "some invalid input"
- **Discriminating oracle** — passes on correct firmware, fails on the hypothesized bug
- **Self-contained preconditions** — states the device condition it needs (format, namespace, power state)
- **Restorable** — notes how to return the DUT to a known state, especially after power-loss or corruption tests
- **Traceable** — cites the source file and line that motivated it

## Prioritization Heuristics

When the analysis yields more candidates than anyone can run:

- Prefer defects on the **data path** over the control path — silent corruption outranks a wrong status code.
- Prefer **irreversible** consequences over recoverable ones — a test that catches a brick or data loss earns its runtime.
- Prefer code that is **new, recently modified, or full of workaround comments** — that is where the defect density actually is.
- Prefer paths reachable with **legal host commands** over ones needing exotic setup; they are more likely to be hit in the field.
- Cluster tests that share expensive setup (format, fill, aging) so the suite stays practical to run.

## Important Notes

- Output language should match the user's request language. If the user writes in
  Korean, write the document in Korean but keep code identifiers, command names,
  status codes, and spec section numbers in their original form.
- Never claim a defect is confirmed. The code was read statically — hypotheses are
  suspicions with a confidence level (High / Medium / Low), and the test is what
  settles them.
- If the firmware references a public specification (NVMe, UFS, SD, eMMC, SATA),
  anchor expected behavior to spec sections so a failure can be argued as
  non-compliance rather than opinion.
- When the user also has the design/spec document, cross-check: places where the
  code and the document disagree are among the highest-yield hypotheses available.
- This skill pairs naturally with `testcase-to-design-doc`. Generate tests here,
  and once they are implemented, that skill can document the resulting suite.
