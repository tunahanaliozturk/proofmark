# 0010: Command-line arguments are parsed by hand, without lexopt

Status: accepted, 2026-11-25

## Context

The design planned `lexopt` 0.3.2 (MIT, no dependencies) to parse arguments, with the help text written by hand. M2 is the first milestone with commands: `run`, `list`, `explain`, `cleanup` and `fake`, each with a handful of `--name value` options and two flags.

The project rule is no new dependency unless the milestone cannot reasonably be done without it.

## Decision

Parse by hand in `src/cli.rs`. Arguments are converted to UTF-8 strings first (anything else is a usage error), then read as `--name value`, `--name=value` or a plain word. Each command matches the option names it knows; anything else is a usage error with exit code 2.

## Consequences

- One dependency fewer, and about sixty lines of parsing that the exit-code tests drive through the real binary.
- Non-UTF-8 arguments are refused. Paths in this tool are the ledger, reports and a CA file, which a user names; a path that is not UTF-8 is unlikely and gets a clear error rather than a misread.
- Short options and combined flags are not supported. If the command line grows enough that this matters, `lexopt` is still the choice, in its own commit with the reason.
