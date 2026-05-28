"""Typer-powered CLI: `pqc-v2x-bench run|report|compare|list`."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer

from . import __version__
from . import algorithms as alg_mod
from . import bench as bench_mod
from . import report as report_mod


app = typer.Typer(
    name="pqc-v2x-bench",
    help="Reproducible benchmark suite for PQC primitives in V2X PKI contexts.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_cb(value: bool) -> None:
    if value:
        typer.echo(f"pqc-v2x-bench {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_cb, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Tool entrypoint — see subcommands."""


@app.command("list")
def cmd_list() -> None:
    """List registered algorithms and exit."""
    rows = [(a.name, a.kind, a.family, a.nist_level) for a in alg_mod.list_algorithms()]
    from tabulate import tabulate
    typer.echo(tabulate(rows, headers=["Algorithm", "Kind", "Family", "Level"], tablefmt="github"))


def _split_csv(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [p for p in (s.strip() for s in value.split(",")) if p]


@app.command("run")
def cmd_run(
    iters: int = typer.Option(100, "--iters", "-n", help="Measurement iterations per algorithm."),
    warmup: int = typer.Option(5, "--warmup", "-w", help="Warmup iterations discarded from stats."),
    msg_size: int = typer.Option(256, "--msg-size", "-m",
                                 help="Payload size in bytes (CAM payload proxy)."),
    algorithms: Optional[str] = typer.Option(
        None, "--algorithms", "-a",
        help="Comma-separated glob filter, e.g. 'ml-dsa-*,falcon-*'. Default: all.",
    ),
    output: str = typer.Option(
        "json", "--output", "-o", help="Output format: json|markdown|csv.",
    ),
    out_file: Optional[Path] = typer.Option(
        None, "--out", help="Write to this file instead of stdout. Default: results.{ext}.",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q",
                               help="Suppress per-algorithm progress messages."),
) -> None:
    """Measure registered algorithms and emit a report."""
    fmt = output.lower()
    if fmt not in {"json", "markdown", "md", "csv"}:
        raise typer.BadParameter(f"unknown --output {output!r}; expected json|markdown|csv")
    if iters <= 0:
        raise typer.BadParameter("--iters must be >= 1")
    if msg_size <= 0:
        raise typer.BadParameter("--msg-size must be >= 1")

    selected = alg_mod.select(_split_csv(algorithms))
    if not selected:
        typer.echo(f"No algorithms matched filter {algorithms!r}", err=True)
        raise typer.Exit(code=2)

    if not quiet:
        typer.echo(
            f"# pqc-v2x-bench {__version__} | iters={iters} warmup={warmup} "
            f"msg_size={msg_size}B algorithms={len(selected)}",
            err=True,
        )

    def _progress(name: str) -> None:
        if not quiet:
            typer.echo(f"  measuring {name}...", err=True)

    report = bench_mod.bench_many(
        selected, iters=iters, warmup=warmup, msg_size=msg_size, progress=_progress,
    )
    text = report_mod.format_report(report, "markdown" if fmt == "md" else fmt)

    if out_file is None:
        # Default file targets when format implies a file artifact for run.
        ext = {"json": "json", "markdown": "md", "md": "md", "csv": "csv"}[fmt]
        out_file = Path(f"results.{ext}")
    out_file.write_text(text, encoding="utf-8")
    if not quiet:
        typer.echo(f"wrote {out_file} ({len(text):,} bytes)", err=True)
    # Always echo to stdout too so the CLI is pipeable.
    sys.stdout.write(text)


@app.command("report")
def cmd_report(
    input_file: Path = typer.Argument(..., exists=True, readable=True,
                                       help="Path to results JSON from `run`."),
    output: str = typer.Option("markdown", "--output", "-o",
                               help="Output format: json|markdown|csv."),
    out_file: Optional[Path] = typer.Option(None, "--out", help="Write to this file."),
) -> None:
    """Render an existing results file as markdown/csv/json."""
    fmt = output.lower()
    if fmt not in {"json", "markdown", "md", "csv"}:
        raise typer.BadParameter(f"unknown --output {output!r}")
    report = bench_mod.load_report(str(input_file))
    text = report_mod.format_report(report, "markdown" if fmt == "md" else fmt)
    if out_file is not None:
        out_file.write_text(text, encoding="utf-8")
        typer.echo(f"wrote {out_file}", err=True)
    sys.stdout.write(text)


@app.command("compare")
def cmd_compare(
    baseline: Path = typer.Argument(..., exists=True, readable=True,
                                     help="Baseline results JSON."),
    current: Path = typer.Argument(..., exists=True, readable=True,
                                    help="Current results JSON."),
    threshold: float = typer.Option(50.0, "--threshold", "-t",
                                     help="Percent threshold to flag regressions (default 50)."),
    output: str = typer.Option("markdown", "--output", "-o",
                               help="Output format: markdown|json."),
    fail_on_flag: bool = typer.Option(
        False, "--fail-on-flag",
        help="Exit non-zero when any algorithm breaches the threshold (CI guard).",
    ),
) -> None:
    """Diff two reports and report deltas. Use --fail-on-flag in CI."""
    base = bench_mod.load_report(str(baseline))
    curr = bench_mod.load_report(str(current))
    diff = report_mod.compare(base, curr, threshold_pct=threshold)
    fmt = output.lower()
    if fmt in {"markdown", "md"}:
        sys.stdout.write(report_mod.compare_to_markdown(diff))
    elif fmt == "json":
        import json
        sys.stdout.write(json.dumps(diff, indent=2) + "\n")
    else:
        raise typer.BadParameter(f"unknown --output {output!r}; expected markdown|json")
    if fail_on_flag and diff["flagged"]:
        names = ", ".join(r["algorithm"] for r in diff["flagged"])
        typer.echo(f"FAIL: {len(diff['flagged'])} algorithm(s) breached threshold: {names}",
                   err=True)
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
