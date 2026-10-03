#!/usr/bin/env python3
"""Compare identical session-throughput harnesses on one remote CI runner."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import statistics
import subprocess
import tarfile
import tempfile


def run(args, *, cwd=None, output=None):
    process = subprocess.Popen(args, cwd=cwd, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
    timed_out = False
    try:
        text, _ = process.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        timed_out = True
        # Go's testing timeout stops before benchmarks start. Bound the actual
        # child process and preserve its goroutine dump if a sample stalls.
        process.send_signal(signal.SIGQUIT)
        try:
            text, _ = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            text, _ = process.communicate()
    if output:
        output.write_text(text, encoding="utf-8")
    if timed_out or process.returncode:
        print(text, flush=True)
        raise RuntimeError(f"command failed ({process.returncode}): {args}")
    return text


def samples(text):
    rows = {}
    for line in text.splitlines():
        if not line.startswith("BenchmarkTunnelBulkTransfer/"):
            continue
        fields = line.split()
        if len(fields) < 4 or not fields[1].isdigit():
            continue
        metrics = {fields[i + 1]: float(fields[i])
                   for i in range(2, len(fields) - 1, 2)}
        for key in ("MB/s", "ns/op", "delivery-%", "carrier-drops", "undrained-records"):
            if key not in metrics:
                raise RuntimeError(f"missing metric {key}: {line}")
        if metrics["delivery-%"] != 100 or metrics["carrier-drops"] or metrics["undrained-records"]:
            raise RuntimeError(f"incomplete delivery or drain: {line}")
        rows[fields[0]] = {"iterations": int(fields[1]), **metrics}
    if len(rows) != 12:
        raise RuntimeError(f"expected 12 workload cells, got {len(rows)}")
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--benchtime", default="700ms")
    args = parser.parse_args()
    if not os.environ.get("GITHUB_ACTIONS") or os.environ.get("ICMP_CI_THROUGHPUT") != "1":
        raise RuntimeError("throughput acceptance measurements must run in GitHub Actions")
    if not re.fullmatch(r"[0-9a-f]{40}", args.baseline):
        raise RuntimeError("baseline must be a complete immutable commit SHA")
    root = Path.cwd()
    output = root / "throughput-results"
    output.mkdir(exist_ok=True)
    candidate = run(["git", "rev-parse", "HEAD"]).strip()
    metadata = {
        "baseline": args.baseline, "candidate": candidate,
        "go": run(["go", "version"]).strip(),
        "cpu": run(["lscpu"]), "kernel": run(["uname", "-a"]).strip(),
        "gomaxprocs": os.environ["GOMAXPROCS"], "rounds": args.rounds,
        "benchtime": args.benchtime, "carrier": "memory", "backend": "net.Pipe",
        "harness_sha256": hashlib.sha256((root / "tunnel/throughput_test.go").read_bytes()).hexdigest(),
        "measurement": "established-session verified payload; setup and final ACK drain excluded",
    }
    (output / "environment.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    collected = {"baseline": [], "candidate": []}
    binaries = {version: output / f"{version}.test" for version in collected}
    with tempfile.TemporaryDirectory(prefix="icmp-throughput-") as temp:
        baseline = Path(temp) / "baseline"
        baseline.mkdir()
        archive = Path(temp) / "baseline.tar"
        with archive.open("wb") as stream:
            subprocess.run(["git", "archive", args.baseline], stdout=stream, check=True)
        with tarfile.open(archive) as source:
            source.extractall(baseline, filter="data")
        # Both revisions compile the exact same new workload code.
        (baseline / "tunnel/throughput_test.go").write_bytes((root / "tunnel/throughput_test.go").read_bytes())
        for version, directory in (("baseline", baseline), ("candidate", root)):
            run(["go", "test", "-c", "-o", str(binaries[version]), "./tunnel"], cwd=directory)
        for round_number in range(args.rounds):
            order = ("baseline", "candidate") if round_number % 2 == 0 else ("candidate", "baseline")
            for version in order:
                text = run([str(binaries[version]), "-test.run=^$",
                            "-test.bench=^BenchmarkTunnelBulkTransfer$",
                            f"-test.benchtime={args.benchtime}", "-test.cpu=2", "-test.timeout=5m"],
                           output=output / f"{version}-{round_number + 1}.txt")
                collected[version].append(samples(text))
                print(f"round {round_number + 1}: {version} delivered and drained all 12 cells", flush=True)
        # Profile separately, after paired timing, so sampling overhead never
        # contaminates either member of the throughput comparison.
        for direction in ("upload", "download"):
            profile = output / f"baseline-{direction}.cpu"
            run([str(binaries["baseline"]), "-test.run=^$",
                 f"-test.bench=^BenchmarkTunnelBulkTransfer$/{direction}/MSS1400/sessions1$",
                 "-test.benchtime=2s", "-test.cpu=2", f"-test.cpuprofile={profile}"],
                output=output / f"profile-{direction}.txt")
            run(["go", "tool", "pprof", "-top", str(binaries["baseline"]), str(profile)],
                output=output / f"cpu-top-{direction}.txt")
            run(["go", "tool", "pprof", "-top", "-cum", str(binaries["baseline"]), str(profile)],
                output=output / f"cpu-cumulative-{direction}.txt")
    cells = []
    regression = False
    for name in sorted(collected["baseline"][0]):
        before = [sample[name]["MB/s"] for sample in collected["baseline"]]
        after = [sample[name]["MB/s"] for sample in collected["candidate"]]
        before_median, after_median = statistics.median(before), statistics.median(after)
        delta = (after_median / before_median - 1) * 100
        regression |= delta < -10
        cells.append({"workload": name, "baseline_MBps": before_median,
                      "candidate_MBps": after_median, "change_percent": delta,
                      "baseline_samples": before, "candidate_samples": after,
                      "delivery_percent": 100, "carrier_drops": 0, "undrained_records": 0})
    comparison = {"environment": metadata, "cells": cells,
                  "raw_samples": collected, "regression_guard_percent": -10,
                  "guard_passed": not regression}
    (output / "comparison.json").write_text(json.dumps(comparison, indent=2), encoding="utf-8")
    lines = ["| Workload | Baseline MB/s | Candidate MB/s | Change |",
             "| --- | ---: | ---: | ---: |"]
    for cell in cells:
        lines.append(f"| {cell['workload']} | {cell['baseline_MBps']:.2f} | "
                     f"{cell['candidate_MBps']:.2f} | {cell['change_percent']:+.2f}% |")
    lines += ["", "All samples: 100% payload delivery, zero carrier drops and zero undrained records.",
              "Memory carrier/net.Pipe evidence does not establish real ICMP or WAN throughput."]
    summary = "\n".join(lines) + "\n"
    (output / "summary.md").write_text(summary, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write(summary)
    print(summary, flush=True)
    if regression:
        raise RuntimeError("a workload median regressed by more than the fixed 10% guard")


if __name__ == "__main__":
    main()
