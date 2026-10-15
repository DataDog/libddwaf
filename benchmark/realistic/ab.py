# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""A/B performance comparison of two libddwaf revisions on a benchmark host.

Both sides are measured with the *same* benchmark program (the harness in the
directory of this script: src/, rulesets/), linked against libddwaf.a built
from each revision. Only the library differs.

Steps:
  1. export each revision (git archive, or the working tree) to the host;
  2. build libddwaf_static for each side and link the harness against it
     (shared lock: concurrent builds are fine, but never during a measurement);
  3. behaviour check: run both binaries with --dump-results and compare the
     canonical eval outputs (loud failure on any difference);
  4. measure: R rounds, sides interleaved with alternating order, under an
     exclusive lock so measurements of concurrent invocations never overlap;
     scenarios with disturbed or noisy rounds get extra paired rounds;
  5. statistics: per scenario paired log-ratios cur/ref across rounds, median,
     robust 95% interval, Mann-Whitney U p-value; geomeans per group/overall.

Examples:
  uv run benchmark/realistic/ab.py                         # merge-base(master) vs HEAD
  uv run benchmark/realistic/ab.py --ref HEAD --cur WORKTREE --quick
  uv run benchmark/realistic/ab.py --ref HEAD --cur HEAD   # A/A noise check
  uv run benchmark/realistic/ab.py --ref abc123 --cur def456 --filter '^rc/' --threads 1,16
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import math
import os
import re
import shlex
import subprocess
import sys
import tarfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REMOTE_ROOT = "ddwaf-ab"  # relative to the remote home directory


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

class Host:
    def __init__(self, name: str | None):
        self.name = name  # None: run locally (when already on the benchmark host)

    def run(self, script: str, *, input: bytes | None = None, capture: bool = True,
            check: bool = True) -> subprocess.CompletedProcess:
        if self.name:
            cmd = ["ssh", "-o", "ServerAliveInterval=30", self.name, "bash -c " + shlex.quote(script)]
        else:
            cmd = ["bash", "-c", script]
        res = subprocess.run(cmd, input=input, capture_output=capture)
        if check and res.returncode != 0:
            sys.stderr.write(f"remote command failed ({res.returncode}):\n{script}\n")
            if capture:
                sys.stderr.write(res.stdout.decode(errors="replace")[-4000:])
                sys.stderr.write(res.stderr.decode(errors="replace")[-4000:])
            raise SystemExit(1)
        return res

    def stream(self, script: str) -> int:
        """Run with output streamed to our stdout."""
        if self.name:
            cmd = ["ssh", "-o", "ServerAliveInterval=30", self.name, "bash -c " + shlex.quote(script)]
        else:
            cmd = ["bash", "-c", script]
        return subprocess.call(cmd)

    def read(self, path: str) -> bytes:
        return self.run(f"cat {path}").stdout


def git(repo: Path, *args: str, binary: bool = False):
    res = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True)
    return res.stdout if binary else res.stdout.decode().strip()


def log(msg: str) -> None:
    print(f"[ab {dt.datetime.now():%H:%M:%S}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def tar_of_files(root: Path, files: list[str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for f in sorted(files):
            p = root / f
            if not p.is_file():
                continue
            info = tarfile.TarInfo(f)
            data = p.read_bytes()
            info.size = len(data)
            info.mode = 0o755 if os.access(p, os.X_OK) else 0o644
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class Revision:
    def __init__(self, repo: Path, spec: str):
        self.spec = spec
        if spec in ("WORKTREE", "."):
            files = git(repo, "ls-files", "-co", "--exclude-standard", "-z").split("\0")
            files = [f for f in files if f and "/rulesets/asm_org2/" not in f]
            self.tar = tar_of_files(repo, files)
            self.id = "wt-" + hashlib.sha256(self.tar).hexdigest()[:12]
            self.sha = git(repo, "rev-parse", "HEAD") + "+worktree"
        else:
            self.sha = git(repo, "rev-parse", "--verify", spec + "^{commit}")
            self.id = self.sha[:12]
            self.tar = None
            self.repo = repo

    def archive(self) -> bytes:
        if self.tar is not None:
            return self.tar
        return git(self.repo, "archive", "--format=tar", self.sha, binary=True)

    def label(self) -> str:
        return f"{self.spec} ({self.id})"


def harness_tar() -> tuple[bytes, str]:
    files = ["CMakeLists.txt"]
    for sub in ("src", "rulesets"):
        for p in (HERE / sub).rglob("*"):
            rel = p.relative_to(HERE).as_posix()
            if p.is_file() and "/asm_org2/" not in "/" + rel and not p.name.startswith("."):
                files.append(rel)
    data = tar_of_files(HERE, files)
    return data, "h-" + hashlib.sha256(data).hexdigest()[:12]


def ensure_generated_data() -> None:
    big = HERE / "rulesets" / "data" / "blocked_ips_100000.json"
    if not big.exists():
        log("generating synthetic blocklists (gen_data.py)")
        subprocess.run(["uv", "run", str(HERE / "gen_data.py")], check=True, capture_output=True)


# ---------------------------------------------------------------------------
# Remote build
# ---------------------------------------------------------------------------

def upload(host: Host, remote_dir: str, data: bytes) -> None:
    script = (f"set -e; cd ~; mkdir -p {REMOTE_ROOT}; cd {REMOTE_ROOT}; "
              f"if [ -f {remote_dir}/.complete ]; then cat > /dev/null; exit 0; fi; "
              f"rm -rf {remote_dir}.tmp.$$; mkdir -p {remote_dir}.tmp.$$; "
              f"tar -x -C {remote_dir}.tmp.$$; touch {remote_dir}.tmp.$$/.complete; "
              f"mkdir -p $(dirname {remote_dir}); "
              f"if [ -e {remote_dir} ]; then rm -rf {remote_dir}.tmp.$$; else mv {remote_dir}.tmp.$$ {remote_dir}; fi")
    host.run(script, input=data)


def build_side(host: Host, rev: Revision, harness_id: str, cfg: dict) -> str:
    """Builds lib + bench for a revision; returns the remote bench binary path."""
    cfg_key = hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()[:8]
    lib_dir = f"lib/{rev.id}-{cfg_key}"
    bench_dir = f"bench/{rev.id}-{cfg_key}-{harness_id}"
    cc, cxx = cfg["cc"], cfg["cxx"]
    extra = " ".join(shlex.quote(x) for x in cfg["cmake_args"])
    script = f"""
set -e
cd ~/{REMOTE_ROOT}
mkdir -p lib bench locks
exec 9>locks/measure.lock
flock -s 9   # never build while another invocation is measuring
exec 8>locks/build-{rev.id}-{cfg_key}.lock
flock 8
LAUNCHER=""
if command -v ccache > /dev/null; then LAUNCHER="-DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache"; fi
if [ ! -f {lib_dir}/.complete ]; then
  rm -rf {lib_dir}
  cmake -S src/{rev.id} -B {lib_dir} -G Ninja -DCMAKE_BUILD_TYPE={cfg['build_type']} \\
    -DLIBDDWAF_BUILD_SHARED=OFF -DLIBDDWAF_BUILD_STATIC=ON -DLIBDDWAF_TESTING=OFF \\
    -DCMAKE_C_COMPILER={cc} -DCMAKE_CXX_COMPILER={cxx} -DGIT_COMMIT={rev.id} $LAUNCHER {extra} > {lib_dir}.cmake.log 2>&1 \\
    || {{ tail -50 {lib_dir}.cmake.log; exit 1; }}
  nice -n 10 ninja -C {lib_dir} -j{cfg['jobs']} libddwaf_static > {lib_dir}.build.log 2>&1 \\
    || {{ tail -80 {lib_dir}.build.log; exit 1; }}
  touch {lib_dir}/.complete
fi
if [ ! -f {bench_dir}/.complete ]; then
  rm -rf {bench_dir}
  cmake -S harness/{harness_id} -B {bench_dir} -G Ninja -DCMAKE_BUILD_TYPE={cfg['build_type']} \\
    -DCMAKE_CXX_COMPILER={cxx} -DDDWAF_LIB=$HOME/{REMOTE_ROOT}/{lib_dir}/libddwaf.a \\
    -DDDWAF_INCLUDE_DIR=$HOME/{REMOTE_ROOT}/src/{rev.id}/include $LAUNCHER > {bench_dir}.cmake.log 2>&1 \\
    || {{ tail -50 {bench_dir}.cmake.log; exit 1; }}
  nice -n 10 ninja -C {bench_dir} -j{cfg['jobs']} > {bench_dir}.build.log 2>&1 \\
    || {{ tail -80 {bench_dir}.build.log; exit 1; }}
  touch {bench_dir}/.complete
fi
echo $HOME/{REMOTE_ROOT}/{bench_dir}/ddwaf_realistic_bench
"""
    t0 = time.time()
    res = host.run(script)
    path = res.stdout.decode().strip().splitlines()[-1]
    log(f"built {rev.label()} in {time.time() - t0:.0f}s -> {path}")
    return path


# ---------------------------------------------------------------------------
# Behaviour check
# ---------------------------------------------------------------------------

def relaxed(line: str):
    """Order-insensitive form of a canonical output line (arrays sorted)."""
    s = re.sub(r"(\d)u(?=[,\]}])", r"\1", line)
    s = s.replace("<masked>", '"<masked>"').replace("<invalid>", '"<invalid>"').replace(
        "<unknown>", '"<unknown>"')
    try:
        obj = json.loads(s)
    except json.JSONDecodeError:
        return "".join(sorted(line))

    def norm(o):
        if isinstance(o, list):
            return sorted((norm(x) for x in o), key=lambda x: json.dumps(x, sort_keys=True))
        if isinstance(o, dict):
            return {k: norm(v) for k, v in o.items()}
        return o

    return json.dumps(norm(obj), sort_keys=True)


def compare_digests(host: Host, bins: dict[str, str], data_dir: str, run_dir: str,
                    local_dir: Path, filt: list[str]) -> bool:
    for side, b in bins.items():
        host.run(f"cd ~/{REMOTE_ROOT} && exec 9>locks/measure.lock && flock -s 9 && "
                 f"{b} --data-dir {data_dir} --dump-results {run_dir}/dump-{side}.txt {' '.join(filt)} > /dev/null")
    sums = host.run(f"cd {run_dir} && sha256sum dump-ref.txt dump-cur.txt").stdout.decode().split("\n")
    a, b = (s.split()[0] for s in sums[:2])
    if a == b:
        n = host.run(f"wc -l < {run_dir}/dump-ref.txt").stdout.decode().strip()
        log(f"behaviour check: IDENTICAL eval outputs ({n} evals/diagnostics)")
        return True
    ref = host.read(f"{run_dir}/dump-ref.txt").decode(errors="replace").splitlines()
    cur = host.read(f"{run_dir}/dump-cur.txt").decode(errors="replace").splitlines()
    (local_dir / "dump-ref.txt").write_text("\n".join(ref) + "\n")
    (local_dir / "dump-cur.txt").write_text("\n".join(cur) + "\n")

    def keyed(lines):
        out = {}
        for ln in lines:
            parts = ln.split("\t")
            key = "\t".join(parts[:3]) if len(parts) >= 4 else ln
            out[key] = ln
        return out

    kr, kc = keyed(ref), keyed(cur)
    diffs = [k for k in kr.keys() | kc.keys() if kr.get(k) != kc.get(k)]
    order_only = [k for k in diffs if k in kr and k in kc and relaxed(kr[k]) == relaxed(kc[k])]
    bar = "!" * 78
    print(f"\n{bar}\n!! BEHAVIOUR CHANGE: {len(diffs)} of {len(kr)} eval outputs differ "
          f"({len(order_only)} differ only in array order)\n!! dumps: {local_dir}/dump-ref.txt "
          f"{local_dir}/dump-cur.txt\n{bar}")
    for k in sorted(diffs)[:8]:
        print(f"--- {k}")
        print(f"  ref: {kr.get(k, '<missing>')[:600]}")
        print(f"  cur: {kc.get(k, '<missing>')[:600]}")
    print(bar + "\n")
    return False


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------

def measure(host: Host, bins: dict[str, str], bench_args: list[str], filt: str | None,
            first: int, count: int, run_dir: str, local_dir: Path, runs: dict, cooldown: float) -> int:
    """Runs rounds [first, first+count) under the exclusive measurement lock."""
    args = list(bench_args)
    if filt:
        args += ["--filter", shlex.quote(filt)]
    lines = [
        "set -e", f"cd ~/{REMOTE_ROOT}", "exec 9>locks/measure.lock",
        "if ! flock -n -x 9; then echo '[ab] waiting for another measurement to finish...'; flock -x 9; fi",
        "echo \"[ab] host $(hostname), load $(cut -d' ' -f1-3 /proc/loadavg), governor "
        "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null), boost "
        "$(cat /sys/devices/system/cpu/cpufreq/boost 2>/dev/null)\"",
        "L=$(cut -d' ' -f1 /proc/loadavg); if awk \"BEGIN{exit !($L > 1.5)}\"; then "
        "echo \"[ab] WARNING: load average $L: other processes may disturb the measurement\"; fi",
    ]
    for r in range(first, first + count):
        order = ["ref", "cur"] if r % 2 == 0 else ["cur", "ref"]
        for side in order:
            lines.append(f"echo '[ab] round {r + 1}: {side}'")
            lines.append(f"{bins[side]} {' '.join(args)} --json {run_dir}/r{r}-{side}.json "
                         f"2>&1 | grep -v '^\\[diag\\]'")
            lines.append(f"sleep {cooldown}")
    rc = host.stream("\n".join(lines))
    if rc != 0:
        log(f"measurement failed (exit {rc})")
        return rc
    for r in range(first, first + count):
        for side in ("ref", "cur"):
            raw = host.read(f"{run_dir}/r{r}-{side}.json")
            (local_dir / f"r{r}-{side}.json").write_bytes(raw)
            runs[side].append(json.loads(raw))
    return 0


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306,
        9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
        16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086, 25: 2.060, 30: 2.042}


def t975(df: int) -> float:
    if df in T975:
        return T975[df]
    if df > 30:
        return 1.96 + 2.4 / df
    keys = sorted(T975)
    return T975[min(k for k in keys if k >= df)]


def mann_whitney_p(x: list[float], y: list[float]) -> float:
    """Exact two-sided Mann-Whitney U p-value (no ties assumed; ties get half)."""
    n, m = len(x), len(y)
    if n == 0 or m == 0:
        return 1.0
    u = sum((1.0 if a > b else 0.5 if a == b else 0.0) for a in x for b in y)
    if n * m > 400:
        mu, sd = n * m / 2, math.sqrt(n * m * (n + m + 1) / 12)
        z = abs(u - mu) / sd
        return math.erfc(z / math.sqrt(2))
    # counts[k] = number of arrangements with U == k (integer U)
    counts = [[[0] * (n * m + 1) for _ in range(m + 1)] for _ in range(n + 1)]
    for i in range(n + 1):
        for j in range(m + 1):
            if i == 0 or j == 0:
                counts[i][j][0] = 1
                continue
            for k in range(i * j + 1):
                c = counts[i - 1][j][k - j] if k - j >= 0 else 0
                c += counts[i][j - 1][k]
                counts[i][j][k] = c
    total = math.comb(n + m, n)
    dist = counts[n][m]
    lo = min(u, n * m - u)
    tail = sum(dist[k] for k in range(len(dist)) if k <= lo + 1e-9)
    return min(1.0, 2 * tail / total)


def median(v: list[float]) -> float:
    s = sorted(v)
    k = len(s)
    return s[k // 2] if k % 2 else (s[k // 2 - 1] + s[k // 2]) / 2


def analyse(runs: dict[str, list[dict]], min_effect: float) -> dict:
    """runs[side] = list (rounds) of bench JSON documents (paired by index).

    Per scenario and round the value of a side is the median of its
    repetitions. The estimate is the median of the paired log-ratios
    ln(cur/ref) over rounds, which tolerates a minority of rounds disturbed by
    other processes on the host (they show up as a 10-20% drop of one side).
    The spread is the larger of
      * 1.4826 * MAD of the paired log-ratios, and
      * sqrt(2) * the within-run spread (repetition MAD) of a single run's median,
    so that a few lucky rounds cannot make the noise look like zero. The
    interval is +- t(0.975, n-1) * 1.2533 * sigma / sqrt(n) around the median.
    """
    names = []
    for doc in runs["ref"]:
        for r in doc["results"]:
            if r["name"] not in names:
                names.append(r["name"])
    rows = []
    for name in names:
        ref_vals, cur_vals, mads, reps = [], [], [], 1
        for dref, dcur in zip(runs["ref"], runs["cur"]):
            a = next((r for r in dref["results"] if r["name"] == name), None)
            b = next((r for r in dcur["results"] if r["name"] == name), None)
            if a and b and a["median"] > 0 and b["median"] > 0:
                ref_vals.append(a["median"])
                cur_vals.append(b["median"])
                mads += [a["mad_pct"], b["mad_pct"]]
                reps = max(reps, len(a["reps"]))
        if not ref_vals:
            continue
        logs = [math.log(c / r) for r, c in zip(ref_vals, cur_vals)]
        n = len(logs)
        est = median(logs)
        mad_sigma = 1.4826 * median([abs(x - est) for x in logs])
        within = math.sqrt(2) * 1.2533 / math.sqrt(reps) * 1.4826 * median(mads) / 100
        sigma = max(mad_sigma, within)
        half = t975(n - 1) * 1.2533 * sigma / math.sqrt(n) if n > 1 else float("inf")
        lo, hi = math.exp(est - half), math.exp(est + half)
        speedup = math.exp(est)
        p = mann_whitney_p(cur_vals, ref_vals)
        if lo > 1.0 and speedup - 1 >= min_effect:
            verdict = "FASTER"
        elif hi < 1.0 and 1 - speedup >= min_effect:
            verdict = "SLOWER"
        else:
            verdict = "~"
        disturbed = sum(1 for side in (ref_vals, cur_vals) for v in side if v < 0.95 * median(side))
        unit = next(r["unit"] for r in runs["ref"][0]["results"] if r["name"] == name)
        rows.append({
            "name": name, "group": name.split("/")[0], "threads": name.rsplit("/t", 1)[-1],
            "unit": unit, "ref": median(ref_vals), "cur": median(cur_vals),
            "speedup": speedup, "ci_lo": lo, "ci_hi": hi, "ci_half_pct": 100 * (hi - lo) / 2,
            "min_ratio": min(math.exp(x) for x in logs), "max_ratio": max(math.exp(x) for x in logs),
            "p_mw": p, "verdict": verdict, "rounds": n, "disturbed_runs": disturbed,
            "ref_rounds": ref_vals, "cur_rounds": cur_vals,
        })

    def geo(sel):
        v = [r["speedup"] for r in sel]
        return math.exp(sum(math.log(x) for x in v) / len(v)) if v else None

    geomeans = {}
    for g in sorted({r["group"] for r in rows}):
        geomeans[g] = geo([r for r in rows if r["group"] == g])
    for t in sorted({r["threads"] for r in rows if r["unit"] == "req"}, key=int):
        geomeans[f"requests/t{t}"] = geo([r for r in rows if r["unit"] == "req" and r["threads"] == t])
    geomeans["ALL requests"] = geo([r for r in rows if r["unit"] == "req"])
    geomeans["ALL builds"] = geo([r for r in rows if r["unit"] == "op"])
    geomeans["ALL"] = geo(rows)
    return {"rows": rows, "geomeans": geomeans}


def fmt_rate(v: float) -> str:
    if v >= 1e6:
        return f"{v / 1e6:.3f}M"
    if v >= 1e3:
        return f"{v / 1e3:.2f}k"
    return f"{v:.2f}"


def print_table(res: dict) -> None:
    hdr = (f"{'scenario':<30} {'ref':>10} {'cur':>10} {'speedup':>8} {'±95%':>7} "
           f"{'[min-max]':>15} {'p(MW)':>6} {'n':>3}  verdict")
    print(hdr)
    print("-" * len(hdr))
    for r in res["rows"]:
        print(f"{r['name']:<30} {fmt_rate(r['ref']):>10} {fmt_rate(r['cur']):>10} "
              f"{r['speedup']:>8.4f} {r['ci_half_pct']:>6.2f}% "
              f"[{r['min_ratio']:.3f}-{r['max_ratio']:.3f}] {r['p_mw']:>6.3f} {r['rounds']:>3}  "
              f"{r['verdict']}{'  (disturbed runs: %d)' % r['disturbed_runs'] if r['disturbed_runs'] else ''}")
    print()
    for k, v in res["geomeans"].items():
        if v is not None:
            print(f"geomean {k:<22} {v:.4f} ({(v - 1) * 100:+.2f}%)")
    f = sum(r["verdict"] == "FASTER" for r in res["rows"])
    s = sum(r["verdict"] == "SLOWER" for r in res["rows"])
    print(f"\n{f} faster, {s} slower, {len(res['rows']) - f - s} within noise")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=None, help="git repository (default: toplevel of cwd)")
    ap.add_argument("--ref", default=None, help="baseline revision (default: merge-base of HEAD and master)")
    ap.add_argument("--cur", default="HEAD", help="candidate revision, or WORKTREE for uncommitted changes")
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--extra-rounds", type=int, default=4,
                    help="max additional rounds for scenarios that were disturbed or too noisy")
    ap.add_argument("--target-ci", type=float, default=1.5,
                    help="re-measure scenarios whose 95%% half-width (%%) exceeds this")
    ap.add_argument("--threads", default="1,4,16")
    ap.add_argument("--filter", default=None, help="regex on scenario/tN names")
    ap.add_argument("--quick", action="store_true", help="representative subset, shorter reps")
    ap.add_argument("--cpus", default="1-15,0", help="pinning order passed to the benchmark")
    ap.add_argument("--remote", default="ubuntu-vm", help="ssh host ('' = run locally)")
    ap.add_argument("--compiler", choices=["clang", "gcc"], default="clang")
    ap.add_argument("--build-type", default="RelWithDebInfo")
    ap.add_argument("--cmake-arg", action="append", default=[], help="extra cmake args for the library")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--min-effect", type=float, default=1.0, help="minimum effect (%%) for a verdict")
    ap.add_argument("--bench-args", default="", help="extra arguments passed to the benchmark")
    ap.add_argument("--no-behaviour-check", action="store_true")
    ap.add_argument("--cooldown", type=float, default=1.0, help="seconds between runs")
    ap.add_argument("--json", default=None, help="write the analysis here")
    ap.add_argument("--out", default=None, help="local directory for raw results")
    args = ap.parse_args()

    repo = Path(args.repo) if args.repo else Path(
        subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, check=True,
                       text=True).stdout.strip())
    ref_spec = args.ref or git(repo, "merge-base", "HEAD", "master")
    host = Host(args.remote or None)
    ensure_generated_data()

    ref, cur = Revision(repo, ref_spec), Revision(repo, args.cur)
    log(f"ref = {ref.label()} {ref.sha}")
    log(f"cur = {cur.label()} {cur.sha}")
    htar, hid = harness_tar()

    cc, cxx = ("clang-21", "clang++-21") if args.compiler == "clang" else ("gcc", "g++")
    cfg = {"cc": cc, "cxx": cxx, "build_type": args.build_type, "cmake_args": args.cmake_arg,
           "jobs": args.jobs}

    upload(host, f"harness/{hid}", htar)
    for rev in {ref.id: ref, cur.id: cur}.values():
        upload(host, f"src/{rev.id}", rev.archive())
    bins = {"ref": build_side(host, ref, hid, cfg)}
    bins["cur"] = bins["ref"] if cur.id == ref.id else build_side(host, cur, hid, cfg)

    run_id = f"{dt.datetime.now():%Y%m%d-%H%M%S}-{os.getpid()}"
    run_dir = f"$HOME/{REMOTE_ROOT}/runs/{run_id}"
    host.run(f"mkdir -p {run_dir}")
    local_dir = Path(args.out) if args.out else Path("/tmp/ddwaf-ab") / run_id
    local_dir.mkdir(parents=True, exist_ok=True)
    data_dir = f"$HOME/{REMOTE_ROOT}/harness/{hid}"

    filt = []
    if args.filter:
        filt += ["--filter", shlex.quote(args.filter)]
    if args.quick:
        filt += ["--quick"]

    same_behaviour = True
    if not args.no_behaviour_check:
        same_behaviour = compare_digests(host, bins, data_dir, run_dir, local_dir, filt)

    bench_args = ["--data-dir", data_dir, "--threads", args.threads, "--cpus", args.cpus]
    if args.quick:
        bench_args += ["--quick"]
    if args.bench_args:
        bench_args += shlex.split(args.bench_args)
    runs: dict[str, list[dict]] = {"ref": [], "cur": []}
    t0 = time.time()
    if measure(host, bins, bench_args, args.filter, 0, args.rounds, run_dir, local_dir, runs,
               args.cooldown) != 0:
        return 1
    # Re-measure scenarios whose rounds were disturbed (other processes on the
    # host) or whose interval is still wide, with additional paired rounds.
    extra_done = 0
    while extra_done < args.extra_rounds:
        res = analyse(runs, args.min_effect / 100)
        noisy = [r["name"] for r in res["rows"]
                 if r["disturbed_runs"] > 0 or r["ci_half_pct"] > args.target_ci]
        if not noisy:
            break
        batch = min(2, args.extra_rounds - extra_done)
        log(f"{len(noisy)} noisy scenario(s), running {batch} extra round(s): {' '.join(noisy)}")
        filt_re = "^(" + "|".join(re.escape(n) for n in noisy) + ")$"
        if measure(host, bins, bench_args, filt_re, args.rounds + extra_done, batch, run_dir,
                   local_dir, runs, args.cooldown) != 0:
            return 1
        extra_done += batch
    log(f"measurement took {time.time() - t0:.0f}s")

    res = analyse(runs, args.min_effect / 100)
    print(f"\nref = {ref.label()}  cur = {cur.label()}  rounds = {args.rounds}+{extra_done}  "
          f"compiler = {cxx} {args.build_type}  cpus = {args.cpus}\n")
    print_table(res)
    if not same_behaviour:
        print("\n!! BEHAVIOUR CHANGED between ref and cur (see above) !!")
    out = {
        "ref": {"spec": ref.spec, "sha": ref.sha, "id": ref.id},
        "cur": {"spec": cur.spec, "sha": cur.sha, "id": cur.id},
        "config": cfg, "rounds": args.rounds, "extra_rounds": extra_done, "cpus": args.cpus, "threads": args.threads,
        "filter": args.filter, "quick": args.quick, "same_behaviour": same_behaviour,
        "meta": runs["ref"][0].get("meta"), **res,
    }
    json_path = Path(args.json) if args.json else local_dir / "ab.json"
    json_path.write_text(json.dumps(out, indent=1))
    log(f"results: {json_path} (raw runs in {local_dir})")
    return 0 if same_behaviour else 3


if __name__ == "__main__":
    sys.exit(main())
