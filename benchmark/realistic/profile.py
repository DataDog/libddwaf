# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Profile one revision and scenario of the realistic benchmark with perf.

The revision is built exactly as ab.py builds it (by default with the
production musl toolchain, cached and shared with ab.py), then one scenario is
run on the benchmark host while `sudo perf record` samples it:

  * --runtime glibc: the binary runs on the host through the glibc loader;
  * --runtime musl:  the same binary runs on the host through musl's loader,
    copied from the Alpine image that ab.py measures in (with musl's debug
    symbols from the image's musl-dbg package, when they can be fetched). This
    is the same libc and malloc as in the container, without the container,
    so that perf sees ordinary host paths.

perf attaches to the benchmark process after --delay seconds, which skips the
handle build and most of the warm-up, and stops when the process exits. Text
reports (flat, inclusive, per DSO, and with --callers the call graphs of the
top symbols) are written locally; perf.data
stays on the host (its path is printed) for further `sudo perf report -f -i`.

The library and the harness are compiled with frame pointers (the musl
toolchain enables them), so --call-graph fp (the default) is cheap and gives
complete libddwaf stacks. libc, libc++ and libc++abi have no frame pointers:
the caller of a sampled libc function is skipped. Use --call-graph dwarf when
those frames matter; --leaf-fp builds a separate variant of the library that
also keeps frame pointers in leaf functions.

--offcpu records sched_switch events with call chains instead of cycles,
which shows where threads block (for example on musl's malloc lock).

The OpenTelemetry eBPF profiler (/usr/local/bin/ebpf-profiler) is not used:
it only exports samples over OTLP gRPC to a collection agent (-collection-agent);
its -pprof flag serves the profiler's own Go runtime profiles, not the samples,
and it has no local file output.

Heavy work holds the shared lock on ~/ddwaf-ab/locks/measure.lock, like ab.py's
builds, so profiling never overlaps with an ab.py measurement.

Examples:
  uv run benchmark/realistic/profile.py --rev HEAD --scenario rc/short/t1
  uv run benchmark/realistic/profile.py --rev WORKTREE --scenario rc/short/t16 --runtime musl
  uv run benchmark/realistic/profile.py --rev HEAD --scenario rc/long/t1 --call-graph dwarf
  uv run benchmark/realistic/profile.py --rev HEAD --scenario rc/rasp_heavy/t16 --runtime musl --offcpu
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import shlex
import sys
from pathlib import Path

import ab

MUSL_LOADER = "ld-musl-x86_64.so.1"


def ensure_musl_loader(host: ab.Host, image: str) -> str:
    """Copies musl's loader (and debug symbols, best effort) out of the image."""
    tag = re.sub(r"[^A-Za-z0-9_.-]", "_", image)
    d = f"$HOME/{ab.REMOTE_ROOT}/musl/{tag}"
    script = f"""
set -e
mkdir -p {d}
if [ ! -f {d}/.complete ]; then
  docker run --rm --user $(id -u):$(id -g) -v {d}:/o {shlex.quote(image)} cp /lib/{MUSL_LOADER} /o/
  # musl-dbg needs the network (apk); without it, musl's internal functions
  # (mallocng) show up as addresses.
  docker run --rm -v {d}:/o {shlex.quote(image)} sh -c \\
    "apk add -q musl-dbg > /dev/null 2>&1 && cp /usr/lib/debug/lib/{MUSL_LOADER}.debug /o/ && chown $(id -u):$(id -g) /o/{MUSL_LOADER}.debug" \\
    || echo "warning: could not fetch musl debug symbols" >&2
  if [ -f {d}/{MUSL_LOADER}.debug ]; then
    perf buildid-cache -a {d}/{MUSL_LOADER}.debug || true
    sudo -n /usr/bin/perf buildid-cache -a {d}/{MUSL_LOADER}.debug || true
  fi
  touch {d}/.complete
fi
echo {d}/{MUSL_LOADER}
"""
    return host.run(script).stdout.decode().strip().splitlines()[-1]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ab.add_build_args(ap)
    ap.add_argument("--rev", default="HEAD", help="revision to profile, or WORKTREE")
    ap.add_argument("--scenario", required=True, help="full scenario name, e.g. rc/short/t1")
    ap.add_argument("--runtime", choices=["glibc", "musl"], default="glibc",
                    help="libc to run with (--toolchain musl only)")
    ap.add_argument("--seconds", type=float, default=10.0, help="length of the profiled phase")
    ap.add_argument("--delay", type=float, default=1.5,
                    help="seconds between start and perf attach (handle build, warm-up)")
    ap.add_argument("--call-graph", default="fp", help="perf --call-graph mode (fp, dwarf, dwarf,16384)")
    ap.add_argument("--freq", type=int, default=0,
                    help="sampling frequency (default: 1999 Hz with fp, 499 Hz with dwarf)")
    ap.add_argument("--offcpu", action="store_true", help="record sched_switch (off-CPU) instead of cycles")
    ap.add_argument("--leaf-fp", action="store_true",
                    help="separate library build with -mno-omit-leaf-frame-pointer")
    ap.add_argument("--perf-args", default="", help="extra arguments for perf record")
    ap.add_argument("--percent-limit", type=float, default=0.3, help="report threshold (%%)")
    ap.add_argument("--callers", action="store_true",
                    help="also write callers.txt (call graphs of the top symbols; slow to produce)")
    ap.add_argument("--out", default=None, help="local output directory")
    args = ap.parse_args()

    m = re.fullmatch(r"(.+)/t(\d+)", args.scenario)
    if not m:
        raise SystemExit("--scenario must be a full name such as rc/short/t1")
    threads = m.group(2)
    if args.toolchain == "host":
        args.runtime = "host"
    if args.leaf_fp:
        flags = "-O2 -g -DNDEBUG -mno-omit-leaf-frame-pointer"
        args.cmake_arg += [f"-DCMAKE_C_FLAGS_RELWITHDEBINFO={flags}",
                           f"-DCMAKE_CXX_FLAGS_RELWITHDEBINFO={flags}"]

    repo = ab.repo_of(args)
    host = ab.Host(args.remote or None)
    ab.ensure_generated_data()
    rev = ab.Revision(repo, args.rev)
    htar, hid = ab.harness_tar()
    cfg = ab.build_config(args, host)
    ab.upload(host, f"harness/{hid}", htar)
    ab.upload(host, f"src/{rev.id}", rev.archive())
    binary = ab.build_side(host, rev, hid, cfg, args.jobs)

    if args.runtime == "musl":
        launcher = ensure_musl_loader(host, args.alpine_image) + " "
    elif args.runtime == "glibc":
        launcher = ab.GLIBC_LOADER + " "
    else:
        launcher = ""

    run_id = f"{dt.datetime.now():%Y%m%d-%H%M%S}-{rev.id}-{args.runtime}"
    run_dir = f"$HOME/{ab.REMOTE_ROOT}/profiles/{run_id}"
    data_dir = f"$HOME/{ab.REMOTE_ROOT}/harness/{hid}"
    dwarf = args.call_graph.startswith("dwarf")
    freq = args.freq or (499 if dwarf else 1999)
    event = "-e sched:sched_switch" if args.offcpu else f"-F {freq}"
    filt = "^" + re.escape(args.scenario) + "$"
    bench = (f"{launcher}{binary} --data-dir {data_dir} --filter {shlex.quote(filt)} --threads {threads} "
             f"--cpus {args.cpus} --inputs {args.inputs} --reps 1 --rep-ms {int(args.seconds * 1000)} "
             f"--warmup-ms {int(args.delay * 1000) + 500}")
    report = "sudo -n /usr/bin/perf report -f -i perf.data --stdio"
    callers = (f"{report} --no-children --sort sym -g graph,0.5,caller --percent-limit 2 > callers.txt 2>/dev/null"
               if args.callers else "touch callers.txt")
    lim = f"--percent-limit {args.percent_limit}"
    script = f"""
set -e
mkdir -p {run_dir}
cd {run_dir}
exec 9>$HOME/{ab.REMOTE_ROOT}/locks/measure.lock
flock -s 9   # never overlap with an ab.py measurement
{bench} > bench.log 2>&1 &
P=$!
sleep {args.delay}
sudo -n /usr/bin/perf record -q {event} --call-graph {args.call_graph} -p $P -o perf.data {args.perf_args} \\
  > perf-record.log 2>&1 || true
wait $P || {{ cat bench.log; exit 1; }}
{report} --no-children --sort dso,sym -g none {lim} > flat.txt 2>/dev/null
{report} --children --sort sym -g none {lim} > inclusive.txt 2>/dev/null
{report} --no-children --sort dso -g none > dso.txt 2>/dev/null
{callers}
grep -v '^\\[diag\\]' bench.log
echo {run_dir}
"""
    ab.log(f"profiling {args.scenario} of {rev.label()} on {args.runtime} for {args.seconds:.0f}s")
    res = host.run(script)
    out_lines = res.stdout.decode().strip().splitlines()
    remote_dir = out_lines[-1]
    print("\n".join(out_lines[:-1]))
    local = Path(args.out) if args.out else Path("/tmp/ddwaf-prof") / run_id
    local.mkdir(parents=True, exist_ok=True)
    for f in ("flat.txt", "inclusive.txt", "dso.txt", "callers.txt", "bench.log", "perf-record.log"):
        (local / f).write_bytes(host.read(f"{remote_dir}/{f}"))
    ab.log(f"reports in {local}; perf.data on {args.remote or 'localhost'}:{remote_dir}/perf.data")
    top = [ln for ln in (local / "flat.txt").read_text(errors="replace").splitlines()
           if ln.strip() and not ln.startswith("#")][:25]
    print("\n".join(ln[:160] for ln in top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
