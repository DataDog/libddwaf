# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""A/B performance comparison of two libddwaf revisions on a benchmark host.

Both sides are measured with the *same* benchmark program (the harness in the
directory of this script: src/, rulesets/), linked against libddwaf.a built
from each revision. Only the library differs.

The harness is always the one next to this script, as it is on disk; the
measured revisions only provide the library (libddwaf.a and include/). So
an old baseline is measured with the current harness, like the candidate.

Steps:
  1. export each revision (git archive, or the working tree) to the host;
  2. build libddwaf_static for each side and link the harness against it. By
     default this happens in the production build image (musl toolchain,
     clang, static libc++); --toolchain host uses the host compiler and
     libstdc++ instead. Builds hold a shared lock: concurrent builds are fine,
     but never during a measurement;
  3. behaviour check, on every runtime: run both binaries with --dump-results
     and compare the canonical eval outputs (loud failure on any difference);
  4. measure, on every runtime (glibc: the host through the glibc loader;
     musl: an Alpine container): R rounds; every scenario at every thread
     count runs in its own process, so that no state carries over between
     measurements; the sides of a scenario run back to back, with orders
     alternating between scenarios, runtimes and rounds; all under an
     exclusive lock so that measurements of concurrent invocations never
     overlap; scenarios with disturbed or noisy rounds get extra paired
     rounds;
  5. statistics per runtime: paired log-ratios cur/ref across rounds, median,
     robust 95% interval, Mann-Whitney U p-value; geomeans per group; then an
     overall verdict per scenario and for the whole run.

Examples:
  uv run benchmark/realistic/ab.py                         # merge-base(master) vs HEAD
  uv run benchmark/realistic/ab.py --ref HEAD --cur WORKTREE --quick
  uv run benchmark/realistic/ab.py --ref HEAD --cur HEAD   # A/A noise check
  uv run benchmark/realistic/ab.py --ref abc123 --cur def456 --filter '^rc/' --threads 1,16
  uv run benchmark/realistic/ab.py --runtimes musl         # one runtime only
  uv run benchmark/realistic/ab.py --toolchain host        # old mode: host clang + libstdc++
  uv run benchmark/realistic/ab.py --memory --rev HEAD     # memory characterisation (README)
  uv run benchmark/realistic/ab.py --memory --ref X --cur Y
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


def ensure_image(host: Host, image: str) -> str:
    """Returns the image id, pulling the image if it is not present."""
    res = host.run(f"docker image inspect --format '{{{{.Id}}}}' {shlex.quote(image)} 2>/dev/null "
                   f"|| {{ docker pull -q {shlex.quote(image)} > /dev/null && "
                   f"docker image inspect --format '{{{{.Id}}}}' {shlex.quote(image)}; }}")
    return res.stdout.decode().strip().splitlines()[-1]


def build_config(args, host: Host) -> dict:
    """Everything that determines the binaries (it keys the build cache)."""
    cfg = {"toolchain": args.toolchain, "build_type": args.build_type, "cmake_args": args.cmake_arg}
    if args.toolchain == "musl":
        cfg["image"] = args.musl_image
        cfg["image_id"] = ensure_image(host, args.musl_image)
    else:
        cfg["cc"], cfg["cxx"] = ("clang-21", "clang++-21") if args.compiler == "clang" else ("gcc", "g++")
    return cfg


def config_key(cfg: dict) -> str:
    return hashlib.sha256(json.dumps(cfg, sort_keys=True).encode()).hexdigest()[:8]


def build_side(host: Host, rev: Revision, harness_id: str, cfg: dict, jobs: int) -> str:
    """Builds lib + bench for a revision; returns the remote bench binary path.

    Production toolchain (cfg["toolchain"] == "musl"): both steps run in the
    musl build image, with the same CMake invocation as libddwaf's release
    build (docker/libddwaf/build/Dockerfile): RelWithDebInfo and the image's
    Toolchain.cmake (clang, static libc++, frame pointers). The release build
    also passes LIBDDWAF_ENABLE_LTO=ON, but that only affects the shared
    library: the static archive, which dd-trace-php links, is made of
    non-LTO objects either way. The benchmark is linked against libddwaf.a and
    libc++ statically, the way the sidecar links them.
    """
    key = config_key(cfg)
    lib_dir = f"lib/{rev.id}-{key}"
    bench_dir = f"bench/{rev.id}-{key}-{harness_id}"
    root = f"$HOME/{REMOTE_ROOT}"
    extra = " ".join(shlex.quote(x) for x in cfg["cmake_args"])
    lib_cmake = (f"cmake -S {root}/src/{rev.id} -B {root}/{lib_dir} -DCMAKE_BUILD_TYPE={cfg['build_type']} "
                 f"-DLIBDDWAF_BUILD_SHARED=OFF -DLIBDDWAF_BUILD_STATIC=ON -DLIBDDWAF_TESTING=OFF "
                 f"-DGIT_COMMIT={rev.id} {extra}")
    bench_cmake = (f"cmake -S {root}/harness/{harness_id} -B {root}/{bench_dir} "
                   f"-DCMAKE_BUILD_TYPE={cfg['build_type']} -DDDWAF_LIB={root}/{lib_dir}/libddwaf.a "
                   f"-DDDWAF_INCLUDE_DIR={root}/src/{rev.id}/include")
    if cfg["toolchain"] == "musl":
        tc = "-G 'Unix Makefiles' -DCMAKE_TOOLCHAIN_FILE=/usr/local/share/musl/Toolchain.cmake"
        lib_cmake += f" {tc}"
        bench_cmake += f" {tc}"
        lib_make = f"nice -n 10 make -C {root}/{lib_dir} -j{jobs} libddwaf_static"
        bench_make = f"nice -n 10 make -C {root}/{bench_dir} -j{jobs}"
        # The tree is mounted at the same path, so paths in logs and CMake
        # caches are valid on the host too. No network: builds of the static
        # library need no download.
        docker = (f"docker run --rm -i --network none --user $(id -u):$(id -g) -e HOME=/tmp "
                  f"-v {root}:{root} {shlex.quote(cfg['image'])} bash -s")

        def step(cmds: str, log_file: str) -> str:
            return (f"{docker} > {log_file} 2>&1 <<EOS || {{ tail -80 {log_file}; exit 1; }}\n"
                    f"set -e\n{cmds}\nEOS")
    else:
        launcher = ("$( command -v ccache > /dev/null && echo -DCMAKE_C_COMPILER_LAUNCHER=ccache "
                    "-DCMAKE_CXX_COMPILER_LAUNCHER=ccache )")
        lib_cmake += f" -G Ninja -DCMAKE_C_COMPILER={cfg['cc']} -DCMAKE_CXX_COMPILER={cfg['cxx']} {launcher}"
        bench_cmake += f" -G Ninja -DCMAKE_CXX_COMPILER={cfg['cxx']} {launcher}"
        lib_make = f"nice -n 10 ninja -C {root}/{lib_dir} -j{jobs} libddwaf_static"
        bench_make = f"nice -n 10 ninja -C {root}/{bench_dir} -j{jobs}"

        def step(cmds: str, log_file: str) -> str:
            return f"( set -e\n{cmds}\n) > {log_file} 2>&1 || {{ tail -80 {log_file}; exit 1; }}"

    script = f"""
set -e
cd ~/{REMOTE_ROOT}
mkdir -p lib bench locks
exec 9>locks/measure.lock
flock -s 9   # never build while another invocation is measuring
exec 8>locks/build-{rev.id}-{key}.lock
flock 8
if [ ! -f {lib_dir}/.complete ]; then
  rm -rf {lib_dir}
{step(f"{lib_cmake}{chr(10)}{lib_make}", f"{lib_dir}.build.log")}
  touch {lib_dir}/.complete
fi
if [ ! -f {bench_dir}/.complete ]; then
  rm -rf {bench_dir}
{step(f"{bench_cmake}{chr(10)}{bench_make}", f"{bench_dir}.build.log")}
  touch {bench_dir}/.complete
fi
echo {root}/{bench_dir}/ddwaf_realistic_bench
"""
    t0 = time.time()
    res = host.run(script)
    path = res.stdout.decode().strip().splitlines()[-1]
    log(f"built {rev.label()} in {time.time() - t0:.0f}s -> {path}")
    return path


# ---------------------------------------------------------------------------
# Runtimes
# ---------------------------------------------------------------------------

GLIBC_LOADER = "/lib64/ld-linux-x86-64.so.2"


class Runtime:
    """How a benchmark binary is executed.

    * host:  directly (host toolchain builds);
    * glibc: a musl-toolchain binary run on the host through the glibc loader.
             The toolchain's libc.so links it against libc.so.6 & co, so it
             runs with glibc and glibc's malloc, like the sidecar on a
             glibc distribution;
    * musl:  the same binary run natively in an Alpine container (musl's
             loader, musl's mallocng), like the sidecar on Alpine. The
             container has no network, is restricted to the benchmark CPUs and
             sees the binaries and data read-only.
    """

    def __init__(self, name: str, alpine_image: str = "", cpuset: str = ""):
        self.name = name
        self.alpine_image = alpine_image
        self.cpuset = cpuset

    def inner(self, binary: str) -> str:
        """How a script run by script_command() starts the binary."""
        return f"{GLIBC_LOADER} {binary}" if self.name == "glibc" else binary

    def script_command(self, script: str, ro_dirs: list[str], rw_dirs: list[str]) -> str:
        """Runs a POSIX sh script of benchmark invocations on this runtime.

        Every invocation in the script is a fresh process (fork + exec by the
        shell), so nothing carries over between them; for musl the whole
        script runs in one container, which keeps Docker's startup cost out
        of the per-run overhead."""
        if self.name != "musl":
            return f"sh {script}"
        mounts = " ".join([f"-v {d}:{d}:ro" for d in ro_dirs] + [f"-v {d}:{d}" for d in rw_dirs])
        cpuset = f"--cpuset-cpus {self.cpuset}" if self.cpuset else ""
        return (f"docker run --rm --network none --user $(id -u):$(id -g) {cpuset} {mounts} "
                f"{shlex.quote(self.alpine_image)} sh {script}")


def tar_of_blobs(blobs: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, text in blobs.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def upload_scripts(host: Host, run_dir: str, scripts: dict[str, str]) -> None:
    host.run(f"mkdir -p {run_dir} && tar -x -C {run_dir}", input=tar_of_blobs(scripts))


def exact(name: str) -> str:
    """--filter argument selecting exactly one scenario (or, with a trailing
    slash, every thread count of one scenario)."""
    return shlex.quote("^" + re.escape(name) + ("" if name.endswith("/") else "$"))


def invoke(rt: Runtime, binary: str, args: list[str], stem: str, tag: str, quiet: bool = False) -> list[str]:
    """Script lines running one benchmark process. Its output goes to
    <stem>.log; the result lines (not the header or diagnostics) are echoed
    with `tag` (only `tag` if quiet), and the whole log on failure."""
    run = (f"{rt.inner(binary)} {' '.join(args)} > {stem}.log 2>&1 || "
           f"{{ cat {stem}.log; echo '[ab] FAILED: {tag}'; exit 1; }}")
    if quiet:
        return [f"echo '[ab] {tag}'", run]
    return [run, f"sed -n -e '/^\\[diag\\]/d' -e '/^#/d' -e 's|^|[ab] {tag}  |p' {stem}.log"]


def list_scenarios(host: Host, toolchain: str, binary: str, data_dir: str, args: list[str]) -> list[str]:
    """Full names (scenario/tN) the benchmark selects with `args`."""
    rt = Runtime("host" if toolchain == "host" else "glibc")
    out = host.run(f"{rt.inner(binary)} --data-dir {data_dir} --list {' '.join(args)}").stdout.decode()
    return [ln.split()[0] for ln in out.splitlines() if ln.strip()]


def base_names(names: list[str]) -> list[str]:
    out = []
    for n in names:
        b = n.rsplit("/t", 1)[0]
        if b not in out:
            out.append(b)
    return out


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


def compare_digests(host: Host, rt: Runtime, bins: dict[str, str], data_dir: str, run_dir: str,
                    local_dir: Path, bench_args: list[str], scenarios: list[str]) -> tuple[bool, str]:
    """Dumps the eval outputs of both sides on a runtime and compares them.

    Every scenario is dumped by its own process, like the measured runs, and
    the dumps are concatenated in scenario order. Returns (identical, sha256
    of the ref dump)."""
    names = {}
    lines = ["set -e", f"cd {run_dir}"]
    for side, b in bins.items():
        names[side] = f"dump-{rt.name}-{side}.txt"
        parts = []
        for k, base in enumerate(scenarios):
            stem = f"dump-{rt.name}-{side}-{k:02d}"
            lines.append(f"{rt.inner(b)} --data-dir {data_dir} {' '.join(bench_args)} --filter {exact(base + '/')} "
                         f"--dump-results {stem}.txt > {stem}.log 2>&1 || {{ cat {stem}.log; exit 1; }}")
            parts.append(f"{stem}.txt")
        lines.append(f"cat {' '.join(parts)} > {names[side]}")
    script = f"{run_dir}/dump-{rt.name}.sh"
    upload_scripts(host, run_dir, {f"dump-{rt.name}.sh": "\n".join(lines) + "\n"})
    ro = sorted({os.path.dirname(b) for b in bins.values()} | {data_dir})
    host.run(f"cd ~/{REMOTE_ROOT} && exec 9>locks/measure.lock && flock -s 9 && "
             f"{rt.script_command(script, ro, [run_dir])}")
    sums = host.run(f"cd {run_dir} && sha256sum {names['ref']} {names['cur']}").stdout.decode().split("\n")
    a, b = (s.split()[0] for s in sums[:2])
    if a == b:
        n = host.run(f"wc -l < {run_dir}/{names['ref']}").stdout.decode().strip()
        log(f"behaviour check [{rt.name}]: IDENTICAL eval outputs ({n} evals/diagnostics)")
        return True, a
    ref = host.read(f"{run_dir}/{names['ref']}").decode(errors="replace").splitlines()
    cur = host.read(f"{run_dir}/{names['cur']}").decode(errors="replace").splitlines()
    (local_dir / names["ref"]).write_text("\n".join(ref) + "\n")
    (local_dir / names["cur"]).write_text("\n".join(cur) + "\n")

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
    print(f"\n{bar}\n!! BEHAVIOUR CHANGE [{rt.name}]: {len(diffs)} of {len(kr)} eval outputs differ "
          f"({len(order_only)} differ only in array order)\n!! dumps: {local_dir}/{names['ref']} "
          f"{local_dir}/{names['cur']}\n{bar}")
    for k in sorted(diffs)[:8]:
        print(f"--- {k}")
        print(f"  ref: {kr.get(k, '<missing>')[:600]}")
        print(f"  cur: {kc.get(k, '<missing>')[:600]}")
    print(bar + "\n")
    return False, a


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------

def measure(host: Host, runtimes: list[Runtime], bins: dict[str, str], bench_args: list[str],
            selection: dict[str, list[str]], first: int, count: int, data_dir: str, run_dir: str,
            local_dir: Path, runs: dict, cooldown: float) -> int:
    """Runs rounds [first, first+count) under the exclusive measurement lock.

    `selection` maps the runtimes to measure to the full scenario names
    (scenario/tN) to run on them. Every run of one scenario at one thread
    count by one side is a separate process, started with an exact --filter:
    nothing that a previous scenario left behind (thread-local caches,
    allocator state, process-wide caches, heap layout) can affect it. Within a
    round, every runtime runs its scenarios one after the other, and both
    sides of a scenario back to back. The order of the sides alternates
    between scenarios, between the runtimes of a round and between rounds,
    and the order of the runtimes alternates between rounds, so slow drift of
    the host cancels out in the paired ratios.
    """
    active = [rt for rt in runtimes if rt.name in selection]
    ro = sorted({os.path.dirname(b) for b in bins.values()} | {data_dir})
    scripts, order = {}, []
    for r in range(first, first + count):
        order_rt = active if r % 2 == 0 else active[::-1]
        for i, rt in enumerate(order_rt):
            lines = ["set -e", f"cd {run_dir}"]
            for k, name in enumerate(selection[rt.name]):
                sides = ["ref", "cur"] if (r + i + k) % 2 == 0 else ["cur", "ref"]
                threads = name.rsplit("/t", 1)[1]
                for side in sides:
                    stem = f"r{r}-{rt.name}-{side}-{k:02d}"
                    args = [*bench_args, "--threads", threads, "--filter", exact(name), "--json", f"{stem}.json"]
                    lines += invoke(rt, bins[side], args, stem, f"r{r + 1} {rt.name} {side}")
                    if cooldown > 0:
                        lines.append(f"sleep {cooldown}")
            scripts[f"r{r}-{rt.name}.sh"] = "\n".join(lines) + "\n"
            order.append((r, rt))
    upload_scripts(host, run_dir, scripts)

    lines = [
        "set -e", f"cd ~/{REMOTE_ROOT}", "exec 9>locks/measure.lock",
        "if ! flock -n -x 9; then echo '[ab] waiting for another measurement to finish...'; flock -x 9; fi",
        "echo \"[ab] host $(hostname), load $(cut -d' ' -f1-3 /proc/loadavg), governor "
        "$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null), boost "
        "$(cat /sys/devices/system/cpu/cpufreq/boost 2>/dev/null)\"",
        "L=$(cut -d' ' -f1 /proc/loadavg); if awk \"BEGIN{exit !($L > 1.5)}\"; then "
        "echo \"[ab] WARNING: load average $L: other processes may disturb the measurement\"; fi",
    ]
    for r, rt in order:
        lines.append(f"echo '[ab] round {r + 1}: {rt.name} ({len(selection[rt.name])} scenarios x 2 sides)'")
        lines.append(rt.script_command(f"{run_dir}/r{r}-{rt.name}.sh", ro, [run_dir]))
    rc = host.stream("\n".join(lines))
    if rc != 0:
        log(f"measurement failed (exit {rc})")
        return rc
    for r in range(first, first + count):
        out = host.run(f"cd {run_dir} && for f in r{r}-*.json; do printf '@@@ %s\\n' \"$f\"; cat \"$f\"; done")
        docs: dict[tuple[str, str], list[tuple[int, dict]]] = {}
        for chunk in out.stdout.decode().split("@@@ ")[1:]:
            fname, _, body = chunk.partition("\n")
            m = re.fullmatch(r"r\d+-(\w+)-(ref|cur)-(\d+)\.json", fname.strip())
            if not m:
                continue
            docs.setdefault((m.group(1), m.group(2)), []).append((int(m.group(3)), json.loads(body)))
        for rt in active:
            for side in ("ref", "cur"):
                parts = [d for _, d in sorted(docs.get((rt.name, side), []), key=lambda x: x[0])]
                if len(parts) != len(selection[rt.name]):
                    log(f"round {r + 1} {rt.name} {side}: {len(parts)} results for "
                        f"{len(selection[rt.name])} scenarios")
                    return 1
                doc = {"meta": parts[0]["meta"], "results": [x for d in parts for x in d["results"]]}
                (local_dir / f"r{r}-{rt.name}-{side}.json").write_text(json.dumps(doc, indent=1))
                runs[rt.name][side].append(doc)
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


def combine(per_rt: dict[str, dict]) -> dict:
    """Overall verdict per scenario across runtimes, and overall geomeans.

    A scenario is FASTER (SLOWER) overall when it is FASTER (SLOWER) on at
    least one runtime and SLOWER (FASTER) on none; MIXED when it goes both
    ways. Its overall speedup is the geomean of the per-runtime speedups.
    """
    names = []
    for res in per_rt.values():
        for r in res["rows"]:
            if r["name"] not in names:
                names.append(r["name"])
    rows = []
    for name in names:
        per = {rt: next((r for r in res["rows"] if r["name"] == name), None) for rt, res in per_rt.items()}
        per = {rt: r for rt, r in per.items() if r is not None}
        verdicts = {r["verdict"] for r in per.values()}
        if "FASTER" in verdicts and "SLOWER" in verdicts:
            verdict = "MIXED"
        elif "FASTER" in verdicts:
            verdict = "FASTER"
        elif "SLOWER" in verdicts:
            verdict = "SLOWER"
        else:
            verdict = "~"
        sp = math.exp(sum(math.log(r["speedup"]) for r in per.values()) / len(per))
        unit = next(iter(per.values()))["unit"]
        rows.append({"name": name, "unit": unit, "speedup": sp, "verdict": verdict,
                     "per_runtime": {rt: {"speedup": r["speedup"], "verdict": r["verdict"]}
                                     for rt, r in per.items()}})
    geomeans = {}
    for rt, res in per_rt.items():
        for k in ("ALL requests", "ALL builds", "ALL"):
            geomeans[f"{rt} {k}"] = res["geomeans"].get(k)

    def geo(sel):
        v = [r["speedup"] for r in sel]
        return math.exp(sum(math.log(x) for x in v) / len(v)) if v else None

    geomeans["overall requests"] = geo([r for r in rows if r["unit"] == "req"])
    geomeans["overall builds"] = geo([r for r in rows if r["unit"] == "op"])
    geomeans["overall"] = geo(rows)
    vs = {r["verdict"] for r in rows}
    if "MIXED" in vs or {"FASTER", "SLOWER"} <= vs:
        overall = "MIXED"
    elif "SLOWER" in vs:
        overall = "SLOWER"
    elif "FASTER" in vs:
        overall = "FASTER"
    else:
        overall = "NO CHANGE"
    return {"rows": rows, "geomeans": geomeans, "verdict": overall}


def print_overall(comb: dict, runtimes: list[str]) -> None:
    hdr = f"{'scenario':<30} " + " ".join(f"{rt:>16}" for rt in runtimes) + f" {'geomean':>8}  verdict"
    print(hdr)
    print("-" * len(hdr))
    for r in comb["rows"]:
        cells = []
        for rt in runtimes:
            p = r["per_runtime"].get(rt)
            cells.append(f"{p['speedup']:.4f} {p['verdict']:>7}" if p else f"{'':>16}")
        print(f"{r['name']:<30} " + " ".join(f"{c:>16}" for c in cells) +
              f" {r['speedup']:>8.4f}  {r['verdict']}")
    print()
    for k, v in comb["geomeans"].items():
        if v is not None:
            print(f"geomean {k:<26} {v:.4f} ({(v - 1) * 100:+.2f}%)")
    counts = {v: sum(r["verdict"] == v for r in comb["rows"]) for v in ("FASTER", "SLOWER", "MIXED")}
    print(f"\n{counts['FASTER']} faster, {counts['SLOWER']} slower, {counts['MIXED']} mixed, "
          f"{len(comb['rows']) - sum(counts.values())} within noise")
    print(f"OVERALL VERDICT: {comb['verdict']}")


# ---------------------------------------------------------------------------
# Memory characterisation
# ---------------------------------------------------------------------------

# Derived metrics per kind of memory run: (metric, point, base point, unit).
# Values are differences between two points of the run, so the harness's own
# data, which is in every point, cancels out. A "peak" point on the rss
# family uses VmHWM (peak RSS since the reset at the start of the phase).
MEM_METRICS = {
    "traffic": [("handle", "built", "start", "MiB"), ("steady", "steady", "start", "MiB"),
                ("peak", "peak", "start", "MiB"), ("idle", "idle", "start", "MiB"),
                ("exited", "threads_exited", "start", "MiB"),
                ("destroyed", "handle_destroyed", "start", "MiB")],
    "contexts": [("per_ctx", "contexts", "warm", "KiB/ctx"), ("per_input", "inputs", "warm", "KiB/ctx"),
                 ("retained", "contexts_destroyed", "warm", "MiB")],
    "build": [("peak", "build_peak", "start", "MiB"), ("+builder", "built_with_builder", "start", "MiB"),
              ("handle", "built", "start", "MiB"), ("destroyed", "handle_destroyed", "start", "MiB"),
              ("after 3", "final", "start", "MiB")],
    "update": [("footprint", "before", "start", "MiB"), ("peak", "update_peak", "before", "MiB"),
               ("2 handles", "both_handles", "before", "MiB"), ("delta", "after", "before", "MiB"),
               ("destroyed", "destroyed", "start", "MiB")],
}
MEM_PEAK_POINTS = {"peak", "build_peak", "update_peak"}
MEM_FAMILIES = {"heap": "in_use", "rss": "rss"}


def mem_metrics(row: dict, hwm_reset: bool) -> dict[str, float | None]:
    """{"<family>.<metric>": bytes (or bytes per context)} for one run."""
    pts = row["points"]
    out = {}
    for name, point, base, unit in MEM_METRICS[row["kind"]]:
        for fam, field in MEM_FAMILIES.items():
            a, b = pts.get(point, {}), pts.get(base, {})
            if fam == "rss" and point in MEM_PEAK_POINTS and hwm_reset:
                x = a.get("hwm")
            else:
                x = a.get(field)
            y = b.get(field)
            v = None if x is None or y is None else float(x - y)
            if v is not None and unit.endswith("/ctx"):
                v /= row["contexts"]
            out[f"{fam}.{name}"] = v
    return out


def run_memory(args, host: Host, runtimes: list[Runtime], revs: dict[str, Revision], bins: dict[str, str],
               names: list[str], data_dir: str, run_dir: str, local_dir: Path, cfg: dict) -> int:
    """Memory characterisation of one or two revisions (see README).

    Each (scenario, thread count) runs in its own process with --memory, plus
    one --mem-contexts process per request scenario. The runs take the shared
    lock: they are not timed, but they must not disturb someone else's timed
    run either."""
    # Build and update scenarios exist at t1 only, so listing at another
    # thread count yields the request scenarios.
    request = base_names(list_scenarios(host, args.toolchain, next(iter(bins.values())), data_dir,
                                        ["--threads", "2"] + (["--filter", shlex.quote(args.filter)]
                                                              if args.filter else [])))
    ro = sorted({os.path.dirname(b) for b in bins.values()} | {data_dir})
    common = ["--data-dir", data_dir, "--cpus", args.cpus, "--inputs", args.inputs,
              "--mem-traffic-ms", str(args.mem_traffic_ms)]
    labels = list(bins)
    scripts, order = {}, []
    for rep in range(args.mem_reps):
        for rt in runtimes:
            for label in (labels if rep % 2 == 0 else labels[::-1]):
                lines, k = ["set -e", f"cd {run_dir}"], 0
                jobs = [(n, ["--threads", n.rsplit("/t", 1)[1], "--filter", exact(n)]) for n in names]
                jobs += [(f"{b}/contexts", ["--threads", "1", "--filter", exact(f"{b}/t1"),
                                            "--mem-contexts", str(args.mem_contexts)]) for b in request]
                for name, a in jobs:
                    stem = f"mem{rep}-{rt.name}-{label}-{k:02d}"
                    lines += invoke(rt, bins[label], [*common, *a, "--memory", f"{stem}.json"], stem,
                                    f"mem {rep + 1} {rt.name} {label} {name}", quiet=True)
                    k += 1
                scripts[f"mem{rep}-{rt.name}-{label}.sh"] = "\n".join(lines) + "\n"
                order.append(f"mem{rep}-{rt.name}-{label}.sh")
    upload_scripts(host, run_dir, scripts)
    lines = ["set -e", f"cd ~/{REMOTE_ROOT}", "exec 9>locks/measure.lock",
             "if ! flock -n -s 9; then echo '[ab] waiting for a measurement to finish...'; flock -s 9; fi"]
    for sc in order:
        rt = next(r for r in runtimes if f"-{r.name}-" in sc)
        lines.append(rt.script_command(f"{run_dir}/{sc}", ro, [run_dir]))
    t0 = time.time()
    if host.stream("\n".join(lines)) != 0:
        log("memory runs failed")
        return 1
    log(f"memory runs took {time.time() - t0:.0f}s")

    out = host.run(f"cd {run_dir} && for f in mem*.json; do printf '@@@ %s\\n' \"$f\"; cat \"$f\"; done")
    raw: dict[str, dict[str, list[dict]]] = {rt.name: {lb: [] for lb in labels} for rt in runtimes}
    hwm_ok = True
    for chunk in out.stdout.decode().split("@@@ ")[1:]:
        fname, _, body = chunk.partition("\n")
        m = re.fullmatch(r"mem(\d+)-(\w+)-(\w+)-(\d+)\.json", fname.strip())
        if not m:
            continue
        doc = json.loads(body)
        (local_dir / fname.strip()).write_text(body)
        hwm_ok = hwm_ok and doc["meta"]["hwm_reset"]
        for row in doc["results"]:
            row["rep"] = int(m.group(1))
            raw[m.group(2)][m.group(3)].append(row)
    if not hwm_ok:
        log("warning: VmHWM could not be reset; rss peaks are the sampled maxima")

    result = {}
    for rt in runtimes:
        result[rt.name] = {}
        for label in labels:
            per_name: dict[str, list[dict]] = {}
            for row in raw[rt.name][label]:
                per_name.setdefault(row["name"], []).append(row)
            metrics = {}
            for name, rows in per_name.items():
                ms = [mem_metrics(r, hwm_ok) for r in rows]
                agg = {}
                for key in ms[0]:
                    vals = [m[key] for m in ms if m[key] is not None]
                    agg[key] = median(vals) if vals else None
                metrics[name] = {"kind": rows[0]["kind"], **agg}
            result[rt.name][label] = {"metrics": metrics, "raw": raw[rt.name][label]}

    for rt in runtimes:
        for fam in MEM_FAMILIES:
            if fam == "heap" and all(v.get("heap.handle") is None and v.get("heap.per_ctx") is None
                                     and v.get("heap.footprint") is None
                                     for lb in labels for v in result[rt.name][lb]["metrics"].values()):
                continue  # no mallinfo2 (musl)
            what = "malloc in use (mallinfo2)" if fam == "heap" else "RSS (VmRSS / VmHWM)"
            print(f"\n=== memory [{rt.name}] {what}: " + "  ".join(
                f"{lb} = {revs[lb].label()}" for lb in labels) +
                  ("  (cells: ref -> cur)" if len(labels) == 2 else ""))
            print_memory(result[rt.name], labels, fam)

    doc = {
        "revisions": {lb: {"spec": r.spec, "sha": r.sha, "id": r.id} for lb, r in revs.items()},
        "config": cfg, "inputs": args.inputs, "cpus": args.cpus, "threads": args.mem_threads,
        "contexts": args.mem_contexts, "traffic_ms": args.mem_traffic_ms, "reps": args.mem_reps,
        "filter": args.filter, "hwm_reset": hwm_ok, "runtimes": result,
    }
    json_path = Path(args.json) if args.json else local_dir / "memory.json"
    json_path.write_text(json.dumps(doc, indent=1))
    log(f"results: {json_path} (raw runs in {local_dir})")
    return 0


def fmt_bytes(v: float | None, unit: str) -> str:
    if v is None:
        return "-"
    x = v / (1024.0 if unit.startswith("KiB") else 1048576.0)
    return f"{x:.1f}" if abs(x) >= 100 else f"{x:.2f}"


def print_memory(res: dict, labels: list[str], fam: str) -> None:
    for kind, cols in MEM_METRICS.items():
        names = [n for n, m in res[labels[0]]["metrics"].items() if m["kind"] == kind]
        if not names:
            continue
        heads = [f"{c[0]} ({c[3].split('/')[0]})" for c in cols]
        widths = [max(18 if len(labels) == 2 else 10, len(h) + 2) for h in heads]
        hdr = f"{kind:<28}" + "".join(f"{h:>{w}}" for h, w in zip(heads, widths))
        print("\n" + hdr)
        print("-" * len(hdr))
        for name in names:
            cells = []
            for metric, _, _, unit in cols:
                vals = [res[lb]["metrics"].get(name, {}).get(f"{fam}.{metric}") for lb in labels]
                cells.append(" -> ".join(fmt_bytes(v, unit) for v in vals))
            print(f"{name:<28}" + "".join(f"{c:>{w}}" for c, w in zip(cells, widths)))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def add_build_args(ap: argparse.ArgumentParser) -> None:
    """Options shared with profile.py."""
    ap.add_argument("--repo", default=None, help="git repository (default: toplevel of cwd)")
    ap.add_argument("--remote", default="ubuntu-vm", help="ssh host ('' = run locally)")
    ap.add_argument("--toolchain", choices=["musl", "host"], default="musl",
                    help="musl: production toolchain (musl build image, clang, static libc++; default); "
                         "host: the host's compiler and libstdc++")
    ap.add_argument("--musl-image", default="datadog/musl-build-env:1.0.6",
                    help="build image for --toolchain musl")
    ap.add_argument("--alpine-image", default="alpine:3.22", help="image of the musl runtime")
    ap.add_argument("--compiler", choices=["clang", "gcc"], default="clang",
                    help="compiler for --toolchain host")
    ap.add_argument("--build-type", default="RelWithDebInfo")
    ap.add_argument("--cmake-arg", action="append", default=[], help="extra cmake args for the library")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--cpus", default="1-15,0", help="pinning order passed to the benchmark")
    ap.add_argument("--inputs", choices=["owned", "borrowed"], default="owned",
                    help="input ownership mode of the benchmark (see README)")


def select_runtimes(args) -> list[Runtime]:
    cpuset = ",".join(sorted({str(c) for c in parse_cpus(args.cpus)}, key=int))
    if args.toolchain == "host":
        names = ["host"]
    else:
        names = [x for x in args.runtimes.split(",") if x]
        for n in names:
            if n not in ("glibc", "musl"):
                raise SystemExit(f"unknown runtime {n} (glibc, musl)")
    return [Runtime(n, args.alpine_image, cpuset) for n in names]


def parse_cpus(s: str) -> list[int]:
    out = []
    for part in s.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            out += list(range(int(lo), int(hi) + 1))
        elif part:
            out.append(int(part))
    return out


def repo_of(args) -> Path:
    return Path(args.repo) if args.repo else Path(
        subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, check=True,
                       text=True).stdout.strip())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    add_build_args(ap)
    ap.add_argument("--ref", default=None, help="baseline revision (default: merge-base of HEAD and master)")
    ap.add_argument("--cur", default="HEAD", help="candidate revision, or WORKTREE for uncommitted changes")
    ap.add_argument("--runtimes", default="glibc,musl",
                    help="runtimes measured with --toolchain musl (comma separated: glibc, musl)")
    ap.add_argument("--rounds", type=int, default=6)
    ap.add_argument("--extra-rounds", type=int, default=4,
                    help="max additional rounds for scenarios that were disturbed or too noisy")
    ap.add_argument("--target-ci", type=float, default=1.5,
                    help="re-measure scenarios whose 95%% half-width (%%) exceeds this")
    ap.add_argument("--threads", default="1,4,16")
    ap.add_argument("--filter", default=None, help="regex on scenario/tN names")
    ap.add_argument("--quick", action="store_true", help="representative subset, shorter reps")
    ap.add_argument("--min-effect", type=float, default=1.0, help="minimum effect (%%) for a verdict")
    ap.add_argument("--bench-args", default="", help="extra arguments passed to the benchmark")
    ap.add_argument("--no-behaviour-check", action="store_true")
    ap.add_argument("--cooldown", type=float, default=0.2, help="seconds between benchmark processes")
    ap.add_argument("--warmup-ms", type=int, default=None,
                    help="untimed warm-up of every measured process (default 1000; 300 with --quick)")
    ap.add_argument("--memory", action="store_true",
                    help="memory characterisation instead of timing (of --rev, or of --ref and --cur)")
    ap.add_argument("--rev", default=None, help="with --memory: the one revision to characterise")
    ap.add_argument("--mem-threads", default="1,4,16", help="with --memory: thread counts of the traffic runs")
    ap.add_argument("--mem-contexts", type=int, default=1000,
                    help="with --memory: concurrent contexts of the per-context runs")
    ap.add_argument("--mem-traffic-ms", type=int, default=3000, help="with --memory: traffic phase length")
    ap.add_argument("--mem-reps", type=int, default=1,
                    help="with --memory: repetitions (metrics are the median over them)")
    ap.add_argument("--json", default=None, help="write the analysis here")
    ap.add_argument("--out", default=None, help="local directory for raw results")
    args = ap.parse_args()

    repo = repo_of(args)
    host = Host(args.remote or None)
    ensure_generated_data()
    runtimes = select_runtimes(args)

    if args.memory and args.rev:
        revs = {"rev": Revision(repo, args.rev)}
    else:
        revs = {"ref": Revision(repo, args.ref or git(repo, "merge-base", "HEAD", "master")),
                "cur": Revision(repo, args.cur)}
    for label, rev in revs.items():
        log(f"{label} = {rev.label()} {rev.sha}")
    htar, hid = harness_tar()
    log(f"harness = {hid} (src/, rulesets/, CMakeLists.txt next to {Path(__file__).name}; "
        f"the same for every side)")
    cfg = build_config(args, host)
    if any(rt.name == "musl" for rt in runtimes):
        ensure_image(host, args.alpine_image)

    upload(host, f"harness/{hid}", htar)
    built: dict[str, str] = {}
    for rev in revs.values():
        if rev.id not in built:
            upload(host, f"src/{rev.id}", rev.archive())
            built[rev.id] = build_side(host, rev, hid, cfg, args.jobs)
    bins = {label: built[rev.id] for label, rev in revs.items()}

    # Absolute paths: scripts also run inside containers, where $HOME differs.
    root = host.run("cd ~ && pwd").stdout.decode().strip() + "/" + REMOTE_ROOT
    run_id = f"{dt.datetime.now():%Y%m%d-%H%M%S}-{os.getpid()}"
    run_dir = f"{root}/runs/{run_id}"
    host.run(f"mkdir -p {run_dir}")
    local_dir = Path(args.out) if args.out else Path("/tmp/ddwaf-ab") / run_id
    local_dir.mkdir(parents=True, exist_ok=True)
    data_dir = f"{root}/harness/{hid}"

    sel = (["--filter", shlex.quote(args.filter)] if args.filter else []) + (["--quick"] if args.quick else [])
    threads = args.mem_threads if args.memory else args.threads
    names = list_scenarios(host, args.toolchain, bins[next(iter(bins))], data_dir, ["--threads", threads, *sel])
    if not names:
        log("no scenario selected")
        return 1
    if args.memory:
        return run_memory(args, host, runtimes, revs, bins, names, data_dir, run_dir, local_dir, cfg)
    ref, cur = revs["ref"], revs["cur"]

    common = ["--inputs", args.inputs]
    same_behaviour = True
    if not args.no_behaviour_check:
        ref_sums = {}
        for rt in runtimes:
            same, ref_sums[rt.name] = compare_digests(host, rt, bins, data_dir, run_dir, local_dir, common,
                                                      base_names(names))
            same_behaviour = same_behaviour and same
        if len(set(ref_sums.values())) > 1:
            log("note: the ref outputs differ between runtimes (" +
                ", ".join(f"{k}={v[:12]}" for k, v in ref_sums.items()) +
                "); this is a libc difference, not an A/B difference")

    # A fresh process starts from an empty heap: on musl with 16 threads the
    # first 300 ms after the warm-up still ran 4-6% slow (18% for
    # rc/rasp_heavy), while mallocng grew its groups, hence the longer
    # warm-up than the benchmark's own default.
    warmup = args.warmup_ms if args.warmup_ms is not None else (300 if args.quick else 1000)
    bench_args = ["--data-dir", data_dir, "--cpus", args.cpus, *common, "--warmup-ms", str(warmup)]
    if args.quick:
        bench_args += ["--quick"]
    if args.bench_args:
        bench_args += shlex.split(args.bench_args)
    runs = {rt.name: {"ref": [], "cur": []} for rt in runtimes}
    t0 = time.time()
    if measure(host, runtimes, bins, bench_args, {rt.name: names for rt in runtimes}, 0,
               args.rounds, data_dir, run_dir, local_dir, runs, args.cooldown) != 0:
        return 1
    # Re-measure scenarios whose rounds were disturbed (other processes on the
    # host) or whose interval is still wide, with additional paired rounds.
    extra_done = 0
    while extra_done < args.extra_rounds:
        noisy = {}
        for rt in runtimes:
            res = analyse(runs[rt.name], args.min_effect / 100)
            sel_names = [r["name"] for r in res["rows"]
                         if r["disturbed_runs"] > 0 or r["ci_half_pct"] > args.target_ci]
            if sel_names:
                noisy[rt.name] = sel_names
                log(f"[{rt.name}] {len(sel_names)} noisy scenario(s): {' '.join(sel_names)}")
        if not noisy:
            break
        batch = min(2, args.extra_rounds - extra_done)
        log(f"running {batch} extra round(s)")
        if measure(host, runtimes, bins, bench_args, noisy, args.rounds + extra_done, batch,
                   data_dir, run_dir, local_dir, runs, args.cooldown) != 0:
            return 1
        extra_done += batch
    log(f"measurement took {time.time() - t0:.0f}s")

    toolchain = (f"musl toolchain ({args.musl_image})" if args.toolchain == "musl"
                 else f"host {cfg['cxx']}")
    per_rt = {}
    for rt in runtimes:
        res = analyse(runs[rt.name], args.min_effect / 100)
        per_rt[rt.name] = res
        print(f"\n=== runtime {rt.name} === ref = {ref.label()}  cur = {cur.label()}  "
              f"rounds = {args.rounds}+{extra_done}  {toolchain} {args.build_type}  "
              f"inputs = {args.inputs}  cpus = {args.cpus}\n")
        print_table(res)
    comb = combine(per_rt)
    if len(runtimes) > 1:
        print(f"\n=== overall ({', '.join(per_rt)}) ===\n")
        print_overall(comb, list(per_rt))
    else:
        print(f"OVERALL VERDICT: {comb['verdict']}")
    if not same_behaviour:
        print("\n!! BEHAVIOUR CHANGED between ref and cur (see above) !!")
    out = {
        "ref": {"spec": ref.spec, "sha": ref.sha, "id": ref.id},
        "cur": {"spec": cur.spec, "sha": cur.sha, "id": cur.id},
        "config": cfg, "inputs": args.inputs, "rounds": args.rounds, "extra_rounds": extra_done,
        "cpus": args.cpus, "threads": args.threads, "filter": args.filter, "quick": args.quick,
        "same_behaviour": same_behaviour,
        "meta": {rt: runs[rt]["ref"][0].get("meta") for rt in runs},
        "runtimes": per_rt, "overall": comb,
    }
    json_path = Path(args.json) if args.json else local_dir / "ab.json"
    json_path.write_text(json.dumps(out, indent=1))
    log(f"results: {json_path} (raw runs in {local_dir})")
    return 0 if same_behaviour else 3


if __name__ == "__main__":
    sys.exit(main())
