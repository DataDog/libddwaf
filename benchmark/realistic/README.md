# Realistic libddwaf benchmarks and A/B harness

This directory has two parts:

- **`ddwaf_realistic_bench`**: a multi-threaded benchmark that calls libddwaf the
  way dd-trace-php's appsec helper does.
- **`ab.py`**: an A/B driver. It builds two revisions on a benchmark host, checks
  that their observable behaviour is identical, and compares their performance
  with interleaved, pinned runs, each in a fresh process. With `--memory` it
  characterises the memory use of one or two revisions instead.

The benchmark uses only the public C API (`include/ddwaf.h`). The same source
can therefore be linked against any revision of the library, and both sides of
an A/B comparison run the exact same benchmark code.

## What is modelled

The model follows dd-trace-php appsec, which calls libddwaf from the Rust
helper (`appsec/helper-rust`) through libddwaf-rust. Every simulated HTTP
request does the following:

1. `ddwaf_context_init(handle, user allocator)`.
2. **request_init**: one `ddwaf_context_eval` with the 10 addresses the PHP
   extension sends:
   - `server.request.query`, `.method`, `.cookies`, `.uri.raw` and
     `.headers.no_cookies` (one string value per header, lowercase names, no
     cookie header);
   - `server.request.body` (`$_POST`, parsed JSON, or an empty map);
   - `server.request.body.filenames` and `.body.files_field_names`;
   - `server.request.path_params` (URI segments, URL-decoded);
   - `http.client_ip`.
3. **Framework routing** (about half of the requests): a second
   `ddwaf_context_eval` with `server.request.path_params` as a map. This is what
   the Laravel, Symfony and WordPress integrations push.
4. **RASP and user events**: one *transient subcontext* per hooked call
   (`ddwaf_subcontext_init`, `ddwaf_subcontext_eval`, `ddwaf_subcontext_destroy`).
   The hooked calls are:
   - SQL statements: `server.db.statement` + `server.db.system`;
   - file accesses: `server.io.fs.file`;
   - outbound URLs: `server.io.net.url`;
   - login events: `server.business_logic.users.login.success`, `usr.login`,
     `usr.id`.
5. **request_shutdown**: `ddwaf_context_eval` with:
   - `server.response.status` (a string);
   - `server.response.headers.no_cookies` (a map of arrays);
   - `server.response.body` (parsed JSON responses only);
   - `waf.context.processor: {"extract-schema": true}` on 1/16 of the requests
     (1/8 for large ones). This stands in for API Security sampling.
6. `ddwaf_context_destroy`.

Some details:

- **Results.** Every result object is freed with `ddwaf_object_destroy` (with
  the context's output allocator) inside the timed loop, as production does.
- **Blocking.** If an eval returns `block_request` or `redirect_request`, the
  remaining steps are skipped and the shutdown eval still runs, the same as an
  aborted PHP request.
- **Timeout.** The timeout is `UINT64_MAX`, which is effectively infinite. Work
  is never truncated, so the results are deterministic.
- **Input limits.** dd-trace-php applies limits before data reaches the WAF
  (`msgpack_helpers.h`), and the generator applies the same ones:
  - strings are cut at 4096 bytes;
  - depth is capped at 21;
  - query, cookies and body share one budget of 2048 elements;
  - headers and the response body each get their own budget.
- **Allocators and input ownership.** libddwaf-rust creates one user
  allocator (`ddwaf_user_allocator_init`) that forwards to the Rust global
  allocator, which in the sidecar is the system `malloc`. It uses it as the
  output allocator of every context, and passes it as `alloc` to every eval,
  so the WAF owns the inputs and frees them when the context or subcontext is
  destroyed. The benchmark does the same by default (`--inputs owned`): a
  malloc-backed user allocator, and each eval's input is built right before
  the call, inside the timed region. In production the binding builds that
  object from the msgpack message it received; here it is built from a flat
  pre-order token tape with the `ddwaf_object_*` functions (exact capacities,
  copied strings and keys), which costs about what the decoding does. The
  cost of building, and of freeing at destruction, is therefore measured, and
  so is its contention on `malloc`. `--inputs borrowed` restores the old
  mode: objects prebuilt before timing, shared read-only between threads and
  passed with `alloc = NULL`, and the default allocator for results. That
  mode measures the WAF alone.
- **Threads.** N worker threads share one `ddwaf_handle`, and each runs its own
  contexts. This matches the sidecar, where all PHP workers of a service share
  one handle and evaluate concurrently.

### Traffic mixes

The generator is deterministic: xoshiro256** with fixed seeds. It does not use
`std::` distributions, so the inputs are identical whatever the standard library.

- **short**: typical small requests:
  - 65% pages, AJAX 15%, small JSON API 20%; 1 in 32 requests is a login;
  - about 20 to 25 headers (browser, proxy and tracing headers) and 2 to 5
    cookies;
  - 1 to 6 SQL statements and 0 to 2 file accesses.
- **long**: large but realistic requests:
  - 50% e-commerce JSON order submissions, with 40 to 90 items, long notes and
    a base64 signature;
  - 30% WordPress post-editor form posts, with multi-KB HTML content and
    100+ fields;
  - 20% faceted-search GETs with very long query strings;
  - about 45 headers, including a JWT bearer token and CDN/tracing headers;
    about 25 cookies, including consent strings, session blobs and a cart;
  - JSON response bodies of 60 to 100 products;
  - 8 to 20 SQL statements and a few file and URL RASP evals.
- **attack**: the short mix with 1 to 3 injected payloads per request. The
  payload types are SQLi, XSS, LFI, RCE, SSRF, SSTI/log4shell, PHP code and
  NoSQL operators. They are placed in the query, the body, headers, cookies or
  the path. 20% of these requests use scanner user agents, and half of the
  payloads that reach parameters are also "exploited" in the matching RASP
  call, which triggers the RASP rules.
- **rasp_heavy**: a CMS or WooCommerce page with 30 to 60 SQL statements, 4 to 8
  file accesses and 1 to 2 outbound URLs. Each of these is one transient
  subcontext.

`--verify` prints, per scenario, the number of evals, the average input size,
and counts of events, blocks and undetected attacks. Benign traffic produces no
WAF events at all, and attack traffic triggers events in about 84% of requests.

### Rulesets

| Name | Content |
|---|---|
| `rec` | `rulesets/recommended.json`. This is the ruleset bundled with dd-trace-php (rules 1.18.0), added as `initial_ruleset`. |
| `rc` | `rulesets/asm_dd.json`, the ASM_DD config served by Remote Config (rules 1.18.2, 205 rules), plus `rulesets/asm_rc/`, a real organisation's ASM configs in anonymised form: 14 custom rules, about 54 exclusions, one WAF policy (`rules_override`) and a processor override. |
| `rc_bl10k` | `rc` plus ASM_DATA `blocked_ips` (10k entries) and `blocked_users` (10k entries). |
| `rc_bl100k` | `rc` plus `blocked_ips` (100k entries) and `blocked_users` (10k entries). |

Each config is added with `ddwaf_builder_add_or_update_config` under an RC-like
path, for example `datadog/2/ASM_DATA/blocked_ips/config`.

### Scenarios

| Scenario | Unit | Description |
|---|---|---|
| `rec/short`, `rec/long` | req/s | Bundled ruleset with benign traffic. |
| `rc/short`, `rc/long` | req/s | RC ruleset with benign traffic. |
| `rc/attack` | req/s | RC ruleset with attack traffic. Covers event serialisation, obfuscation and RASP matches. |
| `rc/rasp_heavy` | req/s | RC ruleset with dozens of RASP subcontexts per request. |
| `rc_bl10k/short`, `rc_bl100k/short` | req/s | Short traffic with large blocklists loaded. 1 in 64 requests comes from a listed IP, and 1 in 8 is a login, of which 1 in 8 comes from a blocked user. |
| `build/rec`, `build/rc`, `build/rc_bl100k` | op/s | `builder_init`, every `add_or_update_config`, `build_instance`, then destroy. |
| `update/blocked_ips_100k` | op/s | RC update: replace the 100k `blocked_ips` config with one that differs in a single entry, rebuild, and destroy the previous handle. |
| `update/asm_exclusion` | op/s | RC update: remove or re-add one ASM exclusion config, then rebuild. |
| `update/blocked_ips_100k_cold` | op/s | `update/blocked_ips_100k` with the CPU caches evicted before each update. |

The request scenarios run with 1, 4 and 16 threads (`/t1`, `/t4`, `/t16`). The
build and update scenarios run single-threaded only.

The `_cold` variant models an update that comes a long time after the
previous one, as in production, where the handle being replaced has been
evicted from the caches by everything else the process did since it was
built. Before each update it writes to a 96 MiB buffer, three times the L3
cache of a CCD of the benchmark host (`evict_caches()`); that time is
excluded from the measured rate. `--quick` keeps a representative subset,
marked in `define_scenarios()` in `src/main.cpp`.

## Running the benchmark directly

```sh
uv run benchmark/realistic/gen_data.py       # once: creates rulesets/data/blocked_ips_100000.json
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
ninja -C build ddwaf_realistic_bench
build/benchmark/realistic/ddwaf_realistic_bench --cpus 1-15,0            # full suite
build/benchmark/realistic/ddwaf_realistic_bench --quick --threads 1 --filter '^rc/'
build/benchmark/realistic/ddwaf_realistic_bench --verify                 # sanity + determinism
build/benchmark/realistic/ddwaf_realistic_bench --dump-results out.txt   # canonical outputs
```

To build it against an arbitrary `libddwaf.a`:

```sh
cmake -S benchmark/realistic -B out -DDDWAF_LIB=/path/libddwaf.a -DDDWAF_INCLUDE_DIR=/path/include
```

With the production toolchain (what `ab.py` does), inside the musl build image:

```sh
docker run --rm -it --user $(id -u):$(id -g) -e HOME=/tmp -v $PWD:$PWD -w $PWD datadog/musl-build-env:1.0.6 bash -c '
  T=-DCMAKE_TOOLCHAIN_FILE=/usr/local/share/musl/Toolchain.cmake
  cmake -S . -B out/lib -DCMAKE_BUILD_TYPE=RelWithDebInfo $T -DLIBDDWAF_BUILD_SHARED=OFF -DLIBDDWAF_TESTING=OFF
  make -C out/lib -j8 libddwaf_static
  cmake -S benchmark/realistic -B out/bench -DCMAKE_BUILD_TYPE=RelWithDebInfo $T \
    -DDDWAF_LIB=$PWD/out/lib/libddwaf.a -DDDWAF_INCLUDE_DIR=$PWD/include
  make -C out/bench -j8'
/lib64/ld-linux-x86-64.so.2 out/bench/ddwaf_realistic_bench --quick       # glibc
docker run --rm -v $PWD:$PWD:ro alpine:3.22 $PWD/out/bench/ddwaf_realistic_bench \
  --data-dir $PWD/benchmark/realistic --quick                               # musl
```

### Options

| Option | Meaning |
|---|---|
| `--threads` | Thread counts, for example `1,4,16`. |
| `--cpus` | Pinning order: worker *i* runs on the *i*-th CPU of the list. Without it, workers are not pinned. |
| `--filter` | Regex on full names such as `rc/short/t4`. |
| `--quick` | Run the representative subset. |
| `--reps`, `--rep-ms`, `--warmup-ms` | Number of timed repetitions, and the length of each repetition and of the warm-up, in milliseconds. |
| `--json` | Write the results as JSON. |
| `--list` | List the scenarios. |
| `--verify` | Run determinism and expectation checks. |
| `--dump-results` | Write the canonical outputs. |
| `--inputs` | `owned` (default: inputs built per eval and owned by the WAF, as in production) or `borrowed` (prebuilt, `alloc = NULL`). |
| `--memory FILE` | Memory characterisation instead of timing, written as JSON (see [Memory characterisation](#memory-characterisation---memory)). Meant for one scenario and thread count per process. |
| `--mem-contexts N` | With `--memory`: hold N contexts open after `request_init` instead of running traffic. |
| `--mem-traffic-ms` | With `--memory`: length of the traffic phase (3000). |
| `--verbose` | Print ruleset diagnostics and details on failed checks. |

### Measurement

Each scenario first builds a fresh handle; this is not timed. It then runs an
untimed warm-up phase, followed by `reps` timed phases of `rep-ms` each.

- Within a phase, every pinned worker loops over the scenario's pool of
  requests, starting at a different offset. It checks the phase deadline only
  after a complete pass over the pool, so every phase contains whole passes and
  the request mix is identical across phases, runs and revisions.
- A worker's rate is its number of completed requests divided by the time from
  its start to the end of its last request.
- The rate of a phase is the sum of the per-worker rates.
- The benchmark reports the median over phases, and the MAD as a percentage.

Run directly, the benchmark executes all selected scenarios in one process,
one after the other. That is convenient, but not isolated: a scenario
inherits what the previous ones left behind (thread-local caches, the
allocator's free lists and arenas, process-wide caches such as compiled
matchers or the address registry, RE2's DFA caches, the heap layout), and
the order of the scenarios then becomes part of the measurement. `ab.py`
therefore never does this: it starts one process per scenario and thread
count with an exact `--filter` (see [What it does](#what-it-does)).

### Behaviour digests

`--dump-results` writes one line for every eval of every request in every
scenario, plus the build diagnostics and the known addresses and actions:

```
<scenario>\t<request>\t<step>\t<return code>\t<canonical JSON of the result>
```

The canonical JSON is built as follows:

- map keys are sorted;
- array order is preserved;
- unsigned integers carry a `u` suffix;
- `duration`, `block_id`, `stack_id` and `security_response_id` are masked,
  because they are timings or random UUIDs.

Two revisions behave identically on this workload if and only if their dumps
are byte-identical.

## A/B testing (`ab.py`)

Run it from the Mac, or from any checkout. It drives the benchmark host over
ssh (`--remote ubuntu-vm` by default; `--remote ''` runs locally).

```sh
# merge-base(HEAD, master) vs HEAD, all scenarios, 1/4/16 threads, 6 rounds,
# glibc and musl (~30-40 min)
uv run benchmark/realistic/ab.py

# the last commit vs uncommitted changes in the working tree, quick subset (~8 min)
uv run benchmark/realistic/ab.py --ref HEAD --cur WORKTREE --quick

# any two revisions, a subset of scenarios and threads, more rounds, musl only
uv run benchmark/realistic/ab.py --ref master --cur my-branch --filter '^rc/(short|long)' \
    --threads 1,16 --rounds 8 --runtimes musl

# A/A: same build on both sides, to measure the noise floor
uv run benchmark/realistic/ab.py --ref HEAD --cur HEAD

# the old mode: host clang-21 and libstdc++, run natively
uv run benchmark/realistic/ab.py --toolchain host

# memory characterisation of one revision, or ref vs cur (~3 min per revision)
uv run benchmark/realistic/ab.py --memory --rev HEAD
uv run benchmark/realistic/ab.py --memory --ref master --cur HEAD
```

### Production toolchain

The Linux artefact that dd-trace-php links is the release `libddwaf.a`, which
libddwaf-sys downloads (only PECL source builds compile libddwaf from
libddwaf-src instead). It is built in `datadog/musl-build-env` by
`docker/libddwaf/build/Dockerfile`:

- `RelWithDebInfo` (`-O2 -g -DNDEBUG`) with
  `/usr/local/share/musl/Toolchain.cmake`: Alpine's clang 21, `-stdlib=libc++`,
  a static libc++/libc++abi/libunwind, compiler-rt, and
  `-fno-omit-frame-pointer`;
- `LIBDDWAF_ENABLE_LTO=ON`, which only affects the shared library: the static
  archive is made of separate, non-LTO objects (`cmake/objects.cmake`);
- the archive is then merged with `libc++.a`, `libc++abi.a` and
  `libunwind.a`, and the sidecar links it statically.

The binaries this produces are musl executables whose libc dependencies are
the glibc names (`libc.so.6`, `libm.so.6`, ...; the image's `libc.so` linker
script and compat archives arrange that). On Alpine they run natively, with
musl's malloc (mallocng). On a glibc distribution the sidecar runs through the
glibc loader and so uses glibc and glibc's malloc.

`ab.py` reproduces this by default (`--toolchain musl`):

- both the library and the harness are built in `--musl-image`
  (`datadog/musl-build-env:1.0.6`) with the release build's CMake arguments
  (except `LIBDDWAF_ENABLE_LTO`, see above), and the harness is linked
  statically against `libddwaf.a` and libc++, the same way for both sides.
  The container has no network, runs as the calling user and sees
  `~/ddwaf-ab` at the same path;
- every measurement runs on two **runtimes**, selected with `--runtimes`:
  - `glibc`: the binary on the host, started through
    `/lib64/ld-linux-x86-64.so.2`;
  - `musl`: the same binary in an `--alpine-image` (`alpine:3.22`) container
    with `--network none`, `--cpuset-cpus` set to the pinning CPUs, and the
    binaries and data mounted read-only. Startup costs of the container are
    outside the timed phases. The container keeps Docker's default seccomp
    profile; running the binary through musl's loader directly on the host
    gives the same rates within noise.

`--toolchain host` keeps the old mode: the host's clang-21 (or `--compiler
gcc`) with libstdc++, run natively, with a single `host` runtime.

### What it does

1. **Export.** It exports each revision with `git archive`. The special name
   `WORKTREE` stands for the tracked and untracked, non-ignored files of the
   working tree, identified by a content hash. Each export goes to
   `~/ddwaf-ab/src/<id>` on the host.
2. **Harness.** The harness is always the one next to the `ab.py` being run:
   `src/`, `rulesets/` and `CMakeLists.txt` of its directory, as they are on
   disk (uncommitted changes included), identified by a hash of their
   content. It never comes from the revisions being measured: `ab.py` only
   takes the library (`libddwaf.a` and `include/`) from them. Both sides are
   linked against this one copy, so a baseline older than the benchmark, or
   one with an older version of it, is measured with the current harness
   too, and the orchestration in `ab.py` always matches the harness it
   drives. To measure with another version of the harness, run the `ab.py`
   of a checkout of that version. The upload goes to
   `~/ddwaf-ab/harness/<hash>`, and the hash is part of the cache key of the
   benchmark binaries.
3. **Build.** It builds `libddwaf_static` for each revision, then the harness
   linked against it, with `-j8` (`--jobs`) at `nice 10`. The build type is
   `RelWithDebInfo` (`--build-type`); `--cmake-arg -DFOO=BAR` adds library
   options. Builds are cached in `~/ddwaf-ab/{lib,bench}/<id>-<config>[-<harness>]`,
   where `<config>` hashes the toolchain, the build image id, the build type
   and the CMake arguments. The musl toolchain uses make (the image has no
   ninja); the host toolchain uses ninja, and ccache if installed.
4. **Behaviour check.** On every runtime, both binaries run with
   `--dump-results`, one process per scenario, and the dumps are concatenated
   in scenario order. If the dumps differ, it prints a loud banner with the
   first differing evals, and says how many of them differ only in array order
   (for example, event order). It saves both dumps locally, and the exit code
   is 3. Use `--no-behaviour-check` to skip this step. It also notes if the
   reference outputs differ between runtimes (they do not today).
5. **Measure.** It runs R rounds (`--rounds`, default 6). Every measured run,
   that is every scenario at every thread count, on every side, runtime and
   round, is a **separate process**, started with an exact `--filter`
   (`^rc/short/t4$`) and `--threads`. Each process parses the configs it
   needs, generates its request pool, builds its handle and runs its own
   warm-up before its timed phases, so no state is carried from one
   measurement to the next. The warm-up is 1000 ms (`--warmup-ms`; 300 ms
   with `--quick`) instead of the benchmark's 300 ms: a fresh process starts
   from an empty heap, and on musl with 16 threads the first timed
   repetition after a 300 ms warm-up was still 4-6% slow (up to 18% for
   `rc/rasp_heavy`) while mallocng grew its groups. In each round, every runtime runs the selected
   scenarios one after the other, and the two sides of a scenario back to
   back, `--cooldown` (0.2 s) apart. The order of the sides alternates between
   scenarios, between the runtimes of a round and between rounds (round 1:
   glibc `rc/short/t1` ref, cur, `rc/short/t4` cur, ref, ...; then musl
   starting with cur), and the order of the runtimes alternates between
   rounds. Each runtime's round is one shell script on the host: for glibc
   it runs on the host, for musl in one Alpine container, so Docker's
   startup is paid once per round and not per run; the shell still starts
   every benchmark process afresh (fork and exec). Workers are pinned with
   `--cpus 1-15,0`:
   - `t1` runs on core 1 and `t4` on cores 1-4, both inside CCD0;
   - `t16` uses all 16 physical cores;
   - SMT siblings (16-31) stay idle.

   The host is shared with other users, and a process landing on the SMT
   sibling of a benchmark core costs that run 10-20%. So after the R rounds,
   scenarios with a disturbed run (more than 5% below their side's median) or
   a 95% half-width above `--target-ci` (1.5%) get up to `--extra-rounds`
   (default 4) more paired rounds, on the runtime where they were noisy. Only
   those scenarios are re-run.
6. **Report.** For each runtime and scenario it reports:
   - the median rate of each side;
   - the speedup: exp(median of the paired per-round log-ratios ln(cur/ref)).
     The median keeps a minority of disturbed rounds from moving the estimate;
   - a 95% interval of the form
     median ± t(n-1) · 1.2533 · σ / √n, shown as its half-width in the `±95%`
     column. σ is the larger of 1.4826 · MAD of the log-ratios and the
     within-run repetition spread, so that a few lucky rounds cannot make the
     noise look like zero;
   - the min and max of the per-round ratios;
   - an exact Mann-Whitney U p-value, comparing the per-round values of the two
     sides;
   - a verdict: `FASTER` or `SLOWER` when the interval excludes 1 and the effect
     is at least `--min-effect`, which defaults to 1%. Otherwise the verdict is
     `~`.

   It also prints geomeans per group (`rec`, `rc`, `rc_bl10k`, ..., `build`,
   `update`), per thread count, and over all request scenarios.

   Then an **overall** table puts the runtimes side by side. A scenario is
   `FASTER` (`SLOWER`) overall if it is `FASTER` (`SLOWER`) on at least one
   runtime and `SLOWER` (`FASTER`) on none, and `MIXED` if it goes both ways.
   Its overall speedup is the geomean of its per-runtime speedups. The last
   line, `OVERALL VERDICT`, applies the same rule to the scenarios: `FASTER`,
   `SLOWER`, `MIXED` or `NO CHANGE`.
7. **Save.** It writes JSON to `/tmp/ddwaf-ab/<run>/ab.json`, or the path given
   with `--json`, together with the raw benchmark JSON of every round, merged
   over the round's processes (`r<round>-<runtime>-<side>.json`).

### Noise floor (A/A)

These numbers come from `uv run benchmark/realistic/ab.py --ref HEAD --cur HEAD`
on ubuntu-vm (Ryzen 9 9950X), with the production toolchain, owned inputs,
one process per run, 6 rounds plus 4 adaptive extra rounds, on both
runtimes. The library was that of the end of the optimisation series built
on top of this harness (`Parse rules/exclusion data without per-entry
allocations`), 2 to 10 times faster than the baseline below depending on
the scenario. The full run took 38 minutes, 37 of them measuring, about as
long as the previous single-process harness took (37 minutes). Each cell is
the 95% half-width and, in parentheses, the measured "speedup" of the build
against itself:

| Scenario | glibc t1 | glibc t4 | glibc t16 | musl t1 | musl t4 | musl t16 |
|---|---|---|---|---|---|---|
| `rec/short` | ±0.47% (0.9992) | ±0.10% (0.9993) | ±0.25% (0.9981) | ±0.81% (0.9950) | ±1.56% (1.0004) | ±2.04% (0.9992) |
| `rec/long` | ±0.26% (1.0000) | ±0.33% (1.0014) | ±0.12% (1.0009) | ±0.50% (1.0022) | ±0.42% (1.0018) | ±1.08% (0.9942) |
| `rc/short` | ±0.69% (1.0020) | ±0.48% (0.9991) | ±0.32% (1.0008) | ±1.23% (0.9981) | ±1.26% (0.9967) | ±1.22% (0.9977) |
| `rc/long` | ±0.33% (0.9976) | ±0.18% (1.0010) | ±0.18% (1.0017) | ±0.42% (0.9935) | ±0.76% (1.0014) | ±1.50% (1.0025) |
| `rc/attack` | ±0.64% (1.0010) | ±0.75% (1.0004) | ±0.37% (0.9994) | ±0.82% (0.9986) | ±2.35% (0.9965) | ±1.42% (1.0055) |
| `rc/rasp_heavy` | ±0.87% (0.9961) | ±0.43% (0.9998) | ±0.10% (1.0021) | ±0.68% (1.0017) | ±1.57% (0.9931) | ±8.39% (1.0440) |
| `rc_bl10k/short` | ±0.45% (1.0065) | ±0.41% (1.0001) | ±0.23% (0.9990) | ±1.12% (1.0032) | ±0.83% (1.0046) | ±1.89% (1.0011) |
| `rc_bl100k/short` | ±0.38% (1.0022) | ±0.23% (0.9967) | ±0.52% (1.0003) | ±1.09% (1.0070) | ±0.59% (1.0001) | ±1.49% (1.0111) |
| `build/rec` | ±0.17% (1.0018) | | | ±0.80% (0.9973) | | |
| `build/rc` | ±0.10% (0.9994) | | | ±0.62% (1.0008) | | |
| `build/rc_bl100k` | ±0.23% (0.9993) | | | ±0.30% (0.9969) | | |
| `update/blocked_ips_100k` | ±1.38% (1.0040) | | | ±0.38% (0.9977) | | |
| `update/asm_exclusion` | ±0.39% (0.9999) | | | ±1.54% (0.9953) | | |

No scenario got a verdict on either runtime, and the overall verdict was
`NO CHANGE`. The geomean over all request scenarios was 1.0002 on glibc,
1.0020 on musl and 1.0011 overall. Effects of about 1% or more on a single
scenario, and of about 0.3% or more on a group geomean, are measurable on
glibc; musl is noisier (up to ±2.4%).

`rc/rasp_heavy/t16` on musl is the exception, at ±8.4%. That scenario is
dominated by contention on mallocng's lock (see below), and its rate is a
property of the process more than of the build: within a process the
repetitions agree to 0.1-0.2%, but from one process to the next the rate
ranges from 6.5k to 7.6k req/s. A single-process run hid this by always
measuring the scenario on whatever heap the previous scenarios had left.
Treat changes of less than about 10% on that cell as noise.

The previous, single-process harness (master library, 300 ms warm-up) had
half-widths of 0.2-1.4% on glibc and 0.3-1.5% on musl (3.3% on
`rc/rasp_heavy/t4`); an A/A of the per-process harness with that 300 ms
warm-up (28 minutes) had 0.1-1.2% on glibc and 0.2-1.9% on musl, but the
first timed repetitions of the musl t16 scenarios were still slow, hence
the 1000 ms warm-up. The host-toolchain A/A (clang-21 with libstdc++,
borrowed inputs, 13 minutes) had half-widths between ±0.21% and ±1.46%.

### Baseline (production toolchain)

Median rates of the library this harness was introduced with (the base of
the optimisation series), from a two-round run of the per-process harness
(req/s or op/s, both sides averaged), and the musl/glibc ratio:

| Scenario | glibc t1 | glibc t4 | glibc t16 | musl t1 | musl t4 | musl t16 | musl/glibc t1 | musl/glibc t16 |
|---|---|---|---|---|---|---|---|---|
| `rec/short` | 6.71k | 26.44k | 85.36k | 5.98k | 16.69k | 6.29k | 0.89 | 0.074 |
| `rec/long` | 205.9 | 810.3 | 2.78k | 188.4 | 710.7 | 427.3 | 0.91 | 0.154 |
| `rc/short` | 5.53k | 22.00k | 73.12k | 4.54k | 12.06k | 4.58k | 0.82 | 0.063 |
| `rc/long` | 206.3 | 817.2 | 2.79k | 178.3 | 696.4 | 409.1 | 0.86 | 0.147 |
| `rc/attack` | 5.10k | 20.09k | 67.99k | 4.06k | 10.88k | 3.54k | 0.80 | 0.052 |
| `rc/rasp_heavy` | 1.24k | 4.89k | 17.52k | 904.0 | 2.17k | 659.4 | 0.73 | 0.038 |
| `rc_bl10k/short` | 5.53k | 21.71k | 72.31k | 4.48k | 11.83k | 4.51k | 0.81 | 0.062 |
| `rc_bl100k/short` | 5.54k | 21.92k | 72.63k | 4.46k | 11.88k | 4.49k | 0.81 | 0.062 |
| `build/rec` | 78.7 |  |  | 56.6 |  |  | 0.72 |  |
| `build/rc` | 70.3 |  |  | 50.7 |  |  | 0.72 |  |
| `build/rc_bl100k` | 19.6 |  |  | 13.7 |  |  | 0.70 |  |
| `update/blocked_ips_100k` | 26.8 |  |  | 16.7 |  |  | 0.62 |  |
| `update/asm_exclusion` | 2.75k |  |  | 3.10k |  |  | 1.13 |  |

Compared with the same library measured by the earlier single-process
harness, most cells agree within 2-3%, but some moved by 8-14%, which is
what running every scenario in a fresh process is for: on musl most t4 rates
are 6-12% lower (`rc/short/t4` 12.1k instead of 13.7k) and `rc/long/t1` 8%
lower, while on glibc `rc/rasp_heavy/t16` is 11% and
`update/asm_exclusion` 14% higher. In a shared process these scenarios ran
on the heap, caches and arenas the previous scenarios had left.

For comparison, the same library built with clang-21 and libstdc++ and run
natively on glibc (`--toolchain host`, owned inputs) does 6.26k req/s on
`rc/short/t1`, 220 on `rc/long/t1`, 1.48k on `rc/rasp_heavy/t1` and 71.6 op/s
on `build/rc/t1`. Owned inputs cost about 2% against borrowed ones on both
runtimes (`rc/short/t1`: 5.53k against 5.64k on glibc, 4.57k against 4.65k
on musl).

### What the production profiles show

From `profile.py` runs of the baseline, compared with the earlier libstdc++
profiles:

- **libc++ hash tables.** `object_store::get_target`
  (`std::unordered_map<target_index, object_view>::find`) is 12% of
  `rc/short/t1` inclusive, and `__constrain_hash`, the prime-modulo bucket
  index, is 7% on its own. Inlined into `scalar_condition::eval`, it is the
  largest self-time symbol (13-18%, ahead of RE2's DFA loop). The
  per-subcontext copies of `evaluation_cache` (`std::unordered_map`s keyed by
  processor and filter pointers) and the `rule_module_cache::collections`
  lookups keyed by `string_view` (hashed with libc++'s CityHash, 2-5% in
  `rc/rasp_heavy`) come next. With libc++ the same library is 12% slower on
  `rc/short/t1`, 21% on `rc/rasp_heavy/t1` and 4% on `rc/long/t1` than with
  libstdc++, on the same glibc.
- **musl, one thread.** Allocation is the main extra cost: the kernel takes
  10-18% of the short-request scenarios and 2% of `rc/long` (`munmap`,
  `mmap` and the page faults on fresh mappings), and musl's `malloc`, `free`, `memcpy`, `memchr` and
  `pthread_rwlock` another 10-12%. Tracing one second of `rc/short/t1`
  shows 23k `munmap` calls, mostly of 36 KiB and 48 KiB: mallocng gives
  every group of large slots back to the kernel as soon as it is free, and the
  context and subcontext arenas (`std::pmr::monotonic_buffer_resource`,
  growing from 1 KiB by doubling, upstream `new`/`delete`) allocate and free
  such blocks on every request. Builds and RC updates spend 50-70% in musl's
  allocator and the kernel (`update/blocked_ips_100k` is 38% slower than on
  glibc); only `update/asm_exclusion`, dominated by `std::set` and
  `std::unordered_set` node churn, is faster on musl.
- **musl, many threads.** Throughput collapses: `rc/short` does 4.5k req/s
  with one thread, 12.1k with four and 4.6k with sixteen (glibc: 73k).
  At t16, 70-85% of the time is in the kernel, spinning on futex hash bucket
  locks (`futex_wake` from musl's `__unlock`, `futex_wait` from `__lock`)
  and in `munmap`'s TLB shootdowns. Both come from allocations: mallocng
  serialises every `malloc` (and many `free`s) on one global lock, and every
  `munmap` of a multi-threaded process interrupts the other cores. The
  collapse is the same with borrowed inputs (5.2k req/s at t16), so it comes
  from the library's own allocations, not from the input construction.
- **glibc, many threads.** No allocator problem; RE2's per-regex
  `pthread_rwlock` is the only visibly shared line (8% inclusive at t16).
### Concurrent use

Several agents or users can use `ab.py` at the same time:

- Every directory on the host is keyed by revision, config and harness hash.
- Builds hold a **shared** `flock` on `~/ddwaf-ab/locks/measure.lock`, so builds
  can run in parallel with each other.
- The measurement phase, all rounds included, holds the lock **exclusively**.
  Measurements of different invocations therefore serialise, and no build runs
  while anything is being measured.
- `ab.py` warns if the load average is above 1.5 before measuring.
- `ab.py --memory` holds the shared lock: its runs are not timed, but they
  load up to 16 cores and must not disturb a measurement.
- `profile.py` holds the shared lock while it runs.
- Heavy work outside these scripts (builds, tests, ad hoc profiling) should
  hold the shared lock as well: `flock -s ~/ddwaf-ab/locks/measure.lock nice -n 10 <cmd>`.

## Memory characterisation (`--memory`)

`ab.py --memory --rev <rev>` characterises the memory use of one revision;
without `--rev` it does so for `--ref` and `--cur` and prints both side by
side (`ref -> cur`). It builds exactly as an A/B does, on the same runtimes
(`--runtimes`), and never during a timed run: the memory runs are separate
processes, run under the shared lock, and nothing is measured while they
run. Every process characterises one scenario at one thread count
(`ddwaf_realistic_bench --memory FILE --filter '^rc/short/t4$' --threads 4`),
so, as for timing, nothing is inherited from another scenario.

Each process records samples at fixed points. A sample holds:

- with glibc, `mallinfo2()` summed over all arenas: `in_use` (`uordblks +
  hblkhd`, the bytes allocated, mmapped chunks included), `arena`
  (non-mmapped bytes obtained from the kernel), `mmapped` (`hblkhd`), `free`
  (`fordblks`, free bytes the arenas keep) and `keepcost`. The binary looks
  the function up at run time, so the same binary also runs on musl, which
  has no equivalent. Chunks held in glibc's per-thread tcache count as in
  use;
- from `/proc/self/status`, on both runtimes: `VmRSS`, `RssAnon` and `VmHWM`.
  Before each phase whose peak matters, the process writes `5` to
  `/proc/self/clear_refs`, which resets `VmHWM` to the current RSS, so that
  `VmHWM` is the peak RSS of that phase (the JSON's `hwm_reset` says whether
  that worked).

A sampler thread, which allocates nothing while it runs, takes samples every
250 us during builds and every 5 ms during traffic, for the peak and the
steady state. mallinfo2() takes every arena's lock, so it slows the sampled
threads a little; that does not matter, as nothing is timed.

The runs, and the metrics `ab.py` derives from them (differences between two
points, so that the harness's own data, parsed configs and prepared requests,
cancels out), are:

- **Request scenarios** at each of `--mem-threads` (1, 4 and 16), each run
  for `--mem-traffic-ms` (3 s). All values are relative to `start`, the
  process after loading its data and before building the handle:
  - `handle`: after the handle build, before any traffic;
  - `steady`: the median of the samples of the second half of the traffic;
  - `peak`: the largest sample of the traffic (in use), or its `VmHWM` (RSS);
  - `idle`: after the traffic stopped and every context was destroyed, with
    the worker threads still alive: the handle plus what the library and the
    allocator retain, for example in thread-local caches;
  - `exited`: after the workers exited;
  - `destroyed`: after the handle was destroyed as well.
- **Per-context cost** (`<scenario>/contexts`), one process per request
  scenario: after a warm-up pass over the pool on one thread, it opens
  `--mem-contexts` (1000) contexts and leaves each in the middle of a request,
  after its `request_init` eval (the result is freed, the owned input is
  kept by the context, as in production):
  - `per_ctx`: (in use with the contexts open − before) / N;
  - `per_input`: the same for N `request_init` inputs built alone, the share
    of `per_ctx` that is the input itself and not the WAF;
  - `retained`: what remains after destroying the contexts.
- **Builds** (`build/*`): three builds from scratch; values relative to
  `start` (configs already parsed):
  - `peak`: during the first build (`builder_init`, configs,
    `build_instance`);
  - `+builder`: the builder and the new handle;
  - `handle`: the handle alone, after `ddwaf_builder_destroy`;
  - `destroyed`: after destroying the handle;
  - `after 3`: the same after the third build (growth across builds).
- **Updates** (`update/*`): a builder and a handle, two warm-up updates, then
  one measured update:
  - `footprint`: the builder plus the current handle, relative to `start`;
  - `peak`: during the update (`add_or_update_config` or `remove_config`,
    `build_instance`), relative to before it;
  - `2 handles`: right after the update, with the old handle still alive;
  - `delta`: after destroying the old handle (the net change of the update);
  - `destroyed`: after destroying everything, relative to `start`.

Each table is printed for the in-use bytes (glibc only) and for RSS (both
runtimes). The memory run of one revision takes about 1.5 minutes per
runtime. `--mem-reps N` repeats every process and reports medians. The JSON
(`/tmp/ddwaf-ab/<run>/memory.json`, or `--json`) holds the derived metrics and
every raw sample point; the raw output of every process is next to it.

## Profiling (`profile.py`)

`profile.py` builds a revision exactly as `ab.py` does (and shares its build
cache), runs one scenario on the host, and samples it with `sudo perf record`:

```sh
uv run benchmark/realistic/profile.py --rev HEAD --scenario rc/short/t1                  # glibc
uv run benchmark/realistic/profile.py --rev WORKTREE --scenario rc/short/t16 --runtime musl
uv run benchmark/realistic/profile.py --rev HEAD --scenario rc/long/t1 --call-graph dwarf --callers
uv run benchmark/realistic/profile.py --rev HEAD --scenario rc/rasp_heavy/t16 --runtime musl --offcpu
```

- `--runtime glibc` runs the binary through the glibc loader. `--runtime musl`
  runs the same binary on the host through musl's loader, which it copies out
  of the Alpine image together with musl's debug symbols (`musl-dbg`, fetched
  with `apk`; it needs network). This is the libc and malloc of the
  measurement container, with ordinary host paths for perf. The symbols are
  registered in perf's build-id cache.
- perf attaches `--delay` seconds after the start, which skips the handle
  build and most of the warm-up, and samples for `--seconds`.
- Call graphs use frame pointers by default (`--call-graph fp`). The musl
  toolchain compiles the library and the harness with frame pointers, but
  libc, libc++ and libc++abi have none, so the direct caller of a sampled libc
  function is skipped. `--call-graph dwarf` recovers it, at a higher cost.
  DWARF unwinding through musl's own functions was unreliable when tried
  (stacks that degenerate into repeated `__clone` frames). `--leaf-fp` builds a separate variant of the
  library with `-mno-omit-leaf-frame-pointer`.
- `--offcpu` records `sched:sched_switch` with call chains instead of cycles:
  where threads block, for example on musl's malloc lock.
- `--inputs borrowed` profiles the WAF without the input construction.

It writes `flat.txt` (self time by DSO and symbol), `inclusive.txt` (with
children), `dso.txt`, `bench.log` and, with `--callers`, `callers.txt` (call
graphs of the top symbols; slow to produce) to `/tmp/ddwaf-prof/<run>/`, and
leaves `perf.data` on the host under `~/ddwaf-ab/profiles/<run>/`, for
`sudo perf report -f -i perf.data` there. The `sudo` matters for reports:
kernel symbols are only readable as root.

The OpenTelemetry eBPF profiler (`/usr/local/bin/ebpf-profiler`) is not used.
It can only export samples over OTLP gRPC to a collection agent
(`-collection-agent`); its `-pprof` flag serves the agent's own Go runtime
profiles, not the samples; and it has no local file output. perf covers both
on-CPU and off-CPU profiles here.

## Data sources and regeneration

- **`rulesets/recommended.json`** is copied from
  `dd-trace-php/appsec/recommended.json`.
- **`rulesets/asm_dd.json`** is the live ASM_DD config `49.recommended.json`,
  fetched from the Remote Config admin API. It contains Datadog's public rules,
  as distributed to tracers. To fetch it again:

  ```sh
  TOKEN=$(ddtool auth token rc-api-internal --datacenter us1.prod.dog | tail -1 | sed 's/^.*Bearer //')
  H=(-H "Authorization: Bearer $TOKEN" -H 'Accept: application/json')
  curl -s "${H[@]}" "https://rc-admin.us1.prod.dog/products/ASM_DD/configs?orgId=2"   # list config ids
  curl -s "${H[@]}" "https://rc-admin.us1.prod.dog/products/ASM_DD/config/49.recommended.json?orgId=2" \
    | jq -r '.data.attributes.configs[0].Config' > rulesets/asm_dd.json
  # ASM (custom rules, exclusions, overrides): products/ASM/configs?orgId=2 then products/ASM/config/<ID>?orgId=2
  ```

- **`rulesets/asm_rc/`** is produced by `uv run sanitize_asm.py` from the raw
  ASM configs in `rulesets/asm_org2/`. The raw configs are git-ignored and
  never committed. The sanitiser keeps the structure:
  - the number of rules, exclusions and conditions;
  - operators, transformers and key paths;
  - the shape and length of each regex.

  It removes identifying content:
  - words are mapped to pseudo-words of the same length;
  - IPs are mapped into 100.64.0.0/10 or 2001:db8::/32;
  - user tags are replaced.

  It also drops three configs that no single service would receive, or that
  would disable what the benchmark measures:
  - two of the org's three WAF policies, which together would disable most
    rules;
  - an exclusion that turns off user blocking (`blk-001-002`) for every URI.

  The raw `blocking.json`, which disables IP and user blocking, was never
  fetched into `asm_org2/`.
- **`rulesets/data/blocked_{ips,users}_N.json`** is synthetic ASM_DATA,
  generated with a fixed seed by `uv run gen_data.py`:
  - IPs are 70% v4, 15% v6, 10% v4 CIDR and 5% v6 CIDR;
  - users are numeric ids, UUIDs, emails and `usr_` ids;
  - expirations are mostly far in the future, 40% have none and 5% have
    already expired.

  `blocked_ips_100000.json` (4.5 MB) is git-ignored and regenerated on demand;
  `ab.py` does this automatically.

## Caveats

- **Toolchain.** By default the binaries are built like the production
  artefact (see [Production toolchain](#production-toolchain)). With
  `--toolchain host` they are built with libstdc++, whose containers and hash
  functions perform differently: the library is 12% (`rc/short/t1`) to 21%
  (`rc/rasp_heavy/t1`) faster with libstdc++ than with libc++ on the same
  glibc.
- **Input construction.** The owned inputs are built with the `ddwaf_object_*`
  functions, whereas libddwaf-rust fills the `ddwaf_object` structures
  itself. The allocations are comparable (one per container, one per string
  that does not fit inline), but a change to the `ddwaf_object_*` builders
  shows up in the request scenarios, which it would not in production.
- **Allocator.** Production allocations go to the Rust global allocator,
  which is the system malloc in the sidecar; the benchmark calls malloc
  directly. Any other allocator in the process, a different glibc version, or
  different malloc tunables change the numbers, especially those of musl.
- **Turbo and governor.** The host runs with boost on and the `powersave`
  governor, and neither can be changed without root. `t1` runs at about
  5.7 GHz and `t16` noticeably lower. Compare only identical scenarios and
  thread counts. Interleaving and round pairing cancel slow drift.
