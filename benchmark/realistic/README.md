# Realistic libddwaf benchmarks and A/B harness

This directory has two parts:

- **`ddwaf_realistic_bench`**: a multi-threaded benchmark that calls libddwaf the
  way dd-trace-php's appsec helper does.
- **`ab.py`**: an A/B driver. It builds two revisions on a benchmark host, checks
  that their observable behaviour is identical, and compares their performance
  with interleaved, pinned runs.

The benchmark uses only the public C API (`include/ddwaf.h`). The same source
can therefore be linked against any revision of the library, and both sides of
an A/B comparison run the exact same benchmark code.

## What is modelled

The model follows dd-trace-php appsec, which calls libddwaf from the Rust
helper (`appsec/helper-rust`) through libddwaf-rust. Every simulated HTTP
request does the following:

1. `ddwaf_context_init(handle, default allocator)`.
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

- **Results.** Every result object is freed with `ddwaf_object_destroy` inside
  the timed loop, as production does.
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
- **Input ownership.** Inputs are built once, before timing starts, and passed
  as borrowed objects (`alloc = NULL`). They are shared read-only between
  threads. Production hands ownership to the context instead, so the cost of
  freeing the inputs at context destruction is not measured.
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

The request scenarios run with 1, 4 and 16 threads (`/t1`, `/t4`, `/t16`). The
build and update scenarios run single-threaded only. `--quick` keeps a
representative subset, marked in `define_scenarios()` in `src/main.cpp`.

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
# merge-base(HEAD, master) vs HEAD, all scenarios, 1/4/16 threads, 6 rounds (~13-16 min)
uv run benchmark/realistic/ab.py

# the last commit vs uncommitted changes in the working tree, quick subset (~4 min)
uv run benchmark/realistic/ab.py --ref HEAD --cur WORKTREE --quick

# any two revisions, a subset of scenarios and threads, more rounds
uv run benchmark/realistic/ab.py --ref master --cur my-branch --filter '^rc/(short|long)' --threads 1,16 --rounds 8

# A/A: same build on both sides, to measure the noise floor
uv run benchmark/realistic/ab.py --ref HEAD --cur HEAD
```

### What it does

1. **Export.** It exports each revision with `git archive`. The special name
   `WORKTREE` stands for the tracked and untracked, non-ignored files of the
   working tree, identified by a content hash. Each export goes to
   `~/ddwaf-ab/src/<id>` on the host.
2. **Harness.** It uploads the harness (`src/`, `rulesets/`, `CMakeLists.txt`
   from the directory of `ab.py`) to `~/ddwaf-ab/harness/<hash>`. Both sides use
   this one copy, so a baseline older than the benchmark works too.
3. **Build.** It builds `libddwaf_static` for each revision, then the harness
   linked against it. The default build is `RelWithDebInfo` (`-O2 -g`, the
   build type of the production artefact) with clang-21 and `-j8`, at
   `nice 10`; ccache is used if installed. Builds are cached in
   `~/ddwaf-ab/{lib,bench}/<id>-<config>[-<harness>]`. Use
   `--compiler gcc`, `--build-type Release` or `--cmake-arg -DFOO=BAR` to change
   the build.
4. **Behaviour check.** Both binaries run with `--dump-results`. If the dumps
   differ, it prints a loud banner with the first differing evals, and says how
   many of them differ only in array order (for example, event order). It saves
   both dumps locally, and the exit code is 3. Use `--no-behaviour-check` to
   skip this step.
5. **Measure.** It runs R rounds (`--rounds`, default 6). Each round runs both
   binaries as fresh processes, alternating the order: ref then cur, then cur
   then ref. Workers are pinned with `--cpus 1-15,0`:
   - `t1` runs on core 1 and `t4` on cores 1-4, both inside CCD0;
   - `t16` uses all 16 physical cores;
   - SMT siblings (16-31) stay idle.

   The host is shared with other users, and a process landing on the SMT
   sibling of a benchmark core costs that run 10-20%. So after the R rounds,
   scenarios with a disturbed run (more than 5% below their side's median) or
   a 95% half-width above `--target-ci` (1.5%) get up to `--extra-rounds`
   (default 4) more paired rounds. Only those scenarios are re-run.
6. **Report.** For each scenario it reports:
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
7. **Save.** It writes JSON to `/tmp/ddwaf-ab/<run>/ab.json`, or the path given
   with `--json`, together with the raw per-round benchmark JSON files.

### Noise floor (A/A)

These numbers come from `uv run benchmark/realistic/ab.py --ref WORKTREE --cur WORKTREE`
on ubuntu-vm (Ryzen 9 9950X, clang-21, RelWithDebInfo), with 6 rounds plus
adaptive extra rounds. The full run took 13 minutes. Each cell is the 95%
half-width and, in parentheses, the measured "speedup" of the build against
itself:

| Scenario | t1 | t4 | t16 |
|---|---|---|---|
| `rec/short` | ±1.07% (1.0031) | ±0.31% (1.0013) | ±0.49% (1.0010) |
| `rec/long` | ±0.43% (1.0027) | ±0.41% (0.9987) | ±0.62% (0.9976) |
| `rc/short` | ±0.46% (1.0017) | ±0.49% (1.0005) | ±0.23% (1.0026) |
| `rc/long` | ±0.41% (1.0028) | ±0.35% (0.9992) | ±0.53% (0.9960) |
| `rc/attack` | ±1.46% (1.0041) | ±0.33% (1.0066) | ±0.59% (0.9989) |
| `rc/rasp_heavy` | ±0.51% (0.9966) | ±0.25% (0.9972) | ±0.80% (0.9989) |
| `rc_bl10k/short` | ±0.78% (0.9986) | ±0.68% (0.9995) | ±0.70% (0.9999) |
| `rc_bl100k/short` | ±1.40% (1.0041) | ±0.21% (0.9950) | ±0.77% (0.9985) |
| `build/rec` | ±0.56% (1.0016) | | |
| `build/rc` | ±0.29% (1.0004) | | |
| `build/rc_bl100k` | ±0.65% (0.9974) | | |
| `update/blocked_ips_100k` | ±1.03% (0.9986) | | |
| `update/asm_exclusion` | ±1.41% (0.9958) | | |

The geomean over all request scenarios was 1.0002, and over all scenarios
1.0000. No scenario got a verdict. Effects of about 1% or more on a single
scenario, and of about 0.3% or more on a group geomean, are therefore
measurable. The `t1` cells are the noisiest: a single core is the most
exposed to other processes on the host.

### Concurrent use

Several agents or users can use `ab.py` at the same time:

- Every directory on the host is keyed by revision, config and harness hash.
- Builds hold a **shared** `flock` on `~/ddwaf-ab/locks/measure.lock`, so builds
  can run in parallel with each other.
- The measurement phase, all rounds included, holds the lock **exclusively**.
  Measurements of different invocations therefore serialise, and no build runs
  while anything is being measured.
- `ab.py` warns if the load average is above 1.5 before measuring.

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

- **Standard library.** The production Linux artefact is built with clang and a
  static libc++ against musl. The benchmark host has no libc++, so A/B runs use
  clang-21 with libstdc++. Changes that depend on container or hash
  implementations may behave differently under libc++.
- **Input ownership.** Inputs are borrowed (`alloc = NULL`). Production passes
  ownership with a Rust-backed user allocator, so the inputs are freed at
  context destruction. That cost is not included here.
- **Turbo and governor.** The host runs with boost on and the `powersave`
  governor, and neither can be changed without root. `t1` runs at about
  5.7 GHz and `t16` noticeably lower. Compare only identical scenarios and
  thread counts. Interleaving and round pairing cancel slow drift.
