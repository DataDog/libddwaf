// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

// Realistic multi-threaded libddwaf benchmark. Uses only the public C API
// (include/ddwaf.h) so the same source can be linked against any revision of
// the library; see benchmark/realistic/README.md.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if defined(__linux__)
#  include <pthread.h>
#  include <sched.h>
#  include <sys/utsname.h>
#endif
#if defined(__x86_64__) || defined(_M_X64)
#  include <immintrin.h>
#  define BENCH_PAUSE() _mm_pause()
#elif defined(__aarch64__)
#  define BENCH_PAUSE() asm volatile("yield")
#else
#  define BENCH_PAUSE() ((void)0)
#endif

#include "canon.hpp"
#include "ddwaf.h"
#include "node.hpp"
#include "traffic.hpp"

namespace fs = std::filesystem;
using clk = std::chrono::steady_clock;

namespace bench {
namespace {

// Effectively infinite: libddwaf clamps it to the max representable deadline,
// so evaluations are never cut short by timeouts (deterministic work).
constexpr uint64_t eval_timeout_us = UINT64_MAX;

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

struct options {
    std::vector<unsigned> threads{1, 4, 16};
    std::vector<int> cpus; // pinning order; empty = no pinning
    std::string filter;
    bool quick{false};
    bool list{false};
    bool verify{false};
    bool verbose{false};
    std::string dump_path;
    std::string json_path;
    std::string data_dir;
    unsigned reps{5};
    unsigned rep_ms{300};
    unsigned warmup_ms{300};
    bool reps_set{false}, rep_ms_set{false}, warmup_set{false};
};

std::vector<int> parse_cpu_list(const std::string &s)
{
    std::vector<int> out;
    std::stringstream ss(s);
    std::string part;
    while (std::getline(ss, part, ',')) {
        if (part.empty()) { continue; }
        auto dash = part.find('-');
        if (dash == std::string::npos) {
            out.push_back(std::stoi(part));
        } else {
            int lo = std::stoi(part.substr(0, dash));
            int hi = std::stoi(part.substr(dash + 1));
            for (int c = lo; c <= hi; ++c) { out.push_back(c); }
        }
    }
    return out;
}

void usage()
{
    fprintf(stderr,
        "usage: ddwaf_realistic_bench [options]\n"
        "  --data-dir DIR      directory containing rulesets/ (default: next to the binary's source)\n"
        "  --threads LIST      comma separated thread counts (default 1,4,16)\n"
        "  --cpus LIST         CPU pinning order, e.g. 1-15,0 (worker i -> i-th cpu). Default: no pinning\n"
        "  --filter REGEX      only run scenarios whose full name (e.g. rc/short/t4) matches\n"
        "  --quick             representative subset with shorter repetitions\n"
        "  --reps N            timed repetitions per scenario (default 5)\n"
        "  --rep-ms MS         duration of each repetition (default 300)\n"
        "  --warmup-ms MS      untimed warm-up per scenario (default 300)\n"
        "  --json FILE         write results as JSON\n"
        "  --list              list scenarios and exit\n"
        "  --verify            check determinism and expected matches/blocks, no timing\n"
        "  --dump-results FILE write canonical eval outputs (for cross-revision diffs), no timing\n"
        "  --verbose           print ruleset diagnostics\n");
}

bool parse_args(int argc, char **argv, options &o)
{
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto value = [&]() -> std::string {
            auto eq = a.find('=');
            if (eq != std::string::npos) { return a.substr(eq + 1); }
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for %s\n", a.c_str());
                exit(2);
            }
            return argv[++i];
        };
        auto is = [&](const char *name) {
            return a == name || a.rfind(std::string(name) + "=", 0) == 0;
        };
        if (is("--threads")) {
            o.threads.clear();
            for (int t : parse_cpu_list(value())) { o.threads.push_back(static_cast<unsigned>(t)); }
        } else if (is("--cpus")) {
            o.cpus = parse_cpu_list(value());
        } else if (is("--filter")) {
            o.filter = value();
        } else if (a == "--quick") {
            o.quick = true;
        } else if (is("--reps")) {
            o.reps = static_cast<unsigned>(std::stoul(value()));
            o.reps_set = true;
        } else if (is("--rep-ms")) {
            o.rep_ms = static_cast<unsigned>(std::stoul(value()));
            o.rep_ms_set = true;
        } else if (is("--warmup-ms")) {
            o.warmup_ms = static_cast<unsigned>(std::stoul(value()));
            o.warmup_set = true;
        } else if (is("--json")) {
            o.json_path = value();
        } else if (is("--data-dir")) {
            o.data_dir = value();
        } else if (a == "--list") {
            o.list = true;
        } else if (a == "--verify") {
            o.verify = true;
        } else if (is("--dump-results")) {
            o.dump_path = value();
        } else if (a == "--verbose") {
            o.verbose = true;
        } else if (a == "-h" || a == "--help") {
            usage();
            exit(0);
        } else {
            fprintf(stderr, "unknown option %s\n", a.c_str());
            usage();
            return false;
        }
    }
    if (o.quick) {
        if (!o.reps_set) { o.reps = 3; }
        if (!o.rep_ms_set) { o.rep_ms = 200; }
        if (!o.warmup_set) { o.warmup_ms = 150; }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Configurations (rulesets, RC configs)
// ---------------------------------------------------------------------------

struct config_ref {
    std::string rc_path; // path given to ddwaf_builder_add_or_update_config
    std::string file;    // relative to data dir
};

struct ruleset_def {
    std::string name;
    std::vector<config_ref> configs;
};

class config_store {
public:
    explicit config_store(std::string dir) : dir_(std::move(dir)) {}
    config_store(const config_store &) = delete;
    config_store &operator=(const config_store &) = delete;
    ~config_store()
    {
        for (auto &[k, v] : objects_) { ddwaf_object_destroy(&v, ddwaf_get_default_allocator()); }
    }

    const ddwaf_object &get(const std::string &file) { return get_with(file, {}, {}); }

    // Object parsed from the file after replacing `from` with `to` in its text.
    const ddwaf_object &get_with(
        const std::string &file, const std::string &from, const std::string &to)
    {
        const std::string key = file + "|" + from + "|" + to;
        auto it = objects_.find(key);
        if (it != objects_.end()) { return it->second; }
        std::string text = read_file(file);
        if (!from.empty()) {
            auto pos = text.find(from);
            if (pos == std::string::npos) {
                fprintf(stderr, "'%s' not found in %s\n", from.c_str(), file.c_str());
                exit(1);
            }
            text.replace(pos, from.size(), to);
        }
        ddwaf_object obj;
        if (!ddwaf_object_from_json(
                &obj, text.data(), static_cast<uint32_t>(text.size()), ddwaf_get_default_allocator())) {
            fprintf(stderr, "failed to parse %s\n", file.c_str());
            exit(1);
        }
        return objects_.emplace(key, obj).first->second;
    }

    [[nodiscard]] std::vector<std::string> list_dir(const std::string &rel) const
    {
        std::vector<std::string> out;
        fs::path p = fs::path(dir_) / rel;
        if (!fs::is_directory(p)) { return out; }
        for (const auto &e : fs::directory_iterator(p)) {
            if (e.path().extension() == ".json" && e.path().filename().string()[0] != '.') { out.push_back(rel + "/" + e.path().filename().string()); }
        }
        std::sort(out.begin(), out.end());
        return out;
    }

    [[nodiscard]] bool exists(const std::string &rel) const { return fs::exists(fs::path(dir_) / rel); }

private:
    std::string read_file(const std::string &rel) const
    {
        std::ifstream f(fs::path(dir_) / rel, std::ios::binary);
        if (!f) {
            fprintf(stderr, "cannot open %s/%s\n", dir_.c_str(), rel.c_str());
            exit(1);
        }
        std::stringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }

    std::string dir_;
    std::map<std::string, ddwaf_object> objects_;
};

const char *asm_dd_path = "datadog/2/ASM_DD/49.recommended.json/config";
const char *blocked_ips_path = "datadog/2/ASM_DATA/blocked_ips/config";
const char *blocked_users_path = "datadog/2/ASM_DATA/blocked_users/config";

std::map<std::string, ruleset_def> define_rulesets(config_store &store)
{
    std::map<std::string, ruleset_def> rs;
    rs["rec"] = {"rec", {{"initial_ruleset", "rulesets/recommended.json"}}};

    ruleset_def rc{"rc", {{asm_dd_path, "rulesets/asm_dd.json"}}};
    for (const auto &f : store.list_dir("rulesets/asm_rc")) {
        const auto stem = fs::path(f).stem().string();
        rc.configs.push_back({"datadog/2/ASM/" + stem + "/config", f});
    }
    rs["rc"] = rc;

    ruleset_def bl10k = rc;
    bl10k.name = "rc_bl10k";
    bl10k.configs.push_back({blocked_ips_path, "rulesets/data/blocked_ips_10000.json"});
    bl10k.configs.push_back({blocked_users_path, "rulesets/data/blocked_users_10000.json"});
    rs["rc_bl10k"] = bl10k;

    ruleset_def bl100k = rc;
    bl100k.name = "rc_bl100k";
    bl100k.configs.push_back({blocked_ips_path, "rulesets/data/blocked_ips_100000.json"});
    bl100k.configs.push_back({blocked_users_path, "rulesets/data/blocked_users_10000.json"});
    rs["rc_bl100k"] = bl100k;
    return rs;
}

// Report failures found in a diagnostics object; returns number of failures.
unsigned check_diagnostics(const ddwaf_object *diag, const std::string &what, bool verbose)
{
    unsigned failures = 0;
    if (diag == nullptr || !ddwaf_object_is_map(diag)) { return 0; }
    for (std::size_t i = 0; i < ddwaf_object_get_size(diag); ++i) {
        std::size_t klen = 0;
        const char *k = ddwaf_object_get_string(ddwaf_object_at_key(diag, i), &klen);
        const ddwaf_object *v = ddwaf_object_at_value(diag, i);
        std::string key{k != nullptr ? k : "", klen};
        if (key == "error") {
            ++failures;
            fprintf(stderr, "[diag] %s: %s\n", what.c_str(), canonical_json(v).c_str());
            continue;
        }
        if (!ddwaf_object_is_map(v)) { continue; }
        const ddwaf_object *failed = ddwaf_object_find(v, "failed", 6);
        if (failed != nullptr && ddwaf_object_get_size(failed) > 0) {
            failures += static_cast<unsigned>(ddwaf_object_get_size(failed));
            fprintf(stderr, "[diag] %s: %s failed: %s\n", what.c_str(), key.c_str(),
                canonical_json(ddwaf_object_find(v, "errors", 6)).c_str());
        } else if (verbose) {
            const ddwaf_object *loaded = ddwaf_object_find(v, "loaded", 6);
            fprintf(stderr, "[diag] %s: %s loaded %zu\n", what.c_str(), key.c_str(),
                loaded != nullptr ? ddwaf_object_get_size(loaded) : 0);
        }
    }
    return failures;
}

ddwaf_builder make_builder(config_store &store, const ruleset_def &rs, bool verbose,
    std::vector<std::string> *diag_dump = nullptr)
{
    static std::map<std::string, bool> checked;
    ddwaf_builder b = ddwaf_builder_init();
    for (const auto &c : rs.configs) {
        ddwaf_object diag;
        ddwaf_object_set_invalid(&diag);
        const bool ok = ddwaf_builder_add_or_update_config(b, c.rc_path.data(),
            static_cast<uint32_t>(c.rc_path.size()), &store.get(c.file), &diag);
        if (!checked[c.file]) {
            checked[c.file] = true;
            if (!ok) { fprintf(stderr, "[diag] %s: add_or_update_config failed\n", c.file.c_str()); }
            check_diagnostics(&diag, c.file, verbose);
        }
        if (diag_dump != nullptr) { diag_dump->push_back(c.rc_path + "\t" + canonical_json(&diag)); }
        ddwaf_object_destroy(&diag, ddwaf_get_default_allocator());
    }
    return b;
}

ddwaf_handle build_handle(config_store &store, const ruleset_def &rs, bool verbose)
{
    ddwaf_builder b = make_builder(store, rs, verbose);
    ddwaf_handle h = ddwaf_builder_build_instance(b);
    ddwaf_builder_destroy(b);
    if (h == nullptr) {
        fprintf(stderr, "failed to build ruleset %s\n", rs.name.c_str());
        exit(1);
    }
    return h;
}

// Exact, non-expired values of a rules_data config (deterministic order).
std::vector<std::string> data_values(const ddwaf_object &cfg, std::size_t max)
{
    std::vector<std::string> out;
    const ddwaf_object *rd = ddwaf_object_find(&cfg, "rules_data", 10);
    if (rd == nullptr || ddwaf_object_get_size(rd) == 0) { return out; }
    const ddwaf_object *data = ddwaf_object_find(ddwaf_object_at_value(rd, 0), "data", 4);
    if (data == nullptr) { return out; }
    for (std::size_t i = 0; i < ddwaf_object_get_size(data) && out.size() < max; ++i) {
        const ddwaf_object *e = ddwaf_object_at_value(data, i);
        const ddwaf_object *exp = ddwaf_object_find(e, "expiration", 10);
        if (exp != nullptr && ddwaf_object_get_unsigned(exp) < 4000000000ULL &&
            ddwaf_object_get_signed(exp) < 4000000000LL) {
            continue; // expired or expiring before ~2096: skip to keep results time independent
        }
        std::size_t len = 0;
        const char *v = ddwaf_object_get_string(ddwaf_object_find(e, "value", 5), &len);
        if (v == nullptr) { continue; }
        std::string s{v, len};
        if (s.find('/') != std::string::npos) { continue; }
        out.push_back(std::move(s));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

enum class scenario_kind : uint8_t { lifecycle, build, update_data, update_asm };

struct scenario {
    std::string name;
    scenario_kind kind;
    std::string ruleset;
    traffic_mix mix{traffic_mix::small};
    std::size_t pool{256};
    uint64_t seed{1};
    bool blocklists{false};
    bool quick{false};
    std::string description;
};

std::vector<scenario> define_scenarios()
{
    using sk = scenario_kind;
    using tm = traffic_mix;
    return {
        {"rec/short", sk::lifecycle, "rec", tm::small, 256, 0x5401, false, true,
            "bundled recommended.json, small benign requests"},
        {"rec/long", sk::lifecycle, "rec", tm::large, 32, 0x10A6, false, false,
            "bundled recommended.json, large benign requests"},
        {"rc/short", sk::lifecycle, "rc", tm::small, 256, 0x5401, false, true,
            "ASM_DD + ASM (custom rules, exclusions, overrides), small benign requests"},
        {"rc/long", sk::lifecycle, "rc", tm::large, 32, 0x10A6, false, true,
            "ASM_DD + ASM, large benign requests (big JSON/form bodies, many headers/cookies)"},
        {"rc/attack", sk::lifecycle, "rc", tm::attack, 256, 0xA77A, false, true,
            "ASM_DD + ASM, small requests carrying attacks (events, RASP matches)"},
        {"rc/rasp_heavy", sk::lifecycle, "rc", tm::rasp_heavy, 64, 0x7A5B, false, false,
            "ASM_DD + ASM, CMS page with 30-60 SQL queries + file/url RASP evals"},
        {"rc_bl10k/short", sk::lifecycle, "rc_bl10k", tm::small, 256, 0x5402, true, false,
            "rc + 10k blocked IPs + 10k blocked users; some blocked IPs/logins"},
        {"rc_bl100k/short", sk::lifecycle, "rc_bl100k", tm::small, 256, 0x5402, true, true,
            "rc + 100k blocked IPs + 10k blocked users; some blocked IPs/logins"},
        {"build/rec", sk::build, "rec", tm::small, 0, 0, false, false,
            "builder init + add recommended.json + build_instance + destroy"},
        {"build/rc", sk::build, "rc", tm::small, 0, 0, false, true,
            "builder init + add ASM_DD + ASM configs + build_instance + destroy"},
        {"build/rc_bl100k", sk::build, "rc_bl100k", tm::small, 0, 0, false, false,
            "full build including 100k IPs / 10k users"},
        {"update/blocked_ips_100k", sk::update_data, "rc_bl100k", tm::small, 0, 0, false, true,
            "RC update: replace the 100k blocked_ips config and rebuild"},
        {"update/asm_exclusion", sk::update_asm, "rc", tm::small, 0, 0, false, false,
            "RC update: remove/re-add one ASM exclusion config and rebuild"},
    };
}

// ---------------------------------------------------------------------------
// Request execution
// ---------------------------------------------------------------------------

struct prepared_step {
    bool subcontext;
    ddwaf_object data;
};

struct prepared_request {
    std::vector<prepared_step> steps;
    bool attack;
    bool expect_block;
};

std::vector<prepared_request> prepare(std::vector<request_spec> specs)
{
    std::vector<prepared_request> out;
    out.reserve(specs.size());
    for (auto &s : specs) {
        prepared_request p{{}, s.attack, s.expect_block};
        for (auto &st : s.steps) {
            prepared_step ps{st.subcontext, {}};
            to_object(st.data, &ps.data, ddwaf_get_default_allocator());
            p.steps.push_back(ps);
        }
        out.push_back(std::move(p));
    }
    return out;
}

void release(std::vector<prepared_request> &reqs)
{
    for (auto &r : reqs) {
        for (auto &s : r.steps) { ddwaf_object_destroy(&s.data, ddwaf_get_default_allocator()); }
    }
    reqs.clear();
}

bool is_blocking(const ddwaf_object *res)
{
    const ddwaf_object *actions = ddwaf_object_find(res, "actions", 7);
    if (actions == nullptr) { return false; }
    return ddwaf_object_find(actions, "block_request", 13) != nullptr ||
           ddwaf_object_find(actions, "redirect_request", 16) != nullptr;
}

struct step_observer {
    virtual ~step_observer() = default;
    virtual void on_step(std::size_t step, DDWAF_RET_CODE rc, const ddwaf_object *res) = 0;
};

// One HTTP request as dd-trace-php drives it. Input objects are borrowed
// (alloc = NULL), they are prebuilt and shared read-only between threads.
template <bool Observe>
inline void run_request(ddwaf_handle handle, ddwaf_allocator out_alloc, const prepared_request &req,
    step_observer *obs = nullptr)
{
    ddwaf_context ctx = ddwaf_context_init(handle, out_alloc);
    bool blocked = false;
    const std::size_t last = req.steps.size() - 1;
    for (std::size_t i = 0; i < req.steps.size(); ++i) {
        const auto &st = req.steps[i];
        if (blocked && i != last) { continue; } // blocked: request aborted, shutdown still runs
        ddwaf_object res;
        DDWAF_RET_CODE rc;
        auto *data = const_cast<ddwaf_object *>(&st.data);
        if (st.subcontext) {
            ddwaf_subcontext sub = ddwaf_subcontext_init(ctx);
            rc = ddwaf_subcontext_eval(sub, data, nullptr, &res, eval_timeout_us);
            if constexpr (Observe) { obs->on_step(i, rc, &res); }
            blocked = blocked || is_blocking(&res);
            ddwaf_object_destroy(&res, out_alloc);
            ddwaf_subcontext_destroy(sub);
        } else {
            rc = ddwaf_context_eval(ctx, data, nullptr, &res, eval_timeout_us);
            if constexpr (Observe) { obs->on_step(i, rc, &res); }
            blocked = blocked || is_blocking(&res);
            ddwaf_object_destroy(&res, out_alloc);
        }
    }
    ddwaf_context_destroy(ctx);
}

// ---------------------------------------------------------------------------
// Threading
// ---------------------------------------------------------------------------

void pin_to(int cpu)
{
#if defined(__linux__)
    if (cpu < 0) { return; }
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set) != 0) {
        fprintf(stderr, "warning: failed to pin to cpu %d\n", cpu);
    }
#else
    (void)cpu;
#endif
}

struct alignas(64) worker_slot {
    uint64_t count{0};
    int64_t start_ns{0};
    int64_t end_ns{0};
};

int64_t now_ns()
{
    return std::chrono::duration_cast<std::chrono::nanoseconds>(clk::now().time_since_epoch()).count();
}

double median(std::vector<double> v)
{
    if (v.empty()) { return 0; }
    std::sort(v.begin(), v.end());
    const auto n = v.size();
    return n % 2 == 1 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
}

double mad_pct(const std::vector<double> &v)
{
    const double m = median(v);
    if (m == 0) { return 0; }
    std::vector<double> d;
    d.reserve(v.size());
    for (double x : v) { d.push_back(std::fabs(x - m)); }
    return 100.0 * median(d) / m;
}

// Runs `op(tid)` repeatedly on `nthreads` pinned workers during a warm-up and
// `reps` timed phases; returns the aggregate rate (ops/s) of each phase.
// Each worker checks the deadline only every `batch` operations; lifecycle
// scenarios use the pool size so that every timed phase is made of whole
// passes over the request pool (identical request mix in every phase).
template <typename Op>
std::vector<double> run_phases(const options &o, unsigned nthreads, std::size_t batch, Op &&op)
{
    std::vector<worker_slot> slots(nthreads);
    std::atomic<int64_t> generation{0};
    std::atomic<int64_t> deadline{0};
    std::atomic<unsigned> done{0};
    std::atomic<unsigned> ready{0};

    std::vector<std::thread> workers;
    workers.reserve(nthreads);
    for (unsigned t = 0; t < nthreads; ++t) {
        workers.emplace_back([&, t]() {
            pin_to(o.cpus.empty() ? -1 : o.cpus[t % o.cpus.size()]);
            ready.fetch_add(1);
            int64_t seen = 0;
            while (true) {
                int64_t g;
                while ((g = generation.load(std::memory_order_acquire)) == seen) { BENCH_PAUSE(); }
                if (g < 0) { return; }
                seen = g;
                const int64_t dl = deadline.load(std::memory_order_relaxed);
                worker_slot &s = slots[t];
                s.count = 0;
                s.start_ns = now_ns();
                int64_t end;
                do {
                    for (std::size_t k = 0; k < batch; ++k) { op(t); }
                    s.count += batch;
                    end = now_ns();
                } while (end < dl);
                s.end_ns = end;
                done.fetch_add(1, std::memory_order_release);
            }
        });
    }
    while (ready.load() != nthreads) { std::this_thread::yield(); }

    std::vector<double> rates;
    for (unsigned phase = 0; phase <= o.reps; ++phase) {
        const unsigned ms = phase == 0 ? o.warmup_ms : o.rep_ms;
        done.store(0);
        deadline.store(now_ns() + static_cast<int64_t>(ms) * 1000000);
        generation.store(phase + 1, std::memory_order_release);
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
        while (done.load(std::memory_order_acquire) != nthreads) {
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
        if (phase == 0) { continue; }
        double rate = 0;
        for (const auto &s : slots) {
            rate += static_cast<double>(s.count) * 1e9 / static_cast<double>(s.end_ns - s.start_ns);
        }
        rates.push_back(rate);
    }
    generation.store(-1, std::memory_order_release);
    for (auto &w : workers) { w.join(); }
    return rates;
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

struct result_row {
    std::string name;
    std::string scenario;
    unsigned threads;
    std::string unit;
    std::vector<double> reps;
    double median;
    double mad_pct;
};

std::string json_str(const std::string &s)
{
    std::string out = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; }
        out += c;
    }
    return out + "\"";
}

void write_json(const options &o, const std::vector<result_row> &rows)
{
    std::ofstream f(o.json_path);
    f << "{\n  \"meta\": {";
    f << "\"ddwaf_version\": " << json_str(ddwaf_get_version());
#if defined(__VERSION__)
    f << ", \"compiler\": " << json_str(__VERSION__);
#endif
    f << ", \"reps\": " << o.reps << ", \"rep_ms\": " << o.rep_ms
      << ", \"warmup_ms\": " << o.warmup_ms << ", \"cpus\": [";
    for (std::size_t i = 0; i < o.cpus.size(); ++i) { f << (i ? "," : "") << o.cpus[i]; }
    f << "]},\n  \"results\": [\n";
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const auto &r = rows[i];
        char buf[64];
        f << "    {\"name\": " << json_str(r.name) << ", \"scenario\": " << json_str(r.scenario)
          << ", \"threads\": " << r.threads << ", \"unit\": " << json_str(r.unit) << ", \"reps\": [";
        for (std::size_t j = 0; j < r.reps.size(); ++j) {
            snprintf(buf, sizeof(buf), "%.3f", r.reps[j]);
            f << (j ? ", " : "") << buf;
        }
        snprintf(buf, sizeof(buf), "%.3f", r.median);
        f << "], \"median\": " << buf;
        snprintf(buf, sizeof(buf), "%.3f", r.mad_pct);
        f << ", \"mad_pct\": " << buf << "}" << (i + 1 < rows.size() ? "," : "") << "\n";
    }
    f << "  ]\n}\n";
}

// ---------------------------------------------------------------------------
// Verification / dump
// ---------------------------------------------------------------------------

struct digest_observer final : step_observer {
    uint64_t digest{0xcbf29ce484222325ULL};
    std::vector<std::string> *lines{nullptr};
    std::string prefix;
    // stats
    unsigned steps{0}, steps_with_events{0}, events{0}, blocks{0}, errors{0};
    std::map<std::string, unsigned> rule_ids;

    void on_step(std::size_t step, DDWAF_RET_CODE rc, const ddwaf_object *res) override
    {
        ++steps;
        if (rc < 0) { ++errors; }
        std::string canon = std::to_string(static_cast<int>(rc)) + "\t" + canonical_json(res);
        digest = fnv1a(canon, digest);
        if (lines != nullptr) { lines->push_back(prefix + "\t" + std::to_string(step) + "\t" + canon); }
        const ddwaf_object *ev = ddwaf_object_find(res, "events", 6);
        if (ev != nullptr && ddwaf_object_get_size(ev) > 0) {
            ++steps_with_events;
            events += static_cast<unsigned>(ddwaf_object_get_size(ev));
            for (std::size_t i = 0; i < ddwaf_object_get_size(ev); ++i) {
                const ddwaf_object *rule = ddwaf_object_find(ddwaf_object_at_value(ev, i), "rule", 4);
                const ddwaf_object *id = rule != nullptr ? ddwaf_object_find(rule, "id", 2) : nullptr;
                std::size_t len = 0;
                const char *s = id != nullptr ? ddwaf_object_get_string(id, &len) : nullptr;
                if (s != nullptr) { rule_ids[std::string{s, len}]++; }
            }
        }
        if (is_blocking(res)) { ++blocks; }
    }
};

int verify_lifecycle(const options &o, const scenario &sc, ddwaf_handle h,
    const std::vector<prepared_request> &reqs, std::vector<std::string> *dump_lines)
{
    const auto alloc = ddwaf_get_default_allocator();
    int failures = 0;
    std::vector<uint64_t> digests(reqs.size());
    unsigned steps = 0, steps_with_events = 0, events = 0, blocked_reqs = 0;
    unsigned attack_missed = 0, block_missed = 0, unexpected_blocks = 0, benign_with_events = 0;
    unsigned errors = 0;
    std::map<std::string, unsigned> benign_rules, all_rules;
    std::size_t input_bytes = 0;
    for (const auto &rq : reqs) {
        for (const auto &st : rq.steps) { input_bytes += canonical_json(&st.data).size(); }
    }
    for (std::size_t i = 0; i < reqs.size(); ++i) {
        digest_observer obs;
        obs.lines = dump_lines;
        obs.prefix = sc.name + "\t" + std::to_string(i);
        run_request<true>(h, alloc, reqs[i], &obs);
        digests[i] = obs.digest;
        steps += obs.steps;
        steps_with_events += obs.steps_with_events;
        events += obs.events;
        errors += obs.errors;
        if (obs.blocks > 0) { ++blocked_reqs; }
        if (reqs[i].attack && obs.events == 0) {
            ++attack_missed;
            if (o.verbose) {
                printf("    %s request %zu: attack not detected\n", sc.name.c_str(), i);
                for (const auto &st : reqs[i].steps) {
                    printf("      %s %s\n", st.subcontext ? "sub" : "ctx",
                        canonical_json(&st.data).c_str());
                }
            }
        }
        // Unexpected blocks are possible (a random client IP may fall in a
        // blocked CIDR) and only reported; missing blocks are failures.
        if (!reqs[i].expect_block && obs.blocks > 0) { ++unexpected_blocks; }
        if (reqs[i].expect_block && obs.blocks == 0) {
            ++block_missed;
            if (o.verbose) {
                printf("    %s request %zu: expected block=%d, got %u blocking evals\n",
                    sc.name.c_str(), i, reqs[i].expect_block ? 1 : 0, obs.blocks);
                for (const auto &st : reqs[i].steps) {
                    const std::string in = canonical_json(&st.data);
                    printf("      %s %.300s\n", st.subcontext ? "sub" : "ctx", in.c_str());
                }
            }
        }
        if (!reqs[i].attack && obs.events > 0) {
            ++benign_with_events;
            for (auto &[k, v] : obs.rule_ids) { benign_rules[k] += v; }
        }
        for (auto &[k, v] : obs.rule_ids) { all_rules[k] += v; }
    }
    if (dump_lines != nullptr) { return 0; }

    // Determinism: replay concurrently on 4 threads, in different orders.
    std::atomic<unsigned> mismatches{0};
    {
        std::vector<std::thread> ts;
        for (unsigned t = 0; t < 4; ++t) {
            ts.emplace_back([&, t]() {
                for (std::size_t k = 0; k < reqs.size(); ++k) {
                    const std::size_t i = (k * (2 * t + 1) + t * 7) % reqs.size();
                    digest_observer obs;
                    run_request<true>(h, alloc, reqs[i], &obs);
                    if (obs.digest != digests[i]) { mismatches.fetch_add(1); }
                }
            });
        }
        for (auto &t : ts) { t.join(); }
    }

    printf("%-22s reqs=%zu evals=%u avg_input=%.1fKB evals_with_events=%u events=%u "
           "blocked_reqs=%u errors=%u nondeterministic=%u",
        sc.name.c_str(), reqs.size(), steps,
        static_cast<double>(input_bytes) / 1024.0 / static_cast<double>(reqs.size()),
        steps_with_events, events, blocked_reqs, errors, mismatches.load());
    if (sc.mix == traffic_mix::attack) { printf(" attacks_undetected=%u", attack_missed); }
    printf(" missed_blocks=%u unexpected_blocks=%u benign_reqs_with_events=%u\n", block_missed,
        unexpected_blocks, benign_with_events);
    if (o.verbose) {
        for (auto &[k, v] : all_rules) { printf("    rule %-28s %u\n", k.c_str(), v); }
    } else if (!benign_rules.empty()) {
        printf("    benign matches:");
        for (auto &[k, v] : benign_rules) { printf(" %s(%u)", k.c_str(), v); }
        printf("\n");
    }
    if (mismatches.load() > 0 || errors > 0 || block_missed > 0) { ++failures; }
    // Some payload/location combinations are legitimately not detected by the
    // ruleset (e.g. libinjection sqli disabled by the policy); this only
    // guards against the WAF not evaluating at all.
    if (sc.mix == traffic_mix::attack && attack_missed * 2 > reqs.size()) { ++failures; }
    return failures;
}

// ---------------------------------------------------------------------------
// Scenario execution
// ---------------------------------------------------------------------------

std::string fmt_rate(double v)
{
    char buf[32];
    if (v >= 1e6) {
        snprintf(buf, sizeof(buf), "%.3fM", v / 1e6);
    } else if (v >= 1e3) {
        snprintf(buf, sizeof(buf), "%.2fk", v / 1e3);
    } else {
        snprintf(buf, sizeof(buf), "%.2f", v);
    }
    return buf;
}

void print_row(const result_row &r)
{
    const double per_op_us = r.median > 0 ? 1e6 * r.threads / r.median : 0;
    printf("%-30s %12s %s/s  (%9.2f us/%s/thread)  mad %.2f%%\n", r.name.c_str(),
        fmt_rate(r.median).c_str(), r.unit.c_str(), per_op_us, r.unit.c_str(), r.mad_pct);
    fflush(stdout);
}

class runner {
public:
    explicit runner(options o)
        : o_(std::move(o)), store_(o_.data_dir), rulesets_(define_rulesets(store_))
    {}

    int run()
    {
        auto scenarios = define_scenarios();
        std::regex re(o_.filter.empty() ? ".*" : o_.filter);
        std::vector<std::string> dump;
        int failures = 0;
        std::vector<result_row> rows;

        for (const auto &sc : scenarios) {
            if (o_.quick && !sc.quick) { continue; }
            const bool lifecycle = sc.kind == scenario_kind::lifecycle;
            std::vector<unsigned> threads = lifecycle ? o_.threads : std::vector<unsigned>{1};
            if (!lifecycle && std::find(o_.threads.begin(), o_.threads.end(), 1U) == o_.threads.end()) {
                continue;
            }
            std::vector<unsigned> selected;
            for (unsigned t : threads) {
                const std::string full = sc.name + "/t" + std::to_string(t);
                if (std::regex_search(full, re)) { selected.push_back(t); }
            }
            if (selected.empty()) { continue; }

            if (o_.list) {
                for (unsigned t : selected) {
                    printf("%-30s %s\n", (sc.name + "/t" + std::to_string(t)).c_str(),
                        sc.description.c_str());
                }
                continue;
            }

            const auto &rs = rulesets_.at(sc.ruleset);
            if (lifecycle) {
                auto reqs = prepare(generate_traffic(traffic_for(sc)));
                if (o_.verify || !o_.dump_path.empty()) {
                    ddwaf_handle h = build_handle(store_, rs, o_.verbose);
                    failures += verify_lifecycle(o_, sc, h, reqs, o_.dump_path.empty() ? nullptr : &dump);
                    ddwaf_destroy(h);
                } else {
                    for (unsigned t : selected) { rows.push_back(time_lifecycle(sc, rs, reqs, t)); }
                }
                release(reqs);
            } else if (o_.verify || !o_.dump_path.empty()) {
                if (sc.kind == scenario_kind::build) {
                    std::vector<std::string> diag;
                    ddwaf_builder b = make_builder(store_, rs, o_.verbose, &diag);
                    ddwaf_handle h = ddwaf_builder_build_instance(b);
                    for (auto &d : diag) { dump.push_back(sc.name + "\tdiag\t" + d); }
                    dump.push_back(sc.name + "\taddresses\t" + known(h, true));
                    dump.push_back(sc.name + "\tactions\t" + known(h, false));
                    if (o_.verify) {
                        printf("%-22s built=%s\n", sc.name.c_str(), h != nullptr ? "yes" : "NO");
                    }
                    failures += h == nullptr ? 1 : 0;
                    ddwaf_destroy(h);
                    ddwaf_builder_destroy(b);
                }
            } else {
                rows.push_back(time_build(sc, rs));
            }
        }

        if (!o_.dump_path.empty()) {
            std::ofstream f(o_.dump_path);
            for (const auto &l : dump) { f << l << "\n"; }
            printf("wrote %zu lines to %s\n", dump.size(), o_.dump_path.c_str());
        }
        if (!o_.json_path.empty() && !rows.empty()) { write_json(o_, rows); }
        if (o_.verify) { printf(failures == 0 ? "verify: OK\n" : "verify: FAILED (%d)\n", failures); }
        return failures == 0 ? 0 : 1;
    }

private:
    traffic_options traffic_for(const scenario &sc)
    {
        traffic_options t;
        t.mix = sc.mix;
        t.count = sc.pool;
        t.seed = sc.seed;
        if (sc.blocklists) {
            const auto &rs = rulesets_.at(sc.ruleset);
            for (const auto &c : rs.configs) {
                if (c.rc_path == blocked_ips_path) { t.blocked_ips = data_values(store_.get(c.file), 512); }
                if (c.rc_path == blocked_users_path) {
                    t.blocked_users = data_values(store_.get(c.file), 512);
                }
            }
            t.blocked_ip_one_in = 64;
            t.login_one_in = 8;
            t.blocked_user_one_in = 8;
        }
        return t;
    }

    static std::string known(ddwaf_handle h, bool addresses)
    {
        if (h == nullptr) { return "[]"; }
        uint32_t n = 0;
        const char *const *v = addresses ? ddwaf_known_addresses(h, &n) : ddwaf_known_actions(h, &n);
        std::vector<std::string> items;
        for (uint32_t i = 0; i < n; ++i) { items.emplace_back(v[i]); }
        std::sort(items.begin(), items.end());
        std::string out = "[";
        for (std::size_t i = 0; i < items.size(); ++i) { out += (i ? "," : "") + json_str(items[i]); }
        return out + "]";
    }

    result_row time_lifecycle(const scenario &sc, const ruleset_def &rs,
        const std::vector<prepared_request> &reqs, unsigned nthreads)
    {
        ddwaf_handle h = build_handle(store_, rs, o_.verbose);
        const auto alloc = ddwaf_get_default_allocator();
        struct alignas(64) padded_cursor {
            std::size_t v;
        };
        std::vector<padded_cursor> cursor(nthreads);
        for (unsigned t = 0; t < nthreads; ++t) { cursor[t].v = (t * reqs.size()) / nthreads; }
        auto rates = run_phases(o_, nthreads, reqs.size(), [&](unsigned t) {
            std::size_t &c = cursor[t].v;
            run_request<false>(h, alloc, reqs[c]);
            c = c + 1 == reqs.size() ? 0 : c + 1;
        });
        ddwaf_destroy(h);
        result_row r{sc.name + "/t" + std::to_string(nthreads), sc.name, nthreads, "req", rates,
            median(rates), mad_pct(rates)};
        print_row(r);
        return r;
    }

    result_row time_build(const scenario &sc, const ruleset_def &rs)
    {
        std::vector<double> rates;
        if (sc.kind == scenario_kind::build) {
            rates = run_phases(o_, 1, 1, [&](unsigned) {
                ddwaf_handle h = build_handle(store_, rs, false);
                ddwaf_destroy(h);
            });
        } else if (sc.kind == scenario_kind::update_data) {
            const ddwaf_object *variants[2];
            std::string file;
            for (const auto &c : rs.configs) {
                if (c.rc_path == blocked_ips_path) { file = c.file; }
            }
            variants[0] = &store_.get(file);
            variants[1] = &store_.get_with(file, "\"198.51.100.77\"", "\"198.51.100.78\"");
            ddwaf_builder b = make_builder(store_, rs, false);
            ddwaf_handle current = ddwaf_builder_build_instance(b);
            unsigned i = 0;
            rates = run_phases(o_, 1, 1, [&](unsigned) {
                ++i;
                ddwaf_builder_add_or_update_config(b, blocked_ips_path,
                    static_cast<uint32_t>(strlen(blocked_ips_path)), variants[i & 1], nullptr);
                ddwaf_handle next = ddwaf_builder_build_instance(b);
                ddwaf_destroy(current);
                current = next;
            });
            ddwaf_destroy(current);
            ddwaf_builder_destroy(b);
        } else {
            // pick the first exclusion config of the ASM set
            const config_ref *target = nullptr;
            for (const auto &c : rs.configs) {
                if (c.file.find("exclusion") != std::string::npos) {
                    target = &c;
                    break;
                }
            }
            if (target == nullptr) {
                fprintf(stderr, "no exclusion config found for %s\n", sc.name.c_str());
                exit(1);
            }
            ddwaf_builder b = make_builder(store_, rs, false);
            ddwaf_handle current = ddwaf_builder_build_instance(b);
            bool present = true;
            rates = run_phases(o_, 1, 1, [&](unsigned) {
                if (present) {
                    ddwaf_builder_remove_config(
                        b, target->rc_path.data(), static_cast<uint32_t>(target->rc_path.size()));
                } else {
                    ddwaf_builder_add_or_update_config(b, target->rc_path.data(),
                        static_cast<uint32_t>(target->rc_path.size()), &store_.get(target->file),
                        nullptr);
                }
                present = !present;
                ddwaf_handle next = ddwaf_builder_build_instance(b);
                ddwaf_destroy(current);
                current = next;
            });
            ddwaf_destroy(current);
            ddwaf_builder_destroy(b);
        }
        result_row r{sc.name + "/t1", sc.name, 1, "op", rates, median(rates), mad_pct(rates)};
        print_row(r);
        return r;
    }

    options o_;
    config_store store_;
    std::map<std::string, ruleset_def> rulesets_;
};

} // namespace
} // namespace bench

int main(int argc, char **argv)
{
    bench::options o;
    if (!bench::parse_args(argc, argv, o)) { return 2; }
    if (o.data_dir.empty()) {
#ifdef BENCH_DEFAULT_DATA_DIR
        o.data_dir = BENCH_DEFAULT_DATA_DIR;
#else
        o.data_dir = ".";
#endif
    }
    if (!fs::exists(fs::path(o.data_dir) / "rulesets")) {
        fprintf(stderr, "no rulesets/ in data dir %s (use --data-dir)\n", o.data_dir.c_str());
        return 2;
    }
    if (!o.list && !o.verify && o.dump_path.empty()) {
        printf("# libddwaf %s, threads:", ddwaf_get_version());
        for (unsigned t : o.threads) { printf(" %u", t); }
        printf(", reps %u x %u ms (warm-up %u ms), cpus:", o.reps, o.rep_ms, o.warmup_ms);
        if (o.cpus.empty()) { printf(" unpinned"); }
        for (int c : o.cpus) { printf(" %d", c); }
        printf("\n");
    }
    bench::runner r{o};
    return r.run();
}
