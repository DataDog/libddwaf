
# Understanding libddwaf

libddwaf is Datadog’s embeddable security engine. It ingests a declarative security configuration (rules, exclusions, processors, actions) and exposes a compact C API that any tracer or agent can use to evaluate inbound requests. At runtime the library:

1. Parses one or more configurations into an immutable **WAF handle** (`ddwaf_handle`).
2. Creates per-request **contexts** (`ddwaf_context`) bound to the handle and a memory allocator.
3. Accepts request metadata as a tree of `ddwaf_object` values keyed by semantic **addresses** such as `server.request.body` or `http.client_ip`.
4. Produces structured matches, derived attributes, and actions when rules trigger.

The evaluation pipeline is incremental. Each call to `ddwaf_context_eval` updates the context with new data, derives additional inputs, applies exclusions, evaluates rules, and finally runs any post processing steps before returning results.

---

## Execution Pipeline

When a context receives new data, libddwaf processes it in a fixed order:

1. **Preprocessors** enrich or rewrite the input map, often normalising raw user input into structured addresses used by rules.
2. **Exclusion filters** decide which rules or inputs must be ignored for this evaluation (for example to suppress alerts on known-safe endpoints).
3. **Rules** run matchers against the current address store and queue actions and events when they trigger.
4. **Postprocessors** run after rule evaluation to augment the result payload—typically by calculating additional attributes or serialising payloads for downstream systems.
5. The serializer aggregates matches, actions, derived attributes, and timeout information into the `result` object returned by `ddwaf_context_eval`.

Any step can terminate early if the caller’s timeout elapses; in that case the engine short-circuits remaining work while preserving as much partial state as possible.

---

## Configuration Primitives

### Rules

Rules define the core detection logic. Each rule carries:

- Metadata (`id`, `name`, and `tags`) that identifies its purpose and target module.
- One or more **conditions**, each of which applies an operator (such as `match_regex`, `phrase_match`, or `validate_schema`) to a set of addresses. Conditions may also specify key paths and transformers.
- Optional **actions** or overrides that tell integrating products how to respond when the rule matches.

Rules are grouped by **module** internally (for example `network-acl`, `business-logic`, `waf`). Modules isolate specialised detection logic and let the engine maintain separate matcher caches. Each module sorts its rules first by the verdict they can emit (`block` before `monitor`), then by the rule **source** (user vs. Datadog) according to the precedence defined for that module (see *Module ordering and short-circuiting* below), and finally by the rule “type” string when applicable. If a rule returns a blocking verdict the module stops evaluating further rules, avoiding duplicate work once a decisive outcome is known. Monitor-level matches still allow evaluation to continue so other informative events can be collected.

#### Module ordering and short-circuiting

`src/builder/module_builder.cpp` assigns every rule to one of seven categories:

1. `network-acl`
2. `authentication-acl`
3. `custom-acl`
4. `configuration`
5. `business-logic`
6. `rasp`
7. `waf`

The engine evaluates modules in that exact order every time `ddwaf_context_eval` runs. The first two categories are marked as *non-expiring* in `module_builder.hpp`, so `network-acl` and `authentication-acl` always run to completion even if the caller-provided timeout expires. Modules `custom-acl` through `waf` propagate the deadline and will abort early once the budget is exhausted.

Within each module, rule precedence differs:

- `network-acl`, `authentication-acl`, and `rasp` examine Datadog-supplied rules before user-defined ones. These guardrails are meant to fire reliably even when custom rules are misconfigured.
- `custom-acl`, `configuration`, `business-logic`, and `waf` prioritise user rules so that tenant-specific logic can take precedence over built-in defaults.

The `waf` module groups rules by their `type` tag. For each type, user blocking rules run first, followed by Datadog blocking rules, then user monitor rules, and finally Datadog monitor rules. A blocking verdict inside any collection short-circuits the remaining collections and modules. This layering ensures user logic can override defaults where appropriate without sacrificing baseline coverage from Datadog’s managed rules. When a module produces a blocking verdict, remaining modules are skipped and the pipeline advances directly to postprocessors.

---

## Evaluation Flow

The diagram below summarises how the primitives interact during a single call to `ddwaf_context_eval`:

During a single `ddwaf_context_eval` call:

- The incoming `ddwaf_object` map is handed to preprocessors (`evaluate: true` processors) which can create or rewrite addresses. Their outputs become part of the context store.
- Rule and input exclusion filters run next, pruning the address set or muting matching rules before any detection logic executes.
- The engine iterates through the modules in fixed order (`network-acl`, `authentication-acl`, `custom-acl`, `configuration`, `business-logic`, `rasp`, `waf`). The first two modules are non-expiring and always run to completion; the remaining modules respect the caller’s timeout.
- Inside each module, rules are ordered by verdict, source precedence (user vs. Datadog), and optionally type. If a rule returns a blocking verdict the module stops and subsequent modules are skipped; monitor verdicts allow evaluation to continue.
- Once the module loop finishes (or short-circuits), postprocessors (`output: true` processors) enrich the collector with derived attributes that will appear in the result payload.
- The serializer produces the final `result` object: matches, actions, derived attributes, execution metadata, and the `DDWAF_OK`/`DDWAF_MATCH` status that the caller receives.

This sequencing keeps the evaluation deterministic while allowing preprocessors, filters, and postprocessors to cooperate around the shared context state.

### Processors: Preprocessors and Postprocessors

Processors are reusable pieces of logic that transform request data. Each entry in the `processors` section of the configuration specifies a `generator` (for example `uri_parse`, `extract_schema`, `jwt_decode`, or `fingerprint`), optional conditions, and a set of input/output mappings.

Two booleans determine when a processor runs:

- `evaluate: true` marks a **preprocessor**. It runs before exclusions and rules, and any derived addresses are available to matchers in the same evaluation. Typical use cases include decomposing URLs, parsing JWTs, or generating request fingerprints.
- `output: true` marks a **postprocessor**. It runs after rules complete and can emit additional attributes into the result object—for example to expose the parsed URI or schema extraction summaries to telemetry pipelines.

A single processor can act as both a pre- and postprocessor by setting both flags.

Processors are cached per context so expensive computations are only repeated when their inputs change. They can also depend on **scanners**, which provide auxiliary data (for example known good fingerprints) to generator implementations.

### Exclusion Filters

Exclusion filters allow operators to silence noisy rules or drop inputs that should not be considered during evaluation. The configuration distinguishes two flavours:

- **Rule filters** decide whether entire rules (or groups of rules identified by tags) should be skipped. They often key off request metadata such as the current service, endpoint, or environment.
- **Input filters** remove or redact specific addresses before rules see them. They are useful to shield sensitive fields from inspection or to ignore known benign payloads that would otherwise trigger false positives.

Both filter types execute before rule evaluation, and their decisions are cached so later calls within the same context remain consistent.

### Postprocessors (Result Enrichment)

Although postprocessors are defined alongside preprocessors, it is worth calling them out separately: a postprocessor (`output: true`) runs after all rules have evaluated and has access to the request store, the intermediate collector, and the actions selected by the rules. Its job is to attach derived attributes—such as structured URI fields, schema summaries, or decoded tokens—to the `attributes` section of the result returned by `ddwaf_context_eval`. Those attributes help downstream systems present rich diagnostics without recomputing heavy transformations.

---

## Putting It All Together

A minimal integration typically follows these steps:

1. **Load configuration**: parse the JSON/YAML documents describing rules, processors, exclusions, and overrides into `ddwaf_object` instances, then call `ddwaf_init` (or drive the builder API for multi-document workflows).
2. **Create a context per request**: obtain an allocator (`ddwaf_get_default_allocator` or a custom one) and call `ddwaf_context_init`.
3. **Populate addresses**: build a map of request data (`ddwaf_object_set_map` plus insertion helpers) covering the addresses referenced by your rules and preprocessors.
4. **Evaluate**: call `ddwaf_context_eval` with the map, allocator, an optional result object, and a timeout. Inspect `DDWAF_MATCH` or `DDWAF_OK`, along with the populated `events`, `actions`, and `attributes`.
5. **Clean up**: destroy the result with `ddwaf_object_destroy`, then destroy the context (and allocator if you created a custom one).

Because preprocessors, exclusion filters, and postprocessors all operate deterministically on the same address store, their combined effect keeps the rule execution focused on actionable signals while still surfacing rich telemetry to downstream pipelines.
