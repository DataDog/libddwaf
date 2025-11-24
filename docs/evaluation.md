# Evaluation Flow

How `evaluation_engine` runs processors, exclusions, and rules during `ddwaf_context_eval`, based on `evaluation_engine.cpp`, `module.cpp`, and the module builder.

## Pipeline overview

1. **Skip if no new inputs**: if the `object_store` has no new targets, return immediately.
2. **Preprocessors**: run in configured order, populating derived addresses. Each processor has a per-instance cache keyed by its pointer.
3. **Filters**: evaluate rule filters then input filters. Matches populate an `exclusion_policy` (bypass/monitor/custom action, plus input pruning) used by rules.
4. **Rules**: walk modules in fixed order (below). Blocking verdicts short-circuit the rest of the module set; monitor verdicts allow continued evaluation.
5. **Postprocessors**: always run after rules; they may add attributes but never affect matching.
6. **Serialize**: gather events, actions, attributes, and obfuscation into the result. If any rule fired, the engine injects `waf.context.event` so postprocessors can gate on it.

Processor, filter, and rule caches persist across evaluations so repeated data does not trigger repeated work.

## Processor execution

- **Preprocessors** (`evaluate: true`) run before filters/rules and write outputs into the object store (cloned into the caller allocator as needed).
- **Postprocessors** (`output: true`) run after rules and only affect serialized attributes.
- Processor expressions gate execution; optional inputs trigger re-evaluation only when new data appears. The deadline is honoured; a timeout aborts remaining processors in that phase.

## Filters and exclusions

- **Rule filters** can bypass a rule, force monitor, or override the action to a custom value. Results are cached per filter instance.
- **Input filters** prune addresses (with optional key paths) for selected rules. Pruned inputs are invisible to matching and transformers.
- The combined `exclusion_policy` is consulted for every rule before evaluation to apply bypass/monitor/custom verdicts and input pruning.

## Module ordering and deadlines

Modules run in this fixed sequence (`module_category.hpp`). Each module sorts rules by verdict first (`block` before `monitor`) and then by source (Datadog vs. user) according to the policy below. A blocking rule stops the module; a monitor rule records a monitor verdict and lets evaluation continue.

1. **`network-acl`** *(non-expiring)*  
   - Ordering: Datadog before user.  
   - Deadline: ignored; always runs to completion.
2. **`authentication-acl`** *(non-expiring)*  
   - Ordering: Datadog before user.  
   - Deadline: ignored; always runs to completion.
3. **`custom-acl`**  
   - Ordering: user before Datadog.  
   - Deadline: enforced.
4. **`configuration`**  
   - Ordering: user before Datadog.  
   - Deadline: enforced.
5. **`business-logic`**  
   - Ordering: user before Datadog.  
   - Deadline: enforced.
6. **`rasp`**  
   - Ordering: Datadog before user.  
   - Deadline: enforced.
7. **`waf`** *(collection-based)*  
   - Collections: grouped by `tags.type`, verdict, and source in this order: user `block`, Datadog `block`, user `monitor`, Datadog `monitor`.  
   - Caching: each collection caches its verdict; collections already satisfied at the same or higher verdict are skipped on later evaluations.  
   - Execution: within a collection, rules run sequentially until one matches or the deadline expires. A `block` result stops remaining collections and modules; a `monitor` result records the verdict and moves to the next collection to gather more context.  
   - Deadline: enforced.

## Practical notes

- Only addresses seen as new trigger work; unchanged inputs can skip processors, filters, and rules.
- Non-expiring modules (`network-acl`, `authentication-acl`) ignore deadlines; all others honour them.
- Postprocessors still run after a rule-timeout so existing data can surface in attributes.
- Exclusions apply per rule right before condition evaluation, enabling fine-grained bypass/monitor/action overrides without editing rules.
