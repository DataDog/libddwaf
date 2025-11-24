# Upgrading libddwaf

This guide helps you migrate call sites of the C API from libddwaf 1.30.x to 2.0.0. It captures the high-impact breaking changes and illustrates them with snippets lifted from the integration tests that ship with 2.0.

## Migration Overview
- Evaluation limits, obfuscator regexes and the result free hook inside `ddwaf_config` have been removed. The core now enforces internal limits; only the obfuscator survives and must be supplied inside configurations when needed. All memory ownership should switch to the allocator API.
- `ddwaf_run` has been replaced by `ddwaf_context_eval`. Persistent and ephemeral maps are merged into a single input object, and every evaluation needs an allocator handle.
- `ddwaf_object_*` constructors now accept the allocator that owns the storage. Container insertion helpers were renamed, and getters migrated to a namespaced family (for example `ddwaf_object_get_type`).
- Context cloning exposed through `ddwaf_subcontext` and the allocator factories enable safe parallel use. Builders no longer take a `ddwaf_config*` argument.

## 1. Remove legacy runtime configuration

`ddwaf_config` and the macros `DDWAF_MAX_STRING_LENGTH`, `DDWAF_MAX_CONTAINER_DEPTH`, `DDWAF_MAX_CONTAINER_SIZE` and `DDWAF_RUN_TIMEOUT` disappeared. Evaluation limits are no longer user-configurable: libddwaf 2.0 ships with built-in safeguards and rejects oversized inputs internally. If you depended on the obfuscator settings, provide them through the configurations you load via `ddwaf_init` or `ddwaf_builder_add_or_update_config` (see `src/configuration/configuration_manager.cpp` for the supported `obfuscator` section). There is no replacement for the removed limits hooks.

## 2. Update initialization and evaluation

`ddwaf_init` now only expects the ruleset and an optional diagnostics object. Context creation requires an allocator, and the evaluation call takes a single request payload. The following example shows the common migration (compare `tests/integration/context/test.cpp` with its `1.30.0` counterpart):

```c
/* libddwaf 1.30.x */
ddwaf_config cfg{
    {.max_container_size = 256, .max_container_depth = 20, .max_string_length = 4096},
    {.key_regex = nullptr, .value_regex = nullptr},
    ddwaf_object_free
};

ddwaf_handle handle = ddwaf_init(&ruleset, &cfg, /*diagnostics=*/nullptr);
ddwaf_context ctx = ddwaf_context_init(handle);

ddwaf_object args = DDWAF_OBJECT_MAP;
ddwaf_object tmp;
ddwaf_object_map_add(&args, "value", ddwaf_object_string(&tmp, "rule2"));

ddwaf_object result;
DDWAF_RET_CODE rc = ddwaf_run(ctx, &args, /*ephemeral=*/nullptr, &result, timeout);
ddwaf_object_free(&result);
ddwaf_context_destroy(ctx);
ddwaf_destroy(handle);
```

```c
/* libddwaf 2.0.0 */
ddwaf_allocator alloc = ddwaf_get_default_allocator();
ddwaf_handle handle = ddwaf_init(&ruleset, /*diagnostics=*/nullptr);
ddwaf_context ctx = ddwaf_context_init(handle, alloc);

ddwaf_object args;
ddwaf_object_set_map(&args, 1, alloc);
ddwaf_object_set_string(
    ddwaf_object_insert_key(&args, "value", sizeof("value") - 1, alloc),
    "rule2", sizeof("rule2") - 1, alloc);

ddwaf_object result;
DDWAF_RET_CODE rc = ddwaf_context_eval(ctx, &args, alloc, &result, timeout);
ddwaf_object_destroy(&result, alloc);
ddwaf_context_destroy(ctx);
ddwaf_destroy(handle);
```

Key points:

- The request data passed to `ddwaf_context_eval` must remain valid until the context (or any subcontext) is destroyed because libddwaf can hold references to the objects you insert.
- You can create lightweight clones with `ddwaf_subcontext_init` when you need concurrent evaluations that share the same persistent state (see `tests/integration/context/test.cpp:508` for usage). Subcontexts reuse the allocator you gave to the parent.

## 3. Manage allocators explicitly

Memory ownership is now routed through `ddwaf_allocator`. Every object that can allocate memory has an overload that accepts an allocator, and any destruction (objects, contexts, results) must receive the same allocator.

- The default allocator is returned by `ddwaf_get_default_allocator()` and is used throughout the integration tests (`tests/integration/context/test.cpp`). The pointer is owned by libddwaf; do not pass it to `ddwaf_allocator_destroy`.
- Pool and monotonic allocators (`ddwaf_{synchronized,unsynchronized}_pool_allocator_init`, `ddwaf_monotonic_allocator_init`) reduce per-request allocations (`tests/integration/interface/allocator/test.cpp:16`).
- Provide your own hooks with `ddwaf_user_allocator_init`. The snippet below is adapted from `tests/integration/interface/allocator/test.cpp:539`:

```c
static void *counting_alloc(void *udata, size_t bytes, size_t alignment) { /* ... */ }
static void counting_free(void *udata, void *p, size_t bytes, size_t alignment) { /* ... */ }

counting_allocator state{};
ddwaf_allocator alloc =
    ddwaf_user_allocator_init(&counting_alloc, &counting_free, &state, /*udata_dtor=*/nullptr);

ddwaf_context ctx = ddwaf_context_init(handle, alloc);
/* ... build inputs and call ddwaf_context_eval ... */
ddwaf_context_destroy(ctx);
ddwaf_allocator_destroy(alloc);
```

Whenever you clone or destroy `ddwaf_object` instances (for instance via `ddwaf_object_clone`, `ddwaf_object_destroy`), pass the allocator that owns their memory.

## 4. Refactor `ddwaf_object` helpers

`ddwaf_object` changed from macro-based initialisers to allocator-aware setters and insertion helpers. The example below mirrors the change implemented in `tests/integration/context/test.cpp`.

```c
/* libddwaf 1.30.x */
ddwaf_object root = DDWAF_OBJECT_MAP;
ddwaf_object tmp, nested = DDWAF_OBJECT_MAP;
ddwaf_object_map_add(&nested, "key", ddwaf_object_string(&tmp, "rule3"));
ddwaf_object_map_add(&root, "value2", &nested);
```

```c
/* libddwaf 2.0.0 */
ddwaf_object root;
ddwaf_object_set_map(&root, 1, alloc);
ddwaf_object *nested = ddwaf_object_insert_key(&root, "value2", sizeof("value2") - 1, alloc);
ddwaf_object_set_map(nested, 1, alloc);
ddwaf_object_set_string(
    ddwaf_object_insert_key(nested, "key", sizeof("key") - 1, alloc),
    "rule3", sizeof("rule3") - 1, alloc);
```

Additional tips:

- Choose the string setter that matches your ownership model:
  - `ddwaf_object_set_string` copies the buffer.
  - `ddwaf_object_set_string_literal` marks the storage as caller-owned and never frees it.
  - `ddwaf_object_set_string_nocopy` keeps a pointer you manage.
- Arrays and maps are sized up-front (`ddwaf_object_set_array`, `ddwaf_object_set_map`) and filled with `ddwaf_object_insert` / `ddwaf_object_insert_key*`.
- Use the new getters (`ddwaf_object_get_type`, `ddwaf_object_get_size`, `ddwaf_object_get_string`, `ddwaf_object_get_bool`, etc.) together with `ddwaf_object_at_key` / `ddwaf_object_at_value` for iteration.

## 5. Builder workflow updates

`ddwaf_builder_init` no longer accepts a `ddwaf_config*`. Instantiate it without arguments and pass configurations that already carry optional obfuscator settings. Inputs still need to be destroyed with `ddwaf_object_destroy`. The integration test at `tests/integration/interface/builder/test.cpp` reflects the new pattern:

```c
ddwaf_builder builder = ddwaf_builder_init();
ddwaf_object config = yaml_to_object<ddwaf_object>(...);

ddwaf_builder_add_or_update_config(builder, "default", sizeof("default") - 1, &config, nullptr);
ddwaf_object_destroy(&config, alloc);

ddwaf_handle handle = ddwaf_builder_build_instance(builder);
/* ... */
ddwaf_builder_destroy(builder);
```

## 6. Quick reference for renamed helpers

- Initialisation and teardown:
  - `ddwaf_run` → `ddwaf_context_eval`
  - `ddwaf_object_free` → `ddwaf_object_destroy`
  - `ddwaf_context_init(handle)` → `ddwaf_context_init(handle, alloc)`
- Primitive setters:
  - `ddwaf_object_invalid/null` → `ddwaf_object_set_invalid/null`
  - `ddwaf_object_string*` → `ddwaf_object_set_string` / `*_literal` / `*_nocopy`
  - `ddwaf_object_unsigned/signed/float/bool` → `ddwaf_object_set_unsigned/signed/float/bool`
- Containers:
  - `ddwaf_object_array` / `ddwaf_object_map` → `ddwaf_object_set_array` / `ddwaf_object_set_map`
  - `ddwaf_object_array_add` → `ddwaf_object_insert`
  - `ddwaf_object_map_add*` → `ddwaf_object_insert_key`, `_insert_literal_key`, `_insert_key_nocopy`
- Accessors:
  - `ddwaf_object_type` / `size` / `length` → `ddwaf_object_get_type` / `get_size` / `get_length`
  - `ddwaf_object_get_key` / `get_index` → `ddwaf_object_at_key` / `ddwaf_object_at_value`

## 7. Reference examples in this repository

- `tests/integration/context/test.cpp` showcases context creation, evaluation, subcontexts and result handling with the new API.
- `tests/integration/interface/waf/test.cpp` exercises error handling, subcontexts and edge cases around `ddwaf_context_eval`.
- `tests/integration/interface/allocator/test.cpp` demonstrates the allocator factories and how to integrate a custom allocator.
- `tests/integration/interface/builder/test.cpp` covers the builder flow without `ddwaf_config`.

## Migration checklist

- [ ] Drop any attempt to configure evaluation limits; they are no longer exposed.
- [ ] If you rely on custom obfuscator patterns, embed them in the configurations you load.
- [ ] Update every `ddwaf_context_init` call to pass an allocator and replace `ddwaf_run` with `ddwaf_context_eval`.
- [ ] Swap out deprecated `ddwaf_object_*` constructors for the allocator-aware setters and ensure destruction happens through `ddwaf_object_destroy`.
- [ ] Review result-handling code for the new getter helpers and the unified request payload.
- [ ] If you provide custom allocators, migrate the hook to `ddwaf_user_allocator_init` and pair it with `ddwaf_allocator_destroy`.
- [ ] Drop the `ddwaf_config` argument when using the builder and ensure configurations are destroyed with the correct allocator.
