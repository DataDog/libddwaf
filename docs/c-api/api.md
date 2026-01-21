# libddwaf C API Reference

This document provides a complete reference for the public symbols exported through `include/ddwaf.h`. It covers every macro, enumeration, structure, type alias, callback signature, and function available to C or C++ callers embedding libddwaf 2.0.0 or later.

- All prototypes and types are defined in `include/ddwaf.h`.
- Functions follow the conventional C calling convention; when used from C++ be sure to include the header without wrapping it in your own `extern "C"`.
- Every function that receives or returns `ddwaf_object` instances requires the caller to respect the allocator ownership rules described in the *Allocator APIs* section.

---

## Preprocessor Macros

### `DDWAF_H`
Include guard that prevents the header from being processed multiple times. It has no behavioural meaning and should not be referenced directly.

### `DDWAF_OBJ_SSTR_SIZE`
Defines the storage capacity (in bytes) of the inline small-string buffer inside `_ddwaf_object_small_string`. The constant has the value `14`.

### `static_assert`
For C compilers that expose `_Static_assert` but not `static_assert`, the header maps `static_assert` to `_Static_assert`. Prefer the standard spelling in your own code.

---

## Enumerations

### `DDWAF_OBJ_TYPE`
Identifies the payload stored in a `ddwaf_object`.

| Value | Meaning |
| --- | --- |
| `DDWAF_OBJ_INVALID` | Sentinel for uninitialised or invalid objects. |
| `DDWAF_OBJ_NULL` | Represents an explicit `null` value. |
| `DDWAF_OBJ_BOOL` | Boolean payload. |
| `DDWAF_OBJ_SIGNED` | Signed 64-bit integer payload. |
| `DDWAF_OBJ_UNSIGNED` | Unsigned 64-bit integer payload. |
| `DDWAF_OBJ_FLOAT` | Double-precision floating point payload. |
| `DDWAF_OBJ_STRING` | Heap-allocated UTF-8 string. |
| `DDWAF_OBJ_LITERAL_STRING` | Non-owning string literal; libddwaf never frees it. |
| `DDWAF_OBJ_SMALL_STRING` | Inline UTF-8 string up to `DDWAF_OBJ_SSTR_SIZE`. |
| `DDWAF_OBJ_ARRAY` | Sequential container of `ddwaf_object`. |
| `DDWAF_OBJ_MAP` | Associative container of key/value `ddwaf_object` pairs. |

### `DDWAF_RET_CODE`
Return codes produced by the evaluation functions.

| Value | Meaning |
| --- | --- |
| `DDWAF_ERR_INTERNAL` (`-3`) | Unexpected internal error; context state is undefined. |
| `DDWAF_ERR_INVALID_OBJECT` (`-2`) | Input object did not match the expected structure. |
| `DDWAF_ERR_INVALID_ARGUMENT` (`-1`) | Call failed because an argument was not valid. |
| `DDWAF_OK` (`0`) | Call completed without generating matches or errors. |
| `DDWAF_MATCH` (`1`) | Call completed with at least one rule match. |

### `DDWAF_LOG_LEVEL`
Verbosity levels used by the logging subsystem.

`DDWAF_LOG_TRACE`, `DDWAF_LOG_DEBUG`, `DDWAF_LOG_INFO`, `DDWAF_LOG_WARN`, `DDWAF_LOG_ERROR`, `DDWAF_LOG_OFF`.

---

## Type Aliases and Callback Signatures

| Symbol | Description |
| --- | --- |
| `ddwaf_handle` | Opaque pointer to a WAF instance returned by `ddwaf_init` or `ddwaf_builder_build_instance`. |
| `ddwaf_context` | Opaque pointer representing an evaluation context obtained via `ddwaf_context_init`. |
| `ddwaf_subcontext` | Opaque pointer representing a lightweight clone of a context created with `ddwaf_subcontext_init`. |
| `ddwaf_builder` | Opaque pointer to the configuration builder returned by `ddwaf_builder_init`. |
| `ddwaf_allocator` | Opaque pointer identifying an allocator instance. |
| `ddwaf_alloc_fn_type` | Signature for custom allocation callbacks used with `ddwaf_user_allocator_init`. |
| `ddwaf_free_fn_type` | Signature for custom free callbacks passed to `ddwaf_user_allocator_init`. |
| `ddwaf_udata_free_fn_type` | Optional destructor for the user data passed to `ddwaf_user_allocator_init`. |

### `ddwaf_log_cb`

```c
typedef void (*ddwaf_log_cb)(
    DDWAF_LOG_LEVEL level,
    const char *function,
    const char *file,
    unsigned line,
    const char *message,
    uint64_t message_len);
```

Logging callback used by `ddwaf_set_log_cb`. The strings are null-terminated, and `message_len` excludes the terminator.

---

## Structure and Union Layouts

The header exposes the internal representation of `ddwaf_object` for interoperability. Always prefer the accessor helpers instead of touching fields directly unless you are implementing a low-level binding.

- Primitive wrappers: `_ddwaf_object_bool`, `_ddwaf_object_signed`, `_ddwaf_object_unsigned`, `_ddwaf_object_float`, `_ddwaf_object_string`, `_ddwaf_object_small_string`.
- Container wrappers: `_ddwaf_object_array`, `_ddwaf_object_map`, `_ddwaf_object_kv`.
- Tagged union: `_ddwaf_object` (aliased as `ddwaf_object`).

The type tag stored in `via` must match the helper you use; mixing the two is undefined behaviour.

---

## Library Lifecycle Functions

### `ddwaf_init`

```c
ddwaf_handle ddwaf_init(const ddwaf_object *ruleset, ddwaf_object *diagnostics);
```

Creates a WAF instance from a configuration object. The `ruleset` must be a map that contains the rule definitions, overrides, data, and exclusions. When supplied, `diagnostics` receives parser warnings and errors; destroy it with `ddwaf_object_destroy` after use. Returns `NULL` on failure.

### `ddwaf_destroy`

```c
void ddwaf_destroy(ddwaf_handle handle);
```

Destroys a WAF instance and releases its resources. Safe to call with `NULL`.

### `ddwaf_get_version`

```c
const char *ddwaf_get_version(void);
```

Returns a null-terminated string describing the libddwaf version. The pointer remains owned by the library.

### `ddwaf_set_log_cb`

```c
bool ddwaf_set_log_cb(ddwaf_log_cb cb, DDWAF_LOG_LEVEL min_level);
```

Installs a callback that receives libddwaf log messages at or above `min_level`. Passing `NULL` disables logging. Returns `false` if the logging system rejects the callback (for example, when called concurrently).

---

## Introspection Helpers

### `ddwaf_known_addresses`

```c
const char *const *ddwaf_known_addresses(const ddwaf_handle handle, uint32_t *size);
```

Returns the null-terminated root addresses referenced by the active configuration. The returned array is owned by libddwaf and becomes invalid after `ddwaf_destroy`.

### `ddwaf_known_actions`

```c
const char *const *ddwaf_known_actions(const ddwaf_handle handle, uint32_t *size);
```

Lists the action identifiers that may appear in evaluation results. Ownership rules mirror `ddwaf_known_addresses`.

---

## Context APIs

### `ddwaf_context_init`

```c
ddwaf_context ddwaf_context_init(const ddwaf_handle handle, ddwaf_allocator output_alloc);
```

Creates an evaluation context bound to a WAF instance. The `output_alloc` allocator is used to allocate result objects returned by `ddwaf_context_eval` and `ddwaf_subcontext_eval`. Returns `NULL` on allocation errors.

### `ddwaf_context_eval`

```c
DDWAF_RET_CODE ddwaf_context_eval(
    ddwaf_context context,
    ddwaf_object *data,
    ddwaf_allocator alloc,
    ddwaf_object *result,
    uint64_t timeout);
```

Evaluates a request payload. `data` must be a map keyed by address. The `alloc` parameter is the allocator used to free the `data` object after evaluation completes (if non-null). When `result` is non-null and the return code is `DDWAF_OK` or `DDWAF_MATCH`, it contains detailed events and metadata allocated with the `output_alloc` from `ddwaf_context_init`, and must be released with `ddwaf_object_destroy(result, output_alloc)`. The function enforces a microsecond timeout.

### `ddwaf_context_destroy`

```c
void ddwaf_context_destroy(ddwaf_context context);
```

Destroys a context and releases any persistent copies of request data using the allocator associated with the context.

---

## Subcontext APIs

### `ddwaf_subcontext_init`

```c
ddwaf_subcontext ddwaf_subcontext_init(ddwaf_context context);
```

Creates a lightweight clone that shares persistent state with its parent context. The subcontext inherits the allocator that was passed to `ddwaf_context_init`.

### `ddwaf_subcontext_eval`

```c
DDWAF_RET_CODE ddwaf_subcontext_eval(
    ddwaf_subcontext subcontext,
    ddwaf_object *data,
    ddwaf_allocator alloc,
    ddwaf_object *result,
    uint64_t timeout);
```

Evaluates request data against a subcontext using the same semantics as `ddwaf_context_eval`. The `alloc` parameter is used to free the `data` object. The `result` object, when populated, is allocated with the `output_alloc` from the parent context's `ddwaf_context_init` call and must be destroyed with that same allocator.

### `ddwaf_subcontext_destroy`

```c
void ddwaf_subcontext_destroy(ddwaf_subcontext subcontext);
```

Destroys the subcontext and releases any data cached within it.

---

## Builder APIs

Use the builder when you need to manage multiple configurations or build WAF instances incrementally.

### `ddwaf_builder_init`

```c
ddwaf_builder ddwaf_builder_init(void);
```

Allocates a new builder instance. Returns `NULL` on failure.

### `ddwaf_builder_add_or_update_config`

```c
bool ddwaf_builder_add_or_update_config(
    ddwaf_builder builder,
    const char *path,
    uint32_t path_len,
    const ddwaf_object *config,
    ddwaf_object *diagnostics);
```

Registers or refreshes a configuration identified by `path`. The `config` object is parsed immediately; on error the return value is `false` and `diagnostics` (when provided) contains parser feedback.

### `ddwaf_builder_remove_config`

```c
bool ddwaf_builder_remove_config(
    ddwaf_builder builder,
    const char *path,
    uint32_t path_len);
```

Deletes the configuration identified by `path`. Returns `false` if the path was not known.

### `ddwaf_builder_build_instance`

```c
ddwaf_handle ddwaf_builder_build_instance(ddwaf_builder builder);
```

Compiles the currently loaded configurations into a WAF instance. Returns `NULL` when compilation fails.

### `ddwaf_builder_get_config_paths`

```c
uint32_t ddwaf_builder_get_config_paths(
    ddwaf_builder builder,
    ddwaf_object *paths,
    const char *filter,
    uint32_t filter_len);
```

Counts the configurations present in the builder and optionally populates `paths` with their identifiers. If `filter` is non-null, only the paths matching the unanchored regular expression are reported.

### `ddwaf_builder_destroy`

```c
void ddwaf_builder_destroy(ddwaf_builder builder);
```

Releases all resources associated with the builder.

---

## Allocator APIs

### `ddwaf_get_default_allocator`

```c
ddwaf_allocator ddwaf_get_default_allocator(void);
```

Returns the allocator used internally by libddwaf. The handle is owned by the library and must not be destroyed.

### Pool and monotonic allocators

```c
ddwaf_allocator ddwaf_synchronized_pool_allocator_init(void);
ddwaf_allocator ddwaf_unsynchronized_pool_allocator_init(void);
ddwaf_allocator ddwaf_monotonic_allocator_init(void);
```

Factory functions that create dedicated allocators. Destroy them with `ddwaf_allocator_destroy` when no outstanding allocations remain.

### `ddwaf_user_allocator_init`

```c
ddwaf_allocator ddwaf_user_allocator_init(
    ddwaf_alloc_fn_type alloc_fn,
    ddwaf_free_fn_type free_fn,
    void *udata,
    ddwaf_udata_free_fn_type udata_free_fn);
```

Wraps user-provided allocation routines in a libddwaf-compatible allocator. When `udata_free_fn` is non-null it is called automatically during `ddwaf_allocator_destroy`.

### Allocation helpers

```c
void *ddwaf_allocator_alloc(ddwaf_allocator alloc, size_t bytes, size_t alignment);
void ddwaf_allocator_free(ddwaf_allocator alloc, void *p, size_t bytes, size_t alignment);
void ddwaf_allocator_destroy(ddwaf_allocator alloc);
```

Low-level allocation routines. The `alloc` argument must be the same handle returned by the allocator factory. `ddwaf_allocator_destroy` is a no-op for the default allocator but must be called for user-created allocators once all objects have been released.

---

## Object Construction Helpers

Each helper returns the pointer passed in on success and `NULL` on failure unless stated otherwise.

```c
ddwaf_object *ddwaf_object_set_invalid(ddwaf_object *object);
ddwaf_object *ddwaf_object_set_null(ddwaf_object *object);
ddwaf_object *ddwaf_object_set_string(ddwaf_object *object, const char *string, uint32_t length, ddwaf_allocator alloc);
ddwaf_object *ddwaf_object_set_string_literal(ddwaf_object *object, const char *string, uint32_t length);
ddwaf_object *ddwaf_object_set_string_nocopy(ddwaf_object *object, const char *string, uint32_t length);
ddwaf_object *ddwaf_object_set_unsigned(ddwaf_object *object, uint64_t value);
ddwaf_object *ddwaf_object_set_signed(ddwaf_object *object, int64_t value);
ddwaf_object *ddwaf_object_set_bool(ddwaf_object *object, bool value);
ddwaf_object *ddwaf_object_set_float(ddwaf_object *object, double value);
ddwaf_object *ddwaf_object_set_array(ddwaf_object *object, uint16_t capacity, ddwaf_allocator alloc);
ddwaf_object *ddwaf_object_set_map(ddwaf_object *object, uint16_t capacity, ddwaf_allocator alloc);
```

- The `_string_literal` variant never copies the buffer; the caller must guarantee its lifetime exceeds that of the object.
- The `_string_nocopy` variant assumes the buffer was allocated by the same allocator that will be used during destruction.
- Arrays and maps allocate storage with the capacity supplied; call `ddwaf_object_insert*` to populate them.

### Container insertion and JSON parsing

```c
ddwaf_object *ddwaf_object_insert(ddwaf_object *array, ddwaf_allocator alloc);
ddwaf_object *ddwaf_object_insert_key(ddwaf_object *map, const char *key, uint32_t length, ddwaf_allocator alloc);
ddwaf_object *ddwaf_object_insert_literal_key(ddwaf_object *map, const char *key, uint32_t length, ddwaf_allocator alloc);
ddwaf_object *ddwaf_object_insert_key_nocopy(ddwaf_object *map, const char *key, uint32_t length, ddwaf_allocator alloc);
bool ddwaf_object_from_json(ddwaf_object *output, const char *json_str, uint32_t length, ddwaf_allocator alloc);
```

Insertion helpers expand array or map containers by one element and return the slot to be filled. `ddwaf_object_from_json` parses a JSON document into a `ddwaf_object`; destroy the result with `ddwaf_object_destroy`.

---

## Object Accessors and Predicates

### Introspection

```c
DDWAF_OBJ_TYPE ddwaf_object_get_type(const ddwaf_object *object);
size_t ddwaf_object_get_size(const ddwaf_object *object);
size_t ddwaf_object_get_length(const ddwaf_object *object);
const char *ddwaf_object_get_string(const ddwaf_object *object, size_t *length);
uint64_t ddwaf_object_get_unsigned(const ddwaf_object *object);
int64_t ddwaf_object_get_signed(const ddwaf_object *object);
double ddwaf_object_get_float(const ddwaf_object *object);
bool ddwaf_object_get_bool(const ddwaf_object *object);
```

Retrieve metadata or scalar values from an object. When the object is not of the expected type, the returned value is zero or `NULL`.

### Container lookup

```c
const ddwaf_object *ddwaf_object_at_key(const ddwaf_object *object, size_t index);
const ddwaf_object *ddwaf_object_at_value(const ddwaf_object *object, size_t index);
const ddwaf_object *ddwaf_object_find(const ddwaf_object *object, const char *key, size_t length);
```

`ddwaf_object_at_key` returns the key object for the entry at `index` when iterating over a map (arrays do not expose keys). `ddwaf_object_at_value` returns the corresponding value object. `ddwaf_object_find` performs a direct lookup by key and returns the associated value.

### Cloning

```c
ddwaf_object *ddwaf_object_clone(
    const ddwaf_object *source,
    ddwaf_object *destination,
    ddwaf_allocator alloc);
```

Performs a deep copy of `source` into `destination`, allocating any necessary storage from `alloc`. The destination must be destroyed with the same allocator once it is no longer needed.

### Type predicates

```c
bool ddwaf_object_is_invalid(const ddwaf_object *object);
bool ddwaf_object_is_null(const ddwaf_object *object);
bool ddwaf_object_is_bool(const ddwaf_object *object);
bool ddwaf_object_is_signed(const ddwaf_object *object);
bool ddwaf_object_is_unsigned(const ddwaf_object *object);
bool ddwaf_object_is_float(const ddwaf_object *object);
bool ddwaf_object_is_string(const ddwaf_object *object);
bool ddwaf_object_is_array(const ddwaf_object *object);
bool ddwaf_object_is_map(const ddwaf_object *object);
```

Convenience wrappers that compare the object type to the respective category.

### Destruction

```c
void ddwaf_object_destroy(ddwaf_object *object, ddwaf_allocator alloc);
```

Reclaims any memory owned by the object. Always pass the allocator that was used to build it.

---

## Thread Safety and Lifetime Notes

- WAF handles are thread-safe for read operations (`ddwaf_context_init`, `ddwaf_known_addresses`, `ddwaf_known_actions`). Builder operations and handle destruction are not thread-safe with respect to these read operations.
- Allocation routines inherit the thread-safety guarantees of the allocator instance returned by the corresponding factory.
- Objects created with `_string_literal` or `_insert_literal_key` expect the referenced buffers to outlive the object or to remain immutable.
- Result objects returned by evaluation functions remain valid until destroyed. Never reuse them across calls without destroying or reinitialising them first.

This reference mirrors the API shipped in `include/ddwaf.h` and should be kept in sync whenever the header changes.
