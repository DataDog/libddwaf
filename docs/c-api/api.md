# libddwaf C API Reference

This document describes the public C API of libddwaf.

## Table of Contents

- [Enumerations](#enumerations)
  - [DDWAF_OBJ_TYPE](#ddwaf-obj-type)
  - [DDWAF_RET_CODE](#ddwaf-ret-code)
  - [DDWAF_LOG_LEVEL](#ddwaf-log-level)
- [Type Definitions](#type-definitions)
- [Functions](#functions)
  - [Initialization/Destruction](#initializationdestruction)
  - [Builder](#builder)
  - [Context](#context)
  - [Subcontext](#subcontext)
  - [Allocator](#allocator)
  - [Object Creation](#object-creation)
  - [Object Inspection](#object-inspection)
  - [Object Container Operations](#object-container-operations)
  - [Object Type Checking](#object-type-checking)
  - [Utility](#utility)

---

## Enumerations

### DDWAF_OBJ_TYPE

Specifies the type of a ddwaf::object.

| Value | Code | Description |
|-------|------|-------------|
| `DDWAF_OBJ_INVALID` | `= 0` |  |
| `DDWAF_OBJ_NULL` | `= 0x01` |  |
| `DDWAF_OBJ_BOOL` | `= 0x02` |  |
| `DDWAF_OBJ_SIGNED` | `= 0x04` |  |
| `DDWAF_OBJ_UNSIGNED` | `= 0x06` |  |
| `DDWAF_OBJ_FLOAT` | `= 0x08` |  |
| `DDWAF_OBJ_STRING` | `= 0x10` |  |
| `DDWAF_OBJ_LITERAL_STRING` | `= 0x12` |  |
| `DDWAF_OBJ_SMALL_STRING` | `= 0x14` |  |
| `DDWAF_OBJ_ARRAY` | `= 0x20` |  |
| `DDWAF_OBJ_MAP` | `= 0x40` |  |

### DDWAF_RET_CODE

Codes returned by ddwaf_context_eval.

| Value | Code | Description |
|-------|------|-------------|
| `DDWAF_ERR_INTERNAL` | `= -3` |  |
| `DDWAF_ERR_INVALID_OBJECT` | `= -2` |  |
| `DDWAF_ERR_INVALID_ARGUMENT` | `= -1` |  |
| `DDWAF_OK` | `= 0` |  |
| `DDWAF_MATCH` | `= 1` |  |

### DDWAF_LOG_LEVEL

Internal WAF log levels, to be used when setting the minimum log level and cb.

| Value | Code | Description |
|-------|------|-------------|
| `DDWAF_LOG_TRACE` | `` |  |
| `DDWAF_LOG_DEBUG` | `` |  |
| `DDWAF_LOG_INFO` | `` |  |
| `DDWAF_LOG_WARN` | `` |  |
| `DDWAF_LOG_ERROR` | `` |  |
| `DDWAF_LOG_OFF` | `` |  |

---

## Type Definitions

### Handle Types

| Type | Definition |
|------|------------|
| `ddwaf_handle` | `typedef struct _ddwaf_handle* ddwaf_handle` |
| `ddwaf_context` | `typedef struct _ddwaf_context* ddwaf_context` |
| `ddwaf_subcontext` | `typedef struct _ddwaf_subcontext* ddwaf_subcontext` |
| `ddwaf_builder` | `typedef struct _ddwaf_builder* ddwaf_builder` |
| `ddwaf_allocator` | `typedef struct _ddwaf_allocator* ddwaf_allocator` |
| `ddwaf_alloc_fn_type` | `typedef void *() ddwaf_alloc_fn_type(void *, size_t, size_t)` |
| `ddwaf_free_fn_type` | `typedef void() ddwaf_free_fn_type(void *, void *, size_t, size_t)` |
| `ddwaf_udata_free_fn_type` | `typedef void() ddwaf_udata_free_fn_type(void *)` |
| `ddwaf_object` | `typedef union _ddwaf_object ddwaf_object` |

### ddwaf_log_cb

```c
ddwaf_log_cb)(DDWAF_LOG_LEVEL level, const char *function, const char *file, unsigned line, const char *message, uint64_t message_len)
```

Callback that libddwaf will call to relay messages to the binding.

**Parameters:**

- `level`: The logging level.
- `function`: The native function that emitted the message. (nonnull)
- `file`: The file of the native function that emmitted the message. (nonnull)
- `line`: The line where the message was emmitted.
- `message`: The size of the logging message. NUL-terminated
- `message_len`: The length of the logging message (excluding NUL terminator).

---

## Functions

### Initialization/Destruction

#### ddwaf_init

```c
ddwaf_handle ddwaf_init(const ddwaf_object * ruleset, ddwaf_object * diagnostics)
```

Initialize a ddwaf instance

**Parameters:**

- `ruleset`: ddwaf::object map containing rules, exclusions, rules_override and rules_data. (nonnull)
- `diagnostics`: Optional ruleset parsing diagnostics. (nullable)

**Returns:** Handle to the WAF instance or NULL on error.

> **Note:** If ruleset is NULL, the diagnostics object will not be initialised.

> **Note:** The deallocation of the diagnostics must be made with default allocator.

#### ddwaf_destroy

```c
void ddwaf_destroy(ddwaf_handle handle)
```

Destroy a WAF instance.

**Parameters:**

- `handle`: Handle to the WAF instance.

#### ddwaf_known_addresses

```c
const char *const * ddwaf_known_addresses(const ddwaf_handle handle, uint32_t * size)
```

Get an array of known (root) addresses used by rules, exclusion filters and processors. This array contains both required and optional addresses. A more accurate distinction between required and optional addresses is provided within the diagnostics.

**Parameters:**

- `handle`: Handle to the WAF instance.
- `size`: Output parameter in which the size will be returned. The value of size will be 0 if the return value is NULL.

**Returns:** NULL if empty, otherwise a pointer to an array with size elements.

> **Note:** This function is not thread-safe

> **Note:** The returned array should be considered invalid after calling ddwaf_destroy on the handle used to obtain it.

#### ddwaf_known_actions

```c
const char *const * ddwaf_known_actions(const ddwaf_handle handle, uint32_t * size)
```

Get an array of all the action types which could be triggered as a result of the current set of rules and exclusion filters.

**Parameters:**

- `handle`: Handle to the WAF instance.
- `size`: Output parameter in which the size will be returned. The value of size will be 0 if the return value is NULL.

**Returns:** NULL if empty, otherwise a pointer to an array with size elements.

> **Note:** This function is not thread-safe

> **Note:** The returned array should be considered invalid after calling ddwaf_destroy on the handle used to obtain it.

### Builder

#### ddwaf_builder_init

```c
ddwaf_builder ddwaf_builder_init()
```

Initialize an instace of the waf builder.

**Returns:** Handle to the builer instance or NULL on error.

> **Note:** If config is NULL, default values will be used

#### ddwaf_builder_add_or_update_config

```c
bool ddwaf_builder_add_or_update_config(ddwaf_builder builder, const char * path, uint32_t path_len, const ddwaf_object * config, ddwaf_object * diagnostics)
```

Adds or updates a configuration based on the given path, which must be a unique identifier for the provided configuration.

**Parameters:**

- `builder`: Builder to perform the operation on. (nonnull)
- `path`: A string containing the path of the configuration, this must uniquely identify the configuration. (nonnull)
- `path_len`: The length of the string contained within path.
- `config`: ddwaf::object map containing rules, exclusions, rules_override and rules_data. (nonnull)
- `diagnostics`: Optional ruleset parsing diagnostics. (nullable)

**Returns:** Whether the operation succeeded (true) or failed (false).

> **Note:** if any of the arguments are NULL, the diagnostics object will not be initialised.

> **Note:** The memory associated with the path, config and diagnostics must be freed by the caller.

> **Note:** The deallocation of the diagnostics must be made with default allocator.

> **Note:** This function is not thread-safe.

#### ddwaf_builder_remove_config

```c
bool ddwaf_builder_remove_config(ddwaf_builder builder, const char * path, uint32_t path_len)
```

Removes a configuration based on the provided path.

**Parameters:**

- `builder`: Builder to perform the operation on. (nonnull)
- `path`: A string containing the path of the configuration to be removed. (nonnull)
- `path_len`: The length of the string contained within path.

**Returns:** Whether the operation succeeded (true) or failed (false).

> **Note:** The memory associated with the path must be freed by the caller.

> **Note:** This function is not thread-safe.

#### ddwaf_builder_build_instance

```c
ddwaf_handle ddwaf_builder_build_instance(ddwaf_builder builder)
```

Builds a ddwaf instance based on the current set of configurations.

**Parameters:**

- `builder`: Builder to perform the operation on. (nonnull)

**Returns:** Handle to the new WAF instance or NULL if there was an error.

> **Note:** This function is not thread-safe.

#### ddwaf_builder_get_config_paths

```c
uint32_t ddwaf_builder_get_config_paths(ddwaf_builder builder, ddwaf_object * paths, const char * filter, uint32_t filter_len)
```

Provides an array of the currently loaded paths, optionally matching the regex provided in filter. In addition, the count is provided as the return value, allowing paths to be nullptr.

**Parameters:**

- `builder`: Builder to perform the operation on. (nonnull)
- `paths`: The object in which paths will be returned, as an array of strings. If NULL, only the count is provided. (nullable)
- `filter`: An optional string regex to filter the provided paths. The provided regular expression is used unanchored so matches can be found at any point within the path, any necessary anchors must be explicitly added to the regex. (nullable).
- `filter_len`: The length of the filter string (or 0 otherwise).

**Returns:** The total number of configurations loaded or, if provided, the number of those matching the filter.

> **Note:** This function is not thread-safe and the memory of the paths object must be freed by the caller using the default allocator.

#### ddwaf_builder_destroy

```c
void ddwaf_builder_destroy(ddwaf_builder builder)
```

Destroy an instance of the builder.

**Parameters:**

- `builder`: Builder to perform the operation on. (nonnull)

### Context

#### ddwaf_context_init

```c
ddwaf_context ddwaf_context_init(const ddwaf_handle handle, ddwaf_allocator output_alloc)
```

Context object to perform matching using the provided WAF instance.

**Parameters:**

- `handle`: Handle of the WAF instance containing the ruleset definition. (nonnull)
- `output_alloc`: Allocator used to serve output objects created during evaluation (nonnull)

**Returns:** Handle to the context instance.

> **Note:** The WAF instance needs to be valid for the lifetime of the context.

#### ddwaf_context_eval

```c
DDWAF_RET_CODE ddwaf_context_eval(ddwaf_context context, ddwaf_object * data, ddwaf_allocator alloc, ddwaf_object * result, uint64_t timeout)
```

Perform a matching operation on the provided data

**Parameters:**

- `context`: WAF context to be used in this run, this will determine the ruleset which will be used and it will also ensure that parameters are taken into account across runs (nonnull)
- `data`: (nonnull) Data on which to perform the pattern matching. This data will be stored by the context and used across multiple calls to this function or ddwaf_subcontext_eval. Once the context is destroyed, the user defined allocator will be used to free the data provided. Note that the data passed must be valid until the destruction of the context. The object must be a map of {string,
- `alloc`: (nullable) Allocator used to free the data provided. If NULL, the data will not be freed.
- `result`: (nullable) Object map containing the following items:
- events: an array of the generated events.
- actions: a map of the generated actions in the format: "{action type: { <parameter map> }, ...}"
- duration: an unsigned specifying the total runtime of the call in nanoseconds.
- timeout: whether there has been a timeout during the call.
- attributes: a map containing all derived objects in the format: {tag, value}
- keep: whether the data contained herein must override any transport sampling through the relevant mechanism. This structure must be freed by the caller using the output allocator provided through ddwaf_context_init. The object will contain all specified keys when the value returned by ddwaf_context_eval is either DDWAF_OK or DDWAF_MATCH and will be empty otherwise. IMPORTANT: This object is not allocated with the allocator passed in this call. It uses the allocator given to ddwaf_context_init instead.
- `timeout`: Maximum time budget in microseconds.

**Returns:** Return code of the operation.

**Return Values:**

- `DDWAF_ERR_INVALID_ARGUMENT`: The context is invalid, the data will not be freed.
- `DDWAF_ERR_INVALID_OBJECT`: The data provided didn't match the desired structure or contained invalid objects, the data will be freed by this function.
- `DDWAF_ERR_INTERNAL`: There was an unexpected error and the operation did not succeed. The state of the WAF is undefined if this error is produced and the ownership of the data is unknown. The result structure will not be filled if this error occurs.

#### ddwaf_context_destroy

```c
void ddwaf_context_destroy(ddwaf_context context)
```

Performs the destruction of the context, freeing the data passed to it through ddwaf_context_eval using the provided allocator during evaluation.

**Parameters:**

- `context`: Context to destroy. (nonnull)

### Subcontext

#### ddwaf_subcontext_init

```c
ddwaf_subcontext ddwaf_subcontext_init(ddwaf_context context)
```

Subcontext object to perform matching using the provided WAF instance.

**Parameters:**

- `context`: Context from which to derive this subcontext. (nonnull)

**Returns:** Handle to the subcontext instance.

#### ddwaf_subcontext_eval

```c
DDWAF_RET_CODE ddwaf_subcontext_eval(ddwaf_subcontext subcontext, ddwaf_object * data, ddwaf_allocator alloc, ddwaf_object * result, uint64_t timeout)
```

Perform a matching operation on the provided data

**Parameters:**

- `subcontext`: WAF subcontext to be used in this run, this will determine the ruleset which will be used and it will also ensure that parameters are taken into account across runs (nonnull)
- `data`: (nonnull) Data on which to perform the pattern matching. This data will be stored by the subcontext and used across multiple calls to this function. Once the subcontext is destroyed, the user defined allocator will be used to free the data provided. Note that the data passed must be valid until the destruction of the subcontext. The object must be a map of {string,
- `alloc`: (nullable) Allocator used to free the data provided. If NULL, the data will not be freed.
- `result`: (nullable) Object map containing the following items:
- events: an array of the generated events.
- actions: a map of the generated actions in the format: "{action type: { <parameter map> }, ...}"
- duration: an unsigned specifying the total runtime of the call in nanoseconds.
- timeout: whether there has been a timeout during the call.
- attributes: a map containing all derived objects in the format: {tag, value}
- keep: whether the data contained herein must override any transport sampling through the relevant mechanism. This structure must be freed by the caller and will contain all specified keys when the value returned by ddwaf_subcontext_eval is either DDWAF_OK or DDWAF_MATCH and will be empty otherwise. IMPORTANT: This object is not allocated with the allocator passed in this call. It uses the allocator given to ddwaf_context_init instead.
- `timeout`: Maximum time budget in microseconds.

**Returns:** Return code of the operation.

**Return Values:**

- `DDWAF_ERR_INVALID_ARGUMENT`: The subcontext is invalid, the data will not be freed.
- `DDWAF_ERR_INVALID_OBJECT`: The data provided didn't match the desired structure or contained invalid objects, the data will be freed by this function.
- `DDWAF_ERR_INTERNAL`: There was an unexpected error and the operation did not succeed. The state of the WAF is undefined if this error is produced and the ownership of the data is unknown. The result structure will not be filled if this error occurs.

#### ddwaf_subcontext_destroy

```c
void ddwaf_subcontext_destroy(ddwaf_subcontext subcontext)
```

Performs the destruction of the subcontext, freeing the data passed to it through ddwaf_subcontext_eval using the used-defined allocator.

**Parameters:**

- `subcontext`: subcontext to destroy. (nonnull)

### Allocator

#### ddwaf_get_default_allocator

```c
ddwaf_allocator ddwaf_get_default_allocator()
```

Returns the default allocator used by the library.

**Returns:** Allocator handle.

#### ddwaf_synchronized_pool_allocator_init

```c
ddwaf_allocator ddwaf_synchronized_pool_allocator_init()
```

Creates a thread-safe pool allocator. Allocations are served from internal pools sized by block class to reduce fragmentation and allocator overhead; memory freed via the corresponding ddwaf APIs is returned to the pools for reuse. This allocator can be shared across threads safely.

**Returns:** Allocator handle.

#### ddwaf_unsynchronized_pool_allocator_init

```c
ddwaf_allocator ddwaf_unsynchronized_pool_allocator_init()
```

Creates a pool allocator without internal synchronization. It provides the same pooling characteristics as the synchronized variant but with lower overhead. This allocator must not be used concurrently from multiple threads unless externally synchronized.

**Returns:** Allocator handle.

#### ddwaf_monotonic_allocator_init

```c
ddwaf_allocator ddwaf_monotonic_allocator_init()
```

Creates a monotonic (growing) allocator. Allocations are fast and never freed individually; all memory is reclaimed only when the allocator is destroyed. This allocator must not be used concurrently from multiple threads unless externally synchronized.

**Returns:** Allocator handle.

#### ddwaf_user_allocator_init

```c
ddwaf_allocator ddwaf_user_allocator_init(ddwaf_alloc_fn_type alloc_fn, ddwaf_free_fn_type free_fn, void * udata, ddwaf_udata_free_fn_type udata_free_fn)
```

Creates an allocator that forwards allocation and deallocation to user provided callbacks.

**Parameters:**

- `alloc_fn`: Allocation callback. It receives the opaque `udata`, the requested `size` and `alignment`, and must return a pointer meeting the alignment requirements or NULL on failure. (nonnull)
- `free_fn`: Deallocation callback. It receives the opaque `udata`, the pointer to free, and the original `size` and `alignment`. It must be able to free any pointer previously returned by `alloc_fn`. (nonnull)
- `udata`: Opaque user pointer forwarded to both callbacks; can be used to carry custom state. (nullable)
- `udata_free_fn`: User data destruction callback, used to perform any relevant destruction and reclamation operations on the provided user data.

**Returns:** Allocator handle.

#### ddwaf_allocator_alloc

```c
void * ddwaf_allocator_alloc(ddwaf_allocator alloc, size_t bytes, size_t alignment)
```

Allocates a block of memory from the given allocator with the requested alignment.

**Parameters:**

- `alloc`: Allocator to use for the allocation. (nonnull)
- `bytes`: Number of bytes to allocate.
- `alignment`: Required alignment in bytes; must be a power of two.

**Returns:** Pointer to the allocated memory or NULL on failure.

#### ddwaf_allocator_free

```c
void ddwaf_allocator_free(ddwaf_allocator alloc, void * p, size_t bytes, size_t alignment)
```

Releases a block of memory previously obtained via ddwaf_allocator_alloc from the same allocator.

**Parameters:**

- `alloc`: Allocator used for the original allocation. (nonnull)
- `p`: Pointer to the memory to free. (nonnull)
- `bytes`: Size in bytes of the original allocation.
- `alignment`: Alignment in bytes of the original allocation.

#### ddwaf_allocator_destroy

```c
void ddwaf_allocator_destroy(ddwaf_allocator alloc)
```

Destroys an allocator created by one of the ddwaf_*_allocator_init functions and releases any internal resources it holds.

**Parameters:**

- `alloc`: Allocator to destroy. (nonnull)

### Object Creation

#### ddwaf_object_set_invalid

```c
ddwaf_object * ddwaf_object_set_invalid(ddwaf_object * object)
```

Creates an invalid object.

**Parameters:**

- `object`: Object to perform the operation on. (nonnull)

**Returns:** A pointer to the passed object or NULL if the operation failed.

#### ddwaf_object_set_null

```c
ddwaf_object * ddwaf_object_set_null(ddwaf_object * object)
```

Creates an null object. Provides a different semantical value to invalid as it can be used to signify that a value is null rather than of an unknown type.

**Parameters:**

- `object`: Object to perform the operation on. (nonnull)

**Returns:** A pointer to the passed object or NULL if the operation failed.

#### ddwaf_object_set_string

```c
ddwaf_object * ddwaf_object_set_string(ddwaf_object * object, const char * string, uint32_t length, ddwaf_allocator alloc)
```

Creates an object from a string.

**Parameters:**

- `object`: Object to perform the operation on. (nonnull)
- `string`: String to initialise the object with, this string will be copied. (nonnull)
- `length`: Length of the string.
- `alloc`: Allocator to use for memory allocation. (nonnull)

**Returns:** A pointer to the passed object or NULL if the operation failed.

#### ddwaf_object_set_string_literal

```c
ddwaf_object * ddwaf_object_set_string_literal(ddwaf_object * object, const char * string, uint32_t length)
```

Creates an object from a literal string and its length.

**Parameters:**

- `object`: Object to perform the operation on. (nonnull)
- `string`: Literal string to initialise the object with, this string will not be copied and must remain valid for the lifetime of the object. (nonnull)
- `length`: Length of the string.

**Returns:** A pointer to the passed object or NULL if the operation failed.

#### ddwaf_object_set_string_nocopy

```c
ddwaf_object * ddwaf_object_set_string_nocopy(ddwaf_object * object, const char * string, uint32_t length)
```

Creates an object with the string pointer and length provided, without copying the string.

**Parameters:**

- `object`: Object to perform the operation on. (nonnull)
- `string`: String pointer to initialise the object with, this string will not be copied and must remain valid for the lifetime of the object. (nonnull)
- `length`: Length of the string.

**Returns:** A pointer to the passed object or NULL if the operation failed.

> **Note:** The provided string must have been allocated with the same allocator used with ddwaf_object_destroy.

#### ddwaf_object_set_unsigned

```c
ddwaf_object * ddwaf_object_set_unsigned(ddwaf_object * object, uint64_t value)
```

Creates an object using an unsigned integer (64-bit). The resulting object will contain an unsigned integer as opposed to a string.

**Parameters:**

- `object`: Object to perform the operation on. (nonnull)
- `value`: Integer to initialise the object with.

**Returns:** A pointer to the passed object or NULL if the operation failed.

#### ddwaf_object_set_signed

```c
ddwaf_object * ddwaf_object_set_signed(ddwaf_object * object, int64_t value)
```

Creates an object using a signed integer (64-bit). The resulting object will contain a signed integer as opposed to a string.

**Parameters:**

- `object`: Object to perform the operation on. (nonnull)
- `value`: Integer to initialise the object with.

**Returns:** A pointer to the passed object or NULL if the operation failed.

#### ddwaf_object_set_bool

```c
ddwaf_object * ddwaf_object_set_bool(ddwaf_object * object, bool value)
```

Creates an object using a boolean, the resulting object will contain a boolean as opposed to a string.

**Parameters:**

- `object`: Object to perform the operation on. (nonnull)
- `value`: Boolean to initialise the object with.

**Returns:** A pointer to the passed object or NULL if the operation failed.

#### ddwaf_object_set_float

```c
ddwaf_object * ddwaf_object_set_float(ddwaf_object * object, double value)
```

Creates an object using a double, the resulting object will contain a double as opposed to a string.

**Parameters:**

- `object`: Object to perform the operation on. (nonnull)
- `value`: Double to initialise the object with.

**Returns:** A pointer to the passed object or NULL if the operation failed.

#### ddwaf_object_set_array

```c
ddwaf_object * ddwaf_object_set_array(ddwaf_object * object, uint16_t capacity, ddwaf_allocator alloc)
```

Creates an array object, for sequential storage.

**Parameters:**

- `object`: Object to perform the operation on. (nonnull)
- `capacity`: Initial capacity of the array.
- `alloc`: Allocator to use for memory allocation. (nonnull)

**Returns:** A pointer to the passed object or NULL if the operation failed.

#### ddwaf_object_set_map

```c
ddwaf_object * ddwaf_object_set_map(ddwaf_object * object, uint16_t capacity, ddwaf_allocator alloc)
```

Creates a map object, for key-value storage.

**Parameters:**

- `object`: Object to perform the operation on. (nonnull)
- `capacity`: Initial capacity of the map.
- `alloc`: Allocator to use for memory allocation. (nonnull)

**Returns:** A pointer to the passed object or NULL if the operation failed.

#### ddwaf_object_from_json

```c
bool ddwaf_object_from_json(ddwaf_object * output, const char * json_str, uint32_t length, ddwaf_allocator alloc)
```

Creates a ddwaf_object from a JSON string. The JSON will be parsed and converted into the appropriate ddwaf_object structure, supporting all JSON types including objects, arrays, strings, numbers, booleans, and null values.

**Parameters:**

- `output`: Object to populate with the parsed JSON data. (nonnull)
- `json_str`: The JSON string to parse. (nonnull)
- `length`: Length of the JSON string.
- `alloc`: Allocator to use for memory allocation. (nonnull)

**Returns:** The success or failure of the operation.

> **Note:** The output object must be freed by the caller using ddwaf_object_free.

> **Note:** If parsing fails, the output object will be left in an undefined state.

> **Note:** The provided JSON string is owned by the caller.

### Object Inspection

#### ddwaf_object_get_type

```c
DDWAF_OBJ_TYPE ddwaf_object_get_type(const ddwaf_object * object)
```

Returns the type of the object.

**Parameters:**

- `object`: The object from which to get the type.

**Returns:** The object type of DDWAF_OBJ_INVALID if NULL.

#### ddwaf_object_get_size

```c
size_t ddwaf_object_get_size(const ddwaf_object * object)
```

Returns the size of the container object.

**Parameters:**

- `object`: The object from which to get the size.

**Returns:** The object size or 0 if the object is not a container (array, map).

#### ddwaf_object_get_length

```c
size_t ddwaf_object_get_length(const ddwaf_object * object)
```

Returns the length of the string object.

**Parameters:**

- `object`: The object from which to get the length.

**Returns:** The string length or 0 if the object is not a string.

#### ddwaf_object_get_string

```c
const char * ddwaf_object_get_string(const ddwaf_object * object, size_t * length)
```

Returns the string contained within the object.

**Parameters:**

- `object`: The object from which to get the string.
- `length`: Output parameter on which to return the length of the string, this parameter is optional / nullable.

**Returns:** The string of the object or NULL if the object is not a string.

#### ddwaf_object_get_unsigned

```c
uint64_t ddwaf_object_get_unsigned(const ddwaf_object * object)
```

Returns the uint64 contained within the object.

**Parameters:**

- `object`: The object from which to get the integer.

**Returns:** The integer or 0 if the object is not an unsigned.

#### ddwaf_object_get_signed

```c
int64_t ddwaf_object_get_signed(const ddwaf_object * object)
```

Returns the int64 contained within the object.

**Parameters:**

- `object`: The object from which to get the integer.

**Returns:** The integer or 0 if the object is not a signed.

#### ddwaf_object_get_float

```c
double ddwaf_object_get_float(const ddwaf_object * object)
```

Returns the float64 (double) contained within the object.

**Parameters:**

- `object`: The object from which to get the float.

**Returns:** The float or 0.0 if the object is not a float.

#### ddwaf_object_get_bool

```c
bool ddwaf_object_get_bool(const ddwaf_object * object)
```

Returns the boolean contained within the object.

**Parameters:**

- `object`: The object from which to get the boolean.

**Returns:** The boolean or false if the object is not a boolean.

### Object Container Operations

#### ddwaf_object_insert

```c
ddwaf_object * ddwaf_object_insert(ddwaf_object * array, ddwaf_allocator alloc)
```

Inserts a new object into an array object.

**Parameters:**

- `array`: Array in which to insert the object. (nonnull)
- `alloc`: Allocator to use for memory allocation. (nonnull)

**Returns:** A pointer to the newly inserted object or NULL if the operation failed.

#### ddwaf_object_insert_key

```c
ddwaf_object * ddwaf_object_insert_key(ddwaf_object * map, const char * key, uint32_t length, ddwaf_allocator alloc)
```

Inserts a new object into a map object, using a key.

**Parameters:**

- `map`: Map in which to insert the object. (nonnull)
- `key`: The key for indexing purposes, this string will be copied. (nonnull)
- `length`: Length of the key.
- `alloc`: Allocator to use for memory allocation. (nonnull)

**Returns:** A pointer to the newly inserted object or NULL if the operation failed.

#### ddwaf_object_insert_literal_key

```c
ddwaf_object * ddwaf_object_insert_literal_key(ddwaf_object * map, const char * key, uint32_t length, ddwaf_allocator alloc)
```

Inserts a new object into a map object, using a literal key.

**Parameters:**

- `map`: Map in which to insert the object. (nonnull)
- `key`: The key for indexing purposes, this string will not be copied. (nonnull)
- `length`: Length of the key.
- `alloc`: Allocator to use for memory allocation. (nonnull)

**Returns:** A pointer to the newly inserted object or NULL if the operation failed.

#### ddwaf_object_insert_key_nocopy

```c
ddwaf_object * ddwaf_object_insert_key_nocopy(ddwaf_object * map, const char * key, uint32_t length, ddwaf_allocator alloc)
```

Inserts a new object into a map object, using a key and its length, but without creating a copy of the key.

**Parameters:**

- `map`: Map in which to insert the object. (nonnull)
- `key`: The key for indexing purposes, this string will not be copied. (nonnull)
- `length`: Length of the key.
- `alloc`: Allocator to use for memory allocation. (nonnull)

**Returns:** A pointer to the newly inserted object or NULL if the operation failed.

> **Note:** The provided string must have been allocated with the same allocator used with ddwaf_object_destroy.

#### ddwaf_object_at_key

```c
const ddwaf_object * ddwaf_object_at_key(const ddwaf_object * object, size_t index)
```

Returns the key contained in the container at the given index.

**Parameters:**

- `object`: The container from which to extract the object.
- `index`: The position of the required object within the container.

**Returns:** The requested object or NULL if the index is out of bounds or the object is not a container.

#### ddwaf_object_at_value

```c
const ddwaf_object * ddwaf_object_at_value(const ddwaf_object * object, size_t index)
```

Returns the object contained in the container at the given index.

**Parameters:**

- `object`: The container from which to extract the object.
- `index`: The position of the required object within the container.

**Returns:** The requested object or NULL if the index is out of bounds or the object is not a container.

#### ddwaf_object_find

```c
const ddwaf_object * ddwaf_object_find(const ddwaf_object * object, const char * key, size_t length)
```

Returns the object within the given map with a key matching the provided one.

**Parameters:**

- `object`: The container from which to extract the object.
- `key`: A string representing the key to find.
- `length`: Length of the key.

**Returns:** The requested object or NULL if the key was not found or the object is not a container.

#### ddwaf_object_clone

```c
ddwaf_object * ddwaf_object_clone(const ddwaf_object * source, ddwaf_object * destination, ddwaf_allocator alloc)
```

Creates a deep copy of the source object into the destination object.

**Parameters:**

- `source`: The source object to clone from. (nonnull)
- `destination`: The destination object to clone into. (nonnull)
- `alloc`: Allocator to use for memory allocation. (nonnull)

**Returns:** A pointer to the destination object or NULL if the operation failed.

#### ddwaf_object_destroy

```c
void ddwaf_object_destroy(ddwaf_object * object, ddwaf_allocator alloc)
```

Frees the memory contained within the object.

**Parameters:**

- `object`: Object to destroy. (nonnull)
- `alloc`: Allocator to use for memory reclamation. (nonnull)

### Object Type Checking

#### ddwaf_object_is_invalid

```c
bool ddwaf_object_is_invalid(const ddwaf_object * object)
```

Returns true if the object is invalid.

**Parameters:**

- `object`: The object from which to get the type.

**Returns:** True if the object is invalid, false otherwise.

#### ddwaf_object_is_null

```c
bool ddwaf_object_is_null(const ddwaf_object * object)
```

Returns true if the object is null.

**Parameters:**

- `object`: The object from which to get the type.

**Returns:** True if the object is null, false otherwise.

#### ddwaf_object_is_bool

```c
bool ddwaf_object_is_bool(const ddwaf_object * object)
```

Returns true if the object is a boolean.

**Parameters:**

- `object`: The object from which to get the type.

**Returns:** True if the object is a boolean, false otherwise.

#### ddwaf_object_is_signed

```c
bool ddwaf_object_is_signed(const ddwaf_object * object)
```

Returns true if the object is a signed integer.

**Parameters:**

- `object`: The object from which to get the type.

**Returns:** True if the object is a signed integer, false otherwise.

#### ddwaf_object_is_unsigned

```c
bool ddwaf_object_is_unsigned(const ddwaf_object * object)
```

Returns true if the object is an unsigned integer.

**Parameters:**

- `object`: The object from which to get the type.

**Returns:** True if the object is an unsigned integer, false otherwise.

#### ddwaf_object_is_float

```c
bool ddwaf_object_is_float(const ddwaf_object * object)
```

Returns true if the object is a float.

**Parameters:**

- `object`: The object from which to get the type.

**Returns:** True if the object is a float, false otherwise.

#### ddwaf_object_is_string

```c
bool ddwaf_object_is_string(const ddwaf_object * object)
```

Returns true if the object is a string.

**Parameters:**

- `object`: The object from which to get the type.

**Returns:** True if the object is a string, false otherwise.

#### ddwaf_object_is_array

```c
bool ddwaf_object_is_array(const ddwaf_object * object)
```

Returns true if the object is an array.

**Parameters:**

- `object`: The object from which to get the type.

**Returns:** True if the object is an array, false otherwise.

#### ddwaf_object_is_map

```c
bool ddwaf_object_is_map(const ddwaf_object * object)
```

Returns true if the object is a map.

**Parameters:**

- `object`: The object from which to get the type.

**Returns:** True if the object is a map, false otherwise.

### Utility

#### ddwaf_get_version

```c
const char * ddwaf_get_version()
```

Return the version of the library

**Returns:** version Version string, note that this should not be freed

#### ddwaf_set_log_cb

```c
bool ddwaf_set_log_cb(ddwaf_log_cb cb, DDWAF_LOG_LEVEL min_level)
```

Sets the callback to relay logging messages to the binding

**Parameters:**

- `cb`: The callback to call, or NULL to stop relaying messages
- `min_level`: The minimum logging level for which to relay messages

**Returns:** whether the operation succeeded or not

> **Note:** This function is not thread-safe
