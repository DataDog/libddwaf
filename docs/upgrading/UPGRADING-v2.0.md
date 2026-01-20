# Upgrading libddwaf

The C API in libddwaf v2 has experienced a large number of changes, primarily around the creation and use of ddwaf_object. This guide aims to provide an overview of the changes required to upgrade from v1.x to v2.x; however it is recommended that the reader carefully read the [C API Reference](c-api/api.md) and [ddwaf.h](../../include/ddwaf.h).

## Summary
- Allocators have been introduced to all relevant API functions.
- The layout of `ddwaf_object` has dramatically changed to reduce the amount of memory required for a single object, which now only requires 16 bytes.
- Two new string types have been introduced:
  - Small string: a string of 14 bytes or less, stored within the object memory itself without extra allocations.
  - Literal string: a C string which should be treated as read-only and never freed.
- Object creation, access and destruction functions have been changed significantly, primarily to avoid the need for intermediate objects and due to the introduction of allocators.
- For consistency, `ddwaf_run` has been renamed to `ddwaf_context_eval`.
- Subcontexts have been introduced to replace ephemerals, their lifecycle and use are equivalent to that of the context.
- `ddwaf_config` has been removed:
  - Evaluation limits have been entirely removed, the caller must now enforce any relevant limits during serialisation.
  - Obfuscator regexes must now be provided through configuration: `{obfuscator: {key_regex: <value>, value_regex: <value>}}`.
  - The free function is no longer needed due to the introduction of allocators.

## Note on Allocators
The ownership of any allocated memory crossing the API boundary was one of the pain points of libddwaf v1. To fix this, v2 introduces allocators, which can be used to define the explicit ownership of the allocated memory.

Since the use of allocators is now required on many of the API functions, the migration examples will use the default allocator and will also include allocator destruction for illustrative purposes, as the destruction of the default allocator is a no-op.

However, note that other allocators are also available. See the [allocators document](../allocators.md) for more information on the different types of allocators available.

## 1. WAF instantiation: Removal of `ddwaf_config`

The main changes pertaining to WAF initialisation are the removal of `ddwaf_config`, as the evaluation limits have been entirely removed, in favour of user-controlled truncation, and the free function is no longer required due to the explicit memory ownership defined through allocators. As a consequence, instantiation through `ddwaf_init` has changed as follows:

**v1.x:**
```c
ddwaf_object ruleset = ...;
ddwaf_config config = ...;

ddwaf_object diagnostics;
ddwaf_handle handle = ddwaf_init(&ruleset, &config, &diagnostics);
```

**v2.x:**
```c
ddwaf_object ruleset = ...;

ddwaf_object diagnostics;
ddwaf_handle handle = ddwaf_init(&ruleset, &diagnostics);
```
When instantiating through the builder, the deprecation of `ddwaf_config` only affects `ddwaf_builder_init`.

**v1.x:**
```c
ddwaf_config config = ...;
ddwaf_builder builder = ddwaf_builder_init(&config);
```

**v2.x:**
```c
ddwaf_builder builder = ddwaf_builder_init();
```

Note that the `diagnostics` object is allocated with the default allocator and must be destroyed as follows:

```c
ddwaf_object_destroy(&diagnostics, ddwaf_get_default_allocator());
```
This applies to both `ddwaf_init` and to relevant `ddwaf_builder_*` functions.

## 2. WAF Context: Input & Output Allocators and Removal of Ephemerals

The WAF context lifecycle functions have changed significantly in v2 with the introduction of allocators and subcontexts as a replacement for ephemerals. In v1.x, `ddwaf_run` accepted separate persistent and ephemeral data parameters, while v2.x no longer provides ephemeral semantics, therefore only persistent data is provided.

### Context Initialization

During context initialisation, the caller must provide the output allocator which is used by the WAF to allocate memory for the result object, provided as an output parameter to `ddwaf_context_eval`. This allocator must remain valid for the lifetime of the context.

**v1.x:**
```c
ddwaf_handle handle = ...;

// Create context without allocator
ddwaf_context context = ddwaf_context_init(handle);
```

**v2.x:**
```c
ddwaf_handle handle = ...;

// Get allocator for output objects (result, diagnostics, etc.)
ddwaf_allocator output_alloc = ddwaf_get_default_allocator();

// Create context with output allocator
ddwaf_context context = ddwaf_context_init(handle, output_alloc);
```

### Context Evaluation

As mentioned, context evaluation no longer supports ephemeral data, consequently the main difference between v1.x and v2.x is the removal of `ddwaf_run`, which has been renamed to `ddwaf_context_eval`. Additionally, the allocator used to generate the input data must also be provided. Note that this allocator may be the same as the output allocator provided through `ddwaf_context_init` and it must also remain valid for the lifetime of the context.

**v1.x:**
```c
ddwaf_object persistent_data = ...;
ddwaf_object ephemeral_data = ...;
ddwaf_result result;

// Separate persistent and ephemeral parameters
DDWAF_RET_CODE code = ddwaf_run(context, &persistent_data, &ephemeral_data, &result, timeout);

// Process result
if (code == DDWAF_MATCH) {
    // Handle match...
}

// Free result (v1 used internal memory management)
ddwaf_result_free(&result);
```

**v2.x:**
```c
ddwaf_allocator input_alloc = ddwaf_get_default_allocator();

ddwaf_object data = ...;  // All data in single parameter
ddwaf_object result;

// Single data parameter, with allocator for input data
DDWAF_RET_CODE code = ddwaf_context_eval(context, &data, input_alloc, &result, timeout);

// Process result
if (code == DDWAF_MATCH) {
    // Handle match...
}

// Destroy result using the output allocator from ddwaf_context_init
ddwaf_object_destroy(&result, output_alloc);
```
### Multiple Evaluations Example

**v1.x:**
```c
ddwaf_context context = ddwaf_context_init(handle);

// First evaluation with persistent data
ddwaf_object persistent = ...;
ddwaf_result result1;
ddwaf_run(context, &persistent, NULL, &result1, timeout);
ddwaf_result_free(&result1);

// Second evaluation - persistent data still available
ddwaf_object more_data = ...;
ddwaf_result result2;
ddwaf_run(context, &more_data, NULL, &result2, timeout);
ddwaf_result_free(&result2);
```

**v2.x:**
```c
ddwaf_allocator alloc = ddwaf_get_default_allocator();
ddwaf_context context = ddwaf_context_init(handle, alloc);

// First evaluation
ddwaf_object data1 = ...;
ddwaf_object result1;
ddwaf_context_eval(context, &data1, alloc, &result1, timeout);
ddwaf_object_destroy(&result1, alloc);

// Second evaluation - data1 persists automatically
ddwaf_object data2 = ...;
ddwaf_object result2;
ddwaf_context_eval(context, &data2, alloc, &result2, timeout);
ddwaf_object_destroy(&result2, alloc);

// Both data1 and data2 are available for evaluation
```

## 3. WAF Subcontext: Replacement of Ephemerals

Subcontexts are the v2 replacement for ephemeral data. In v1.x, ephemeral data was passed separately to `ddwaf_run()` and was not stored in the context. In v2.x, subcontexts inherit all persistent data from their parent context but can be evaluated with data that doesn't persist beyond the subcontext's lifetime.

Note that in the current version, any context-related side-effects within the subcontext are not visible within the parent context.

**v1.x:**
```c
ddwaf_context context = ddwaf_context_init(handle);

// Store persistent data
ddwaf_object persistent = ...;
ddwaf_result result1;
ddwaf_run(context, &persistent, NULL, &result1, timeout);
ddwaf_result_free(&result1);

// Evaluate with ephemeral data
ddwaf_object ephemeral = ...;
ddwaf_result result2;
ddwaf_run(context, NULL, &ephemeral, &result2, timeout);
ddwaf_result_free(&result2);

// Ephemeral data is NOT stored, persistent data remains
```

**v2.x:**
```c
ddwaf_allocator alloc = ddwaf_get_default_allocator();
ddwaf_context context = ddwaf_context_init(handle, alloc);

// Store persistent data in context
ddwaf_object persistent = ...;
ddwaf_object result1;
ddwaf_context_eval(context, &persistent, alloc, &result1, timeout);
ddwaf_object_destroy(&result1, alloc);

// Create subcontext for ephemeral evaluation
ddwaf_subcontext subctx = ddwaf_subcontext_init(context);

// Evaluate with "ephemeral" data (inherits persistent data from parent)
ddwaf_object ephemeral = ...;
ddwaf_object result2;
ddwaf_subcontext_eval(subctx, &ephemeral, alloc, &result2, timeout);
ddwaf_object_destroy(&result2, alloc);

// Clean up subcontext
ddwaf_subcontext_destroy(subctx);

// No side-effects are visible to the context
```

### Subcontext Lifecycle

The subcontext follows the same lifecycle pattern as the context:

1. **Initialize**: `ddwaf_subcontext_init(context)` - Creates a subcontext from parent.
2. **Evaluate**: `ddwaf_subcontext_eval(subctx, data, alloc, result, timeout)` - Evaluates data which must be valid during the lifecycle of the subcontext.
3. **Destroy**: `ddwaf_subcontext_destroy(subctx)` - Cleans up subcontext.

Note that the subcontext inherits the output allocator of the parent context.

### Multiple Subcontexts

Multiple concurrent subcontexts may also be created from the same parent context, each of which defines the scope and lifecycle of the provided data:

**v2.x:**
```c
ddwaf_allocator alloc = ddwaf_get_default_allocator();
ddwaf_context context = ddwaf_context_init(handle, alloc);

// Store persistent data
ddwaf_object persistent = ...;
ddwaf_context_eval(context, &persistent, alloc, NULL, timeout);

// First subcontext with ephemeral data
ddwaf_subcontext subctx1 = ddwaf_subcontext_init(context);
ddwaf_object ephemeral1 = ...;
ddwaf_object result1;
ddwaf_subcontext_eval(subctx1, &ephemeral1, alloc, &result1, timeout);
ddwaf_object_destroy(&result1, alloc);
ddwaf_subcontext_destroy(subctx1);

// Second subcontext with different ephemeral data
ddwaf_subcontext subctx2 = ddwaf_subcontext_init(context);
ddwaf_object ephemeral2 = ...;
ddwaf_object result2;
ddwaf_subcontext_eval(subctx2, &ephemeral2, alloc, &result2, timeout);
ddwaf_object_destroy(&result2, alloc);
ddwaf_subcontext_destroy(subctx2);

// Both subcontexts inherited persistent data, but had independent ephemeral data
```

## 4. Object Creation: New API & Allocator support

The object creation API has changed extensively in v2 to support allocators and reduce memory overhead. All object creation functions now use the `ddwaf_object_set_*` naming pattern, and most require an allocator parameter.

### String Creation

The creation of a string object typically involves an allocation, therefore the allocator parameter is now required. Additionally, the string length is now always required to avoid potential issues with NUL characters.

**v1.x:**
```c
// Create string object (library allocates and copies)
ddwaf_object obj;
ddwaf_object_stringl(&obj, "hello world", 11);

// Free object
ddwaf_object_free(&obj);
```

**v2.x:**
```c
ddwaf_allocator alloc = ddwaf_get_default_allocator();

// Create string object with allocator
ddwaf_object obj;
ddwaf_object_set_string(&obj, "hello world", 11, alloc);

// Destroy object with allocator
ddwaf_object_destroy(&obj, alloc);
```

**Note**: Small strings (14 bytes or less) are automatically stored inline within the object itself without additional allocation.

#### Literal Strings

To address some existing use cases, v2 introduces a new literal string type which, upon destruction, never frees the associated buffer. This makes it easier to provide literals or interned strings as part of an object. The associated memory must be managed by the caller:

```c
ddwaf_object obj;

// String literal - no allocation, no copy
ddwaf_object_set_string_literal(&obj, "constant string", 15);
```

#### No-Copy Strings

It is still possible to create freeable strings by providing a pre-allocated/pre-initialised buffer, however note that the memory of the provided buffer must have been allocated with the same allocator used for object destruction, e.g. using `ddwaf_allocator_alloc`.

```c
ddwaf_object obj;

ddwaf_allocator alloc = ddwaf_get_default_allocator();

// Preallocated and preinitialised
char *str = (char*)ddwaf_allocator_alloc(alloc, 16, 1);
memcpy(str, "constant string", sizeof("constant string"));

// No-copy string - no allocation, no copy
ddwaf_object_set_string_nocopy(&obj, str, strlen(str));

// Destroy using the correct allocator
ddwaf_object_destroy(&obj, alloc);
```

### Numeric Types

**v1.x:**
```c
ddwaf_object obj;
ddwaf_object_unsigned(&obj, 42);
```

**v2.x:**
```c
ddwaf_object obj;
ddwaf_object_set_unsigned(&obj, 42);  // No allocator needed for numeric types
```

The same pattern applies to other numeric types:
- `ddwaf_object_signed()` → `ddwaf_object_set_signed()`
- `ddwaf_object_bool()` → `ddwaf_object_set_bool()`
- `ddwaf_object_float()` → `ddwaf_object_set_float()`


### Array Creation and Insertion

The array creation now requires both the expected size of the array (which may be 0) and a suitable allocator. Note that if the size of the array is incorrect, the container will still grow dynamically.

Additionally, the insertion API has changed to return a pointer to the inserted value, eliminating the need for intermediate objects.

**v1.x:**
```c
ddwaf_object array;
ddwaf_object_array(&array);

// Create value objects and add to array
ddwaf_object elem1;
ddwaf_object_string(&elem1, "first");
ddwaf_object_array_add(&array, &elem1);

ddwaf_object elem2;
ddwaf_object_string(&elem2, "second");
ddwaf_object_array_add(&array, &elem2);

ddwaf_object_free(&array);
```

**v2.x:**
```c
ddwaf_allocator alloc = ddwaf_get_default_allocator();

ddwaf_object array;
ddwaf_object_set_array(&array, 2, alloc);  // Initialize with capacity

// Insert and set value in one step
ddwaf_object_set_string(
    ddwaf_object_insert(&array, alloc),
    "first", 5, alloc);

ddwaf_object_set_string(
    ddwaf_object_insert(&array, alloc),
    "second", 6, alloc);

ddwaf_object_destroy(&array, alloc);
```


### Map Creation and Insertion

The map creation now requires both the expected size of the map (which may be 0) and a suitable allocator. Note that if the size of the map is incorrect, the container will still grow dynamically.

Additionally, the insertion API has changed to return a pointer to the inserted value, eliminating the need for intermediate objects.

**v1.x:**
```c
ddwaf_object map;
ddwaf_object_map(&map);

// Create value object, then add to map
ddwaf_object value;
ddwaf_object_string(&value, "username");
ddwaf_object_map_addl(&map, "user", 4, &value);

// Create another value and add
ddwaf_object value2;
ddwaf_object_unsigned(&value2, 12345);
ddwaf_object_map_addl(&map, "user_id", 7, &value2);

ddwaf_object_free(&map);
```

**v2.x:**
```c
ddwaf_allocator alloc = ddwaf_get_default_allocator();

ddwaf_object map;
ddwaf_object_set_map(&map, 2, alloc);  // Initialize with capacity

// Insert key and get pointer to value, then set value directly
ddwaf_object_set_string(
    ddwaf_object_insert_key(&map, "user", 4, alloc),
    "username", 8, alloc);

// Insert another key-value pair
ddwaf_object_set_unsigned(
    ddwaf_object_insert_key(&map, "user_id", 7, alloc),
    12345);

ddwaf_object_destroy(&map, alloc);
```
#### Insertion Variants

To cover different allocation and/or string management strategies, v2 provides multiple insertion functions for different use cases:

```c
ddwaf_allocator alloc = ddwaf_get_default_allocator();
ddwaf_object map;
ddwaf_object_set_map(&map, 3, alloc);

// Standard: copies the key string
ddwaf_object *val1 = ddwaf_object_insert_key(&map, "key1", 4, alloc);
ddwaf_object_set_string(val1, "value1", 6, alloc);

// Literal: key is read-only, not copied
ddwaf_object *val2 = ddwaf_object_insert_literal_key(&map, "key2", 4, alloc);
ddwaf_object_set_string(val2, "value2", 6, alloc);

// No-copy: key is externally managed (must be allocated with same allocator)
char *external_key = (char*)ddwaf_allocator_alloc(alloc, 5, 1);
memcpy(external_key, "key3", 5);
ddwaf_object *val3 = ddwaf_object_insert_key_nocopy(&map, external_key, 4, alloc);
ddwaf_object_set_string(val3, "value3", 6, alloc);

ddwaf_object_destroy(&map, alloc);
```

### Getter Functions

Object getter functions have been renamed for consistency:

**v1.x:**
```c
DDWAF_OBJ_TYPE type = ddwaf_object_type(&obj);
const char *str = ddwaf_object_get_string(&obj, &length);
uint64_t num = ddwaf_object_get_unsigned(&obj);
```

**v2.x:**
```c
DDWAF_OBJ_TYPE type = ddwaf_object_get_type(&obj);  // Renamed from ddwaf_object_type
const char *str = ddwaf_object_get_string(&obj, &length);  // Unchanged
uint64_t num = ddwaf_object_get_unsigned(&obj);  // Unchanged
```

The same pattern applies to all other getters.

### JSON Parsing

If you use `ddwaf_object_from_json()`, it now takes an allocator and the resulting object must be destroyed with the same allocator:

```c
ddwaf_allocator alloc = ddwaf_get_default_allocator();
ddwaf_object obj;

if (ddwaf_object_from_json(&obj, json, json_len, alloc)) {
    // use obj
    ddwaf_object_destroy(&obj, alloc);
}
```

### Complete Example: Building Request Data

**v1.x:**
```c
// Build a request data structure
ddwaf_object root;
ddwaf_object_map(&root);

ddwaf_object headers;
ddwaf_object_map(&headers);
ddwaf_object header_val;
ddwaf_object_string(&header_val, "application/json");
ddwaf_object_map_addl(&headers, "content-type", 12, &header_val);
ddwaf_object_map_addl(&root, "headers", 7, &headers);

ddwaf_object method;
ddwaf_object_string(&method, "POST");
ddwaf_object_map_addl(&root, "method", 6, &method);

ddwaf_object_free(&root);
```

**v2.x:**
```c
ddwaf_allocator alloc = ddwaf_get_default_allocator();

// Build a request data structure
ddwaf_object root;
ddwaf_object_set_map(&root, 2, alloc);

// Create nested headers map
ddwaf_object *headers = ddwaf_object_insert_key(&root, "headers", 7, alloc);
ddwaf_object_set_map(headers, 1, alloc);
ddwaf_object_set_string(
    ddwaf_object_insert_key(headers, "content-type", 12, alloc),
    "application/json", 16, alloc);

// Add method
ddwaf_object_set_string(
    ddwaf_object_insert_key(&root, "method", 6, alloc),
    "POST", 4, alloc);

ddwaf_object_destroy(&root, alloc);
```
