# Upgrading libddwaf

## Upgrading from `1.12.0` to `1.13.0`

### Interface changes

For historical reasons, the integer object constructors (signed, unsigned) didn't generate an object of a numerical type, but rather a string. This has been a source of confusion and, with the changes required for schema extraction, these functions have now been adjusted to provide the same semantics as all other constructors, meaning that they now generate a numerical object type rather than a string.

Similarly, the numerical object constructors suffixed with `_force` have now been renamed to more accurately express their meaning:
```cpp
ddwaf_object* ddwaf_object_string_from_unsigned(ddwaf_object *object, uint64_t value);
ddwaf_object* ddwaf_object_string_from_signed(ddwaf_object *object, int64_t value);
```

To summarize:
- `ddwaf_object_signed` has been renamed to `ddwaf_object_string_from_signed`
- `ddwaf_object_unsigned` has been renamed to `ddwaf_object_string_from_unsigned`
- `ddwaf_object_signed_force` has been renamed to `ddwaf_object_signed`
- `ddwaf_object_unsigned_force` has been renamed to `ddwaf_object_unsigned`

### New object types

Alongside the schema extraction preprocessor, two new types have been introduced to ensure a more accurate and complete schema can be produced. These are Float and Null, the former for completeness of the numerical types and the latter for its semantical value which, in the context of schema extraction, differs from invalid in that it signifies a null value rather than an unknown type.

Library bindings with a mirrored definition of `ddwaf_object` should now include the `f64` field of type `double` to the value union:

```cpp
...
    union
    {
        const char* stringValue;
        uint64_t uintValue;
        int64_t intValue;
        ddwaf_object* array;
        bool boolean;
        double f64;
    };
...
```
This new field breaks with the naming convention of the current `ddwaf_object` definition, however it matches the naming convention of the future `ddwaf_object` that will be included in version 2.0.

Similarly, those bindings mirroring the enum types should also include the two new types:
```cpp
...
    // 64-bit float (or double) type
    DDWAF_OBJ_FLOAT    = 1 << 6,
    // Null type, only used for its semantical value
    DDWAF_OBJ_NULL    = 1 << 7,
...
```

These new types can now be created with their corresponding `ddwaf_object` constructors:
```cpp
ddwaf_object* ddwaf_object_null(ddwaf_object *object);
ddwaf_object* ddwaf_object_float(ddwaf_object *object, double value);
```

And finally, float values can also be accessed with the corresponding getter:
```cpp
double ddwaf_object_get_float(const ddwaf_object *object);
```

### Derivatives in `ddwaf_result`

Preprocessors in general and, more specifically the schema extraction preprocessor, now generate objects which need to be provided to the caller of `ddwaf_run`. For this reason, a new field has been introduced to `ddwaf_result` called `derivatives`, containing generated objects:
```cpp
struct _ddwaf_result
{
...
    /** Map containing all derived objects in the format (address, value) **/
    ddwaf_object derivatives;
    /** Total WAF runtime in nanoseconds **/
    uint64_t total_runtime;
};
```
This new field is an object which will always contain a map of generated addresses and their arbitrary-type value, for example:

```json
{
    "server.request.body.schema": [[8],{"len":2}]
}
```

This object is freed with `ddwaf_result_free`, so necessary conversions or copies should be performed before disposing of the result structure.

### New Linux builds 

The new linux builds are currently released alongside the legacy linux builds for `aarch64` and `x86_64` and will not replace them for the time being. In addition to the two mentioned architectures, support for `i386` and `armv7` has also been included. The new archives follow a different, more standarised, naming convention which consists of `libddwaf-<version>-<arch><sub>-<sys>-<env>[-<hash>].tar.gz` with `sys` being always `linux` and `env` always `musl`, which results in the following package names:
- `libddwaf-1.13.0-x86_64-linux-musl.tar.gz`
- `libddwaf-1.13.0-aarch64-linux-musl.tar.gz`
- `libddwaf-1.13.0-i386-linux-musl.tar.gz`
- `libddwaf-1.13.0-armv7-linux-musl.tar.gz`

Which are not to be confused with the legacy builds, with the following package names:
- `libddwaf-1.13.0-linux-x86_64.tar.gz`
- `libddwaf-1.13.0-linux-aarch64.tar.gz`
  
The contents of each package is essentially equivalent to the legacy builds, however the new static builds do not provide or require a separate static `libc++` package as all static libraries have been packaged together within `libddwaf.a`.

The new builds use version 16 of `libc++` and friends, compiled against musl `1.2.4` using `clang-16`.

## Upgrading from `1.10.0` to `1.11.0`

Version `1.11.0` introduces a number of breaking changes to the API, notably:
- The `ruleset_info` structure has been replaced with a `ddwaf_object`, providing many more parsing diagnostics.
- The `ddwaf_result::data` field containing the resulting events in JSON format has been replaced with a `ddwaf_object` containing an array of events in `ddwaf_result::events`.
- The actions array has also been replaced by a `ddwaf_object` containing an array of strings.

Finally it also introduces support for per-input transformers which, while not a breaking change, will also be explained here.

### Ruleset Parsing diagnostics

Before `1.11.0`, basic diagnostics were provided through the `ddwaf_ruleset_info` structure, with the following definition:

```c
struct _ddwaf_ruleset_info
{
    /** Number of rules successfully loaded **/
    uint16_t loaded;
    /** Number of rules which failed to parse **/
    uint16_t failed;
    /** Map from an error string to an array of all the rule ids for which
     *  that error was raised. {error: [rule_ids]} **/
    ddwaf_object errors;
    /** Ruleset version **/
    const char *version;
};
```
In this definition, `ddwaf_ruleset_info::errors` was always a map containing errors as keys and an array of rule IDs as values; this field was used as a compressed view of the rules which couldn't be parsed and the relevant parsing errors, e.g.:

```json
"errors": {
  "missing key 'type'": [
    "blk-001-002"
  ]
}
```
With the introduction of exclusion filters, rule overrides, custom rules and, to a lesser extent, rule data, the current set of diagnostics was not enough to provide an accurate understanding of the parsing result. For this reason, the `ddwaf_ruleset_info` structure has been deprecated in favour of `ddwaf_object`. This object is now provided as a parameter to both `ddwaf_init` and `ddwaf_update`, and it should be allocated by the caller (e.g. stack-allocated as a local variable):
```c
ddwaf_handle ddwaf_init(const ddwaf_object *ruleset, const ddwaf_config* config, ddwaf_object *diagnostics);
ddwaf_handle ddwaf_update(ddwaf_handle handle, const ddwaf_object *ruleset, ddwaf_object *diagnostics);
```
The use of a `ddwaf_object` instead of a dedicated structure has a number of advantages and disadvantages, however it allows us to add more diagnostics in a backwards-compatible manner, without breaking the ABI. This translates in having the ability to automatically provide diagnostics for new high-level features without breaking existing libraries. 

The new diagnostics object is always a map containing the following:
- A map per high-level feature parsed (e.g. rules, custom rules, exclusions, etc), with the same key as said high-level feature.
- Other metadata if present in the ruleset, such as the ruleset version.

Providing the WAF with a complete ruleset typically results in a `ddwaf_object` with the following contents:
```json
{
  "custom_rules": {...},
  "exclusions": {...},
  "rules": {...},
  "rules_data": {...},
  "rules_override": {...},
  "ruleset_version": "1.7.0"
}
```
The definition of the map provided for each high-level feature is generic, the complete schema can be found [here](schema/diagnostics.json). The expected keys when the high-level feature couldn't be parsed are the following:
- `error`: this key contains a string indicating the error which prevented the relevant top-level key from being parsed and will only be present in this situation. Since this key represents a critical parsing error, no other keys are provided when this one is present.

An example ruleset in which the `rules_data` key had the wrong type could result in the following diagnostics:
```json
{
  "rules_data": {
    "error": "bad cast, expected 'array', obtained 'map'"
  }
}
```
The expected keys when the high-level feature was parsed successfully are the following:
- `loaded`: the value associated with this key is always an array of IDs and represents those elements that were loaded successfully. If the relevant feature definition does not have an ID (e.g. rule overrides), it'll contain the index within the parsed array in the form `index:x` with `x` representing the numerical index. 
- `failed`: the value provided with this key is exactly the same as with the `loaded` key, but these are instead elements which couldn't be loaded. If the relevant element or feature definition lacks an ID, the `index:x` format is used instead.
- `errors`: for backwards compatibility, this key contains a compressed map of errors, each containing the list of IDs which failed with said error.

An example ruleset with all valid entries could look as follows:
```json
{
  "custom_rules": {
    "loaded": [
      "a45b55fc-5b57-4002-90bf-58cdf296124c"
    ],
    "failed": [],
    "errors": {}
  },
  "rules_override": {
    "loaded": [
      "index:0",
      "index:1"
    ],
    "failed": [],
    "errors": {}
  }
}
```
An example ruleset with some invalid entries could look as follows:
```json
{
  "exclusions": {
    "loaded": [
      "1d058b7b-9b35-4a01-9b60-74c9a2a3bd78",
    ],
    "failed": [
      "index:2"
    ],
    "errors": {
      "missing key 'id'": [
        "index:2"
      ]
    }
  },
  "rules": {
    "loaded": [
      "blk-001-001"
    ],
    "failed": [
      "blk-001-002"
    ],
    "errors": {
      "missing key 'conditions'": [
        "blk-001-002"
      ]
    }
  },
  "rules_override": {
    "loaded": [
      "index:1"
    ],
    "failed": [
      "index:0"
    ],
    "errors": {
      "invalid type 'map' for key 'rules_target', expected 'array'": [
        "index:0"
      ]
    }
  },
  "ruleset_version": "1.7.0"
}
```
Note that in this example, an exclusion filter lacking a valid ID was also represented using the `index:x` notation.

### Adding diagnostics to the root span

In previous versions of the WAF, each field of the `ddwaf_ruleset_info` structure was added to the root span either as a meta tag or a metric as shown in the example below:
```cpp
ddwaf_ruleset_info info;
auto handle = ddwaf_init(rule, &config, &info);

root_span.metrics["_dd.appsec.event_rules.loaded"] = info.loaded;
root_span.metrics["_dd.appsec.event_rules.error_count"] = info.failed;
root_span.meta["_dd.appsec.event_rules.errors"] = object_to_json(info.errors);
root_span.meta["_dd.appsec.event_rules.version"] = info.version;   

ddwaf_ruleset_info_free(&info);
```
While the new diagnostics provide much more information, for backwards compatibility, rule metrics and errors still need to be reported through the root span, the following example shows a simple mechanism to traverse the diagnostics object:

```cpp
ddwaf_object diagnostics;
ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
ddwaf_object_free(&rule);
ddwaf_destroy(handle);

const auto *rules = find_object(&diagnostics, "rules");
if (rules != nullptr) {
    size_t index = 0;
    const ddwaf_object *node = nullptr;
    while ((node = ddwaf_object_get_index(rules, index++)) != nullptr) {
        std::string_view node_key = ddwaf_object_get_key(node, nullptr);

        if (node_key == "loaded") {
            root_span.metrics["_dd.appsec.event_rules.loaded"] = ddwaf_object_size(node);
        } else if (node_key =="failed") {
            root_span.metrics["_dd.appsec.event_rules.error_count"] = ddwaf_object_size(node);
        }  else if (node_key == "errors") {
            root_span.meta["_dd.appsec.event_rules.errors"] = object_to_yaml(*node);
        } else if (node_key == "ruleset_version") {
            root_span.meta["_dd.appsec.event_rules.version"] = ddwaf_object_get_string(node, nullptr);
        }
    }
}
ddwaf_object_free(&diagnostics);
```
Note that it might also be prudent to check for the `error` key before attempting to traverse the map, as the relevant keys won't be available in such case.

A suitable definition of `find_object` could be the following:
```cpp
const ddwaf_object *find_object(const ddwaf_object *map, std::string_view key) {
    size_t index = 0;
    const ddwaf_object *node = nullptr;
    while ((node = ddwaf_object_get_index(map, index++)) != nullptr) {
        std::string_view node_key = ddwaf_object_get_key(node, nullptr);
        if (key == node_key) {
            return node;
        }
    }
    return nullptr;
}
```
#### Events & actions as `ddwaf_object`

The outcome of a WAF run is provided as part of the `ddwaf_result` structure, which before `1.11.0` had the following definition:

```c
struct _ddwaf_result
{
    /** Whether there has been a timeout during the operation **/
    bool timeout;
    /** Run result in JSON format **/
    const char* data;
    /** Actions array and its size **/
    struct _ddwaf_result_actions {
        char **array;
        uint32_t size;
    } actions;
    /** Total WAF runtime in nanoseconds **/
    uint64_t total_runtime;
};
```
In particular, the `data` field was a JSON-serialized string containing an array of events. Unfortunately, since WAF users typically call the WAF multiple times within the same context, extracting a meaningful result requires stitching multiple JSON strings together. Similarly, truncating the resulting JSON array to comply with trace limits also requires deserializing, performing changes and reserialising. 

To work around these problems, the new version of the WAF doesn't report events as a JSON string, but rather as a `ddwaf_object` containing an array of events, with exactly the same definition as the previously provided JSON string. This new object resides in `ddwaf_result::events` rather than `ddwaf_result::data`, as it signifies more clearly the purpose of the field.
```c
struct _ddwaf_result
{
    /** Whether there has been a timeout during the operation **/
    bool timeout;
    /** Array of events generated, this is guaranteed to be an array **/
    ddwaf_object events;
    /** Array of actions generated, this is guaranteed to be an array **/
    ddwaf_object actions;
    /** Total WAF runtime in nanoseconds **/
    uint64_t total_runtime;
};
```
With this new definition, the caller now has the responsibility of serializing events into JSON.

Similarly, actions are now also a `ddwaf_object` instead of a struct representing an array. Iterating through the old structure could be done as follows:

```c
ddwaf_result res;
for (unsigned i = 0; i < res.actions.size; ++i) {
    printf("%s", res.actions.array[i]);
}
```
The same can now be done as follows:
```c
ddwaf_result res;
for (unsigned i = 0; i < ddwaf_object_size(&res.actions); ++i) {
    const ddwaf_object *node = ddwaf_object_get_index(&res.actions, i);
    printf("%s", ddwaf_object_get_string(node, nullptr));
}
```
Finally, the events schema can be found [here](schema/events.json) and the actions schema can be found [here](schema/actions.json).
#### Per-input transformers

Rules provide a `transformers` key which represents a list of transformers which should be applied (in order) to each scalar before evaluating the operator. An example of a rule with transformers could be the following:
```json
{
  "id": "crs-933-111",
  "name": "PHP Injection Attack: PHP Script File Upload Found",
  "tags": {...},
  "conditions": [...],
  "transformers": [
    "lowercase"
  ]
},
```
Since the transformers are rule-local, they are applied to all inputs, potentially resulting in a performance impact, as well as limiting the ability of the rule writer to use more fine-grained transformers. 

In `1.11.0`, transformers can be defined per input, for example:
```json
"inputs": [
  {
    "address": "server.request.headers.no_cookies",
    "transformers": [
      "lowercase",
      "removeNulls"
    ]
  }
]
```
The existence of a `transformers` key on an input, even if empty, completely overrides any available rule transformers. Conversely, the lack of a `transformers` key on an input results in the specific input inheriting the rule transformers.

### Upgrading from `1.7.x` to `1.8.0`

Version `1.8.0` introduces the WAF builder, a new module with the ability to generate a new WAF instance from an existing one. This new module works transparently through the `ddwaf_update` function, which allows the user to update one, some or all of the following:
- The complete ruleset through the `rules` key.
- The `on_match` or `enabled` field of specific rules through the `rules_override` key.
- Exclusion filters through the `exclusions` key.
- Rule data through the `rules_data` key.

The WAF builder has a number of objectives:
- Provide a mechanism to generate and update the WAF as needed.
- Remove all existing mutexes.
- Remove all side-effects on running contexts.
- __Potentially__ provide efficiency gains: 
  - Avoiding the need to parse a whole ruleset on every update.
  - Reusing internal structures, objects and containers whenever possible.

With the introduction of `ddwaf_update`, the following functions have been deprecated and removed:
- `ddwaf_toggle_rules`
- `ddwaf_update_rule_data`
- `ddwaf_required_rule_data_ids`

The first two functions have been removed due to the added complexity of supporting multiple interfaces with a similar outcome but different inputs. On the other hand, the last function was simply removed in favour of letting the WAF handle unexpected rule data IDs more gracefully, however this function can be reintroduced later if deemed necessary.

Typically, the new interface will be used as follows on all instances:

```c
    ddwaf_handle old_handle = ddwaf_init(&ruleset, &config, &info);
    ddwaf_object_free(&ruleset);

    ddwaf_handle new_handle = ddwaf_update(old_handle, &update, &new_info);
    ddwaf_object_free(&update);
    if (new_handle != NULL) {
        ddwaf_destroy(old_handle);
    }
```

The `ddwaf_update` function returns a new `ddwaf_handle` which will be a valid pointer if the update succeeded, or `NULL` if there was nothing to update or there was an error. Creating contexts while calling `ddwaf_update` is, in theory, perfectly legal as well as destroying a handle while associated contexts are still in use, for example:

```c
    ddwaf_handle old_handle = ddwaf_init(&ruleset, &config, &info);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(old_handle);

    ddwaf_handle new_handle = ddwaf_update(old_handle, &new_ruleset, &new_info);
    ddwaf_object_free(&new_rule);
    if (new_handle != NULL) {
        // Destroying the handle should not invalidate the context
        ddwaf_destroy(old_handle);
    }
    
    // Both the context and the handle are destroyed here
    ddwaf_context_destroy(context);
```
Note that the `ddwaf_update` function also has an optional input parameter for the `ruleset_info` structure, this will only provide useful diagnostics when the update provided contains new rules (within the `rules` key), also note that the `ruleset_info` should either be a fresh new structure or the previously used after calling `ddwaf_ruleset_info_free`.

Finally, you can call `ddwaf_init` with all previously mentioned keys, or a combination of them, however the `rules` key is mandatory. This does not apply to `ddwaf_update.

### Notes on thread-safety

The thread-safety of any operations on the handle depends on whether they act on the ruleset or the builder itself, generally:
- Calling `ddwaf_update` concurrently, regardless of the handle, is never thread-safe.
- Calling `ddwaf_context_init` concurrently on the same handle is thread-safe.
- Calling `ddwaf_context_init` and `ddwaf_update` concurrently on the same handle is also thread-safe.

## Upgrading from `1.6.x` to `1.7.0`

There are no API changes in 1.7.0, however `ddwaf_handle` is now reference-counted and shared between the user and each `ddwaf_context`. This means that it is now possible to call `ddwaf_destroy` on a `ddwaf_handle` without invalidating any `ddwaf_context` in use instantiated from said `ddwaf_handle`. For example, the following snippet is now perfectly legal and will work as expected (note that any checks have been omitted for brevity):

```c
    ddwaf_handle handle = ddwaf_init(&rule, &config, NULL);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);

    // Destroying the handle should not invalidate the context
    ddwaf_destroy(handle);

    ...

    ddwaf_run(context, &parameter, NULL, LONG_TIME);

    // Both the context and the handle are destroyed here
    ddwaf_context_destroy(context);
```

To expand on the example above:
- `ddwaf_destroy` only destroys the `ddwaf_handle` if there are no more references to it, otherwise it relinquishes ownership to the rest of the contexts.
- If there is more than one valid context after the user calls `ddwaf_destroy`, each context will reduce the reference count on `ddwaf_context_destroy` until it reaches zero, at which point the `ddwaf_handle` will be freed.
- Once the user calls `ddwaf_destroy` on the `ddwaf_handle`, their reference becomes invalid and no more operations can be performed on it, including instantiating further contexts.

Note that this doesn't make `ddwaf_handle` universally thread-safe, for example, replacing an existing `ddwaf_handle` shared by multiple threads still requires synchronisation.

## Upgrading from `v1.4.0` to `1.5.0`

### Actions

The introduction of actions within the ruleset, through the `on_match` array, provides a generic mechanism to signal the user what the expected outcome of a match should be. This information is now provided to the user through `ddwaf_result`, which now has the following definition:

```c
struct _ddwaf_result
{
    /** Whether there has been a timeout during the operation **/
    bool timeout;
    /** Run result in JSON format **/
    const char* data;
    /** Actions array and its size **/
    struct {
        char **array;
        uint32_t size;
    } actions;
    /** Total WAF runtime in nanoseconds **/
    uint64_t total_runtime;
};
```

Actions are provided as a `char *` array containing `actions.size` items. This array is currently not null-terminated. The contents of this array and the array itself are also freed by `ddwaf_result_free`.

#### Return codes

As a consequence of the introduction of actions, return codes such as `DDWAF_MONITOR` or `DDWAF_BLOCK` are no longer meaningful, to address this:
- `DDWAF_MONITOR` has now been renamed to `DDWAF_MATCH`, this lets the user know that `ddwaf_result` contains meaningful data and possibly actions while making no statement regarding what the user should do with it.
- `DDWAF_BLOCK` has been removed.
- As a slightly unnecessary bonus, `DDWAF_GOOD` has been renamed to `DDWAF_OK` as it is more common to use `OK` than `GOOD` in return codes.

### Free function

In previous versions, the context is initialised with a free function in order to prevent objects provided through `ddwaf_run` from being freed by the WAF itself. In practice, this free function is always the same so it's not very useful to provide it over and over. For that reason it has now been moved to `ddwaf_config`.

As an example, in version `1.4.0`, the following code would provide `ddwaf_object_free` to the context during initialisation:

```c
ddwaf_config config{{0, 0, 0}, {NULL, NULL}};
ddwaf_handle handle = ddwaf_init(&rule, &config, &info);
...
ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
```

In version `1.5.0-alpha0`, the free function should be provided within `ddwaf_config`:
```c
ddwaf_config config{{0, 0, 0}, {NULL, NULL}, ddwaf_object_free};
ddwaf_handle handle = ddwaf_init(&rule, &config, &info);
...
ddwaf_context context = ddwaf_context_init(handle);
```

Alternatively, to completely disable the free function, it can be set to `NULL`:
```c
ddwaf_config config{{0, 0, 0}, {NULL, NULL}, NULL};
ddwaf_handle handle = ddwaf_init(&rule, &config, &info);
```

**Note that if the configuration pointer to the WAF is `NULL`, the default free function (`ddwaf_object_free`) will be used:**
```c
ddwaf_handle handle = ddwaf_init(&rule, NULL, &info);
```

### Version

In order to support version suffixes, such as `-alpha`, `-beta` or `-rc`, the `ddwaf_version` structure has been deprecated altogether. As a result `ddwaf_get_version` now returns a const string which should not be freed by the caller.

To summarize, the following code snippet:

```c
ddwaf_version version;
ddwaf_get_version(&version);
printf("ddwaf version: %d.%d.%d\n", version.major, version.minor, version.patch);
```

Can now be rewritten as follows:

```c
printf("ddwaf version: %s\n", ddwaf_get_version());
```
