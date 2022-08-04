# Upgrading libddwaf

## Upgrading from `v1.4.0` to `1.5.0-alpha0`

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
