# libddwaf binding integration guide

This guide complements the API reference in `docs/c-api/api.md`. It focuses on
the concurrency and lifecycle concerns that most native bindings must handle to
provide a safe libddwaf integration.

## `ddwaf_handle` lifecycle

`ddwaf_handle` represents the compiled ruleset, related data providers, and
exclusions. Handles are built through `ddwaf_init` and updated in place through
`ddwaf_update`. Only one instance is typically kept by a tracer or agent.

The two operations that observe a handle are `ddwaf_context_init` and
`ddwaf_update`. Neither mutates the handle content, but callers must ensure that
other threads only observe a fully initialised pointer. A release/acquire pair
is enough for this requirement:

```c++
std::atomic<ddwaf_handle> cur_ddwaf_handle; // global variable; the live handle

// Initialization thread
void initialize_handle(
    const ddwaf_object *ruleset, const ddwaf_config *config, ddwaf_object *diagnostics)
{
    ddwaf_handle new_handle = ddwaf_init(ruleset, config, diagnostics);
    if (new_handle == nullptr) { /* handle error */}
    cur_ddwaf_handle.store(new_handle, std::memory_order_release);
}

// Request thread
ddwaf_context create_context() {
    ddwaf_handle handle = cur_ddwaf_handle.load(std::memory_order_acquire);
    if (handle == nullptr) { /* handle error */ }
    return ddwaf_context_init(handle);
}
```

However, there is a potential problem when you update the live handle. While
libddwaf refcounts the `ddwaf_handle` and ensures that its memory is not
reclaimed until all associated `ddwaf_context`s have been destroyed, it cannot
prevent a use-after-free in this situation:

```c++
// Remote config thread
void update_handle(const ddwaf_object *ruleset, ddwaf_object *diagnostics)
{
    ddwaf_handle old_handle = cur_ddwaf_handle.load(std::memory_order_acquire);
    ddwaf_handle new_handle = ddwaf_update(old_handle, ruleset, diagnostics);
    cur_ddwaf_handle.store(new_handle, std::memory_order_release);

    // will free the memory if no ddwaf_contexts are associated with it:
    ddwaf_destroy(old_handle);
}

// Request thread
ddwaf_context create_context() {
    ddwaf_handle handle = cur_ddwaf_handle.load(std::memory_order_acquire);
    if (handle == nullptr) { /* handle error */ }
    // XXX: the handle fetched may have been destroyed in the interim
    return ddwaf_context_init(handle);
}
```

That is, the old `ddwaf_handle` can only be destroyed once we can be guaranteed
that no other thread will try to create a new context from it (or update it
through `ddwaf_update`, though that is less of a problem because generally the
tracers will not want to update the global `ddwaf_handle` from several threads
simultaneously).

There are many ways to guarantee safe reclamation. Two common strategies are
outlined below.

* Delay `ddwaf_destroy` until your runtime can prove that no other code keeps a
  reference. Garbage-collected environments can let the wrapper object finalise
  the native handle, but keep in mind that the collector is blind to the native
  memory usage.

* Protect access with reader/writer locks so that `ddwaf_destroy` only executes
  after new contexts can no longer be created:

```c++
// global variables
std::shared_mutex mutex;
ddwaf_handle cur_ddwaf_handle = nullptr;

// Initialization thread
void initialize_handle(
    const ddwaf_object *ruleset, const ddwaf_config *config, ddwaf_object *diagnostics)
{
    ddwaf_handle new_handle = ddwaf_init(ruleset, config, diagnostics);
    if (new_handle == nullptr) { /* handle error */}

    std::unique_lock lock{mutex}; // acquire write lock
    cur_ddwaf_handle = new_handle;
    // write lock released on return
}

// Remote config thread
void update_handle(const ddwaf_object *ruleset, ddwaf_object *diagnostics)
{
    std::unique_lock lock{mutex}; // acquire write lock
    ddwaf_handle old_handle = cur_ddwaf_handle;
    ddwaf_handle new_handle = ddwaf_update(old_handle, ruleset, diagnostics);
    cur_ddwaf_handle = new_handle;
    ddwaf_destroy(old_handle);
    // write lock released on return
}

// Request thread
ddwaf_context create_context() {
    std::shared_lock lock{mutex}; // acquire read lock
    if (cur_ddwaf_handle == nullptr) { /* handle error */ }
    return ddwaf_context_init(cur_ddwaf_handle);
    // read lock released on return
}
```

## `ddwaf_context` and `ddwaf_subcontext`

`ddwaf_context` is not thread-safe. If a context can be touched by multiple
threads (for example, when the web server hands off the same request to another
thread), guard calls to `ddwaf_context_eval` and `ddwaf_context_destroy`. You
must also prevent any evaluation after the owning handle has been destroyed.

When you only need isolated evaluation state but still share the same handle,
prefer `ddwaf_context_init` per request. `ddwaf_subcontext_init` (documented in
the API reference) can provide a cheaper clone when your binding benefits from
sharing captures between stages. Subcontexts inherit the parent lifetime, so
they must never outlive the original context.

```c++
// each request will have one of these associated with it
struct ctx_wrapper {
    std::mutex mutex;
    ddwaf_context ctx;
};

DDWAF_RET_CODE run_waf(
    ctx_wrapper &wrapper, ddwaf_object *data, ddwaf_object *result, uint64_t timeout)
{
    std::lock_guard<std::mutex> lock{wrapper.mutex}; // acquire exclusive lock
    if (wrapper.ctx == nullptr) { /* context already destroyed */ }
    return ddwaf_context_eval(wrapper.ctx, data, result, timeout);
    // lock is released on return
}

void destroy_ctx(ctx_wrapper &wrapper) {
    std::lock_guard<std::mutex> lock{wrapper.mutex};
    if (wrapper.ctx == nullptr) { /* context already destroyed */ }
    ddwaf_context_destroy(wrapper.ctx);
    wrapper.ctx = nullptr;
}
```

## Custom allocators and diagnostics

Consult `docs/c-api/api.md` for the exact signatures of allocator hooks. Any
binding that offers native memory tracking should expose `ddwaf_user_allocator_init`
wrappers and document the ownership of `ddwaf_object`. The documented helpers in
the header (`ddwaf_object_*`) ensure that objects stay consistent with their
type tag.

libddwaf can emit logs through `ddwaf_set_log_cb`. Bindings should translate
the `DDWAF_LOG_LEVEL` levels into their host logging facilities and pay
attention to thread-safety inside the callback. The callback can run from hot
paths, so limit the amount of work performed there.
