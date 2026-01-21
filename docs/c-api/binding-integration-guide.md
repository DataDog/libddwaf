# Implementation notes for bindings


## `ddwaf_handle`

`ddwaf_handle` represents a rule set, with associated rule data, exclusions,
and so on. It is created through the `ddwaf_builder` API.

A tracer will want to keep only one live `ddwaf_handle`. The first one will be
created through `ddwaf_builder_build_instance`, and then it will replace it by
updating the builder and building a new instance as it gets new configurations
through remote config.

The relevant read operations on `ddwaf_handle` are `ddwaf_context_init`,
`ddwaf_known_addresses`, and `ddwaf_known_actions`. None of these operations
modify the `ddwaf_handle`. So, at this point, it is sufficient to ensure that
threads calling these functions see a fully constructed `ddwaf_handle` — or in
other words, it is sufficient that the write to the pointer/reference happens
after `ddwaf_builder_build_instance` is called (as seen by other threads). For
this, a release-acquire operation suffices:

```c++
std::atomic<ddwaf_handle> cur_ddwaf_handle; // global variable; the live handle

// Initialization thread
void initialize_handle(const ddwaf_object *ruleset, ddwaf_object *diagnostics)
{
    ddwaf_builder builder = ddwaf_builder_init();
    if (builder == nullptr) { /* handle error */ }

    ddwaf_builder_add_or_update_config(builder, "main", 4, ruleset, diagnostics);
    ddwaf_handle new_handle = ddwaf_builder_build_instance(builder);
    ddwaf_builder_destroy(builder);

    if (new_handle == nullptr) { /* handle error */ }
    cur_ddwaf_handle.store(new_handle, std::memory_order_release);
}

// Request thread
ddwaf_context create_context(ddwaf_allocator output_alloc) {
    ddwaf_handle handle = cur_ddwaf_handle.load(std::memory_order_acquire);
    if (handle == nullptr) { /* handle error */ }
    return ddwaf_context_init(handle, output_alloc);
}
```

However, there is a potential problem when you update the live handle. While
libddwaf refcounts the `ddwaf_handle` and ensures that its memory is not
reclaimed until all associated `ddwaf_context`s have been destroyed, it cannot
prevent a use-after-free in this situation:

```c++
// Remote config thread
void update_handle(ddwaf_builder builder, const ddwaf_object *ruleset, ddwaf_object *diagnostics)
{
    ddwaf_handle old_handle = cur_ddwaf_handle.load(std::memory_order_acquire);

    // Update the builder with new configuration
    ddwaf_builder_add_or_update_config(builder, "main", 4, ruleset, diagnostics);
    ddwaf_handle new_handle = ddwaf_builder_build_instance(builder);

    cur_ddwaf_handle.store(new_handle, std::memory_order_release);

    // will free the memory if no ddwaf_contexts are associated with it:
    ddwaf_destroy(old_handle);
}

// Request thread
ddwaf_context create_context(ddwaf_allocator output_alloc) {
    ddwaf_handle handle = cur_ddwaf_handle.load(std::memory_order_acquire);
    if (handle == nullptr) { /* handle error */ }
    // XXX: the handle fetched may have been destroyed in the interim
    return ddwaf_context_init(handle, output_alloc);
}
```

That is, the old `ddwaf_handle` can only be destroyed once we can be guaranteed
that no other thread will try to create a new context from it (or build a new
handle through the builder, though that is less of a problem because generally
the tracers will not want to update the global `ddwaf_handle` from several
threads simultaneously).

There are many possible strategies to deal with this memory reclamation
problem, but the most straightforward are:

* If the runtime uses garbage collection, we can delay the call to
  `ddwaf_destroy` until the garbage collector determines the object wrapping
  the native `ddwaf_handle` has no more references. This is relatively easy to
  do and doesn't involve extra usage of locks, but the memory used by the
  `ddwaf_handle` will not be available until the garbage collector decides
  to reclaim the wrapped object. Because the garbage collector does not see
  the memory being used by the `ddwaf_handle`, if garbage collection never
  happens, there is a risk that memory consumption gets too high. This is a
  rather unlikely scenario though.

* You can use read-write locks:

```c++
// global variables
std::shared_mutex mutex;
ddwaf_handle cur_ddwaf_handle;

// Initialization thread
void initialize_handle(const ddwaf_object *ruleset, ddwaf_object *diagnostics)
{
    ddwaf_builder builder = ddwaf_builder_init();
    if (builder == nullptr) { /* handle error */ }

    ddwaf_builder_add_or_update_config(builder, "main", 4, ruleset, diagnostics);
    ddwaf_handle new_handle = ddwaf_builder_build_instance(builder);
    ddwaf_builder_destroy(builder);

    if (new_handle == nullptr) { /* handle error */ }

    std::unique_lock lock{mutex}; // acquire write lock
    cur_ddwaf_handle = new_handle;
    // write lock released on return
}

// Remote config thread
void update_handle(ddwaf_builder builder, const ddwaf_object *ruleset, ddwaf_object *diagnostics)
{
    std::unique_lock lock{mutex}; // acquire write lock
    ddwaf_handle old_handle = cur_ddwaf_handle;

    ddwaf_builder_add_or_update_config(builder, "main", 4, ruleset, diagnostics);
    ddwaf_handle new_handle = ddwaf_builder_build_instance(builder);

    cur_ddwaf_handle = new_handle;
    ddwaf_destroy(old_handle);
    // write lock released on return
}

// Request thread
ddwaf_context create_context(ddwaf_allocator output_alloc) {
    std::shared_lock lock{mutex}; // acquire read lock
    if (cur_ddwaf_handle == nullptr) { /* handle error */ }
    return ddwaf_context_init(cur_ddwaf_handle, output_alloc);
    // read lock released on return
}
```

## `ddwaf_context`

On the other hand, `ddwaf_context` is not thread-safe. If a `ddwaf_context` is
used by multiple threads (in web servers where the processing of the request
can move between several threads, or happen in several threads simultaneously),
you need to use locks so that calls to `ddwaf_context_eval` and `ddwaf_context_destroy`
are not run concurrently, and that changes made to the `ddwaf_context` in one thread
through `ddwaf_context_eval` are visible to the other threads subsequently running
`ddwaf_context_eval` on the same context. You also need to ensure that no calls
to `ddwaf_context_eval` or `ddwaf_context_destroy` happen after `ddwaf_context_destroy`
is called.

**Note**: The same thread-safety considerations apply to `ddwaf_subcontext`. Subcontexts
are created from a parent context via `ddwaf_subcontext_init` and evaluated with
`ddwaf_subcontext_eval`. Like contexts, they are not thread-safe and require external
synchronization if accessed from multiple threads.

```c++
// each request will have one of these associated with it
struct ctx_wrapper {
    std::mutex mutex;
    ddwaf_context ctx;
};

DDWAF_RET_CODE run_waf(
    ctx_wrapper &wrapper, ddwaf_object *data, ddwaf_allocator alloc,
    ddwaf_object *result, uint64_t timeout)
{
    std::lock_guard<std::mutex> lock{wrapper.mutex}; // acquire exclusive lock
    if (wrapper.ctx == nullptr) { /* context already destroyed */ }
    return ddwaf_context_eval(wrapper.ctx, data, alloc, result, timeout);
    // lock is released on return
}

void destroy_ctx(ctx_wrapper &wrapper) {
    std::lock_guard<std::mutex> lock{wrapper.mutex};
    if (wrapper.ctx == nullptr) { /* context already destroyed */ }
    ddwaf_context_destroy(wrapper.ctx);
    wrapper.ctx = nullptr;
}
```

## `ddwaf_builder`

The `ddwaf_builder` API manages multiple configuration sources and enables
configuration updates. This is the recommended way to create `ddwaf_handle`
instances, especially when dealing with remote configuration updates.

### Builder Lifecycle

```c
// 1. Initialize builder
ddwaf_builder builder = ddwaf_builder_init();

// 2. Add configurations with unique paths
ddwaf_object diagnostics;
ddwaf_builder_add_or_update_config(builder, "base", 4, base_config, &diagnostics);
ddwaf_object_destroy(&diagnostics, ddwaf_get_default_allocator());

// 3. Build instance
ddwaf_handle handle = ddwaf_builder_build_instance(builder);

// 4. Later, update configurations
ddwaf_builder_add_or_update_config(builder, "remote/prod", 11, remote_config, &diagnostics);
ddwaf_handle new_handle = ddwaf_builder_build_instance(builder);

// 5. Remove configurations if needed
ddwaf_builder_remove_config(builder, "remote/prod", 11);

// 6. Destroy builder when no longer needed
ddwaf_builder_destroy(builder);
```

### Thread Safety

`ddwaf_builder` operations are not thread-safe. If you need to update configurations
from multiple threads, use external synchronization (e.g., a mutex).
