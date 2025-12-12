# Allocators

As the name suggests, allocators are used for the purpose of memory management, providing functionality for allocating and deallocating memory as needed. Different allocators may follow specific memory management strategies to reduce the amount of memory that needs to be requested to the global allocators or to minimise the cost of allocation or deallocation. 

The allocators provided by `libddwaf` are, under the hood, C++ memory resources, therefore the four different allocator options are provided:
- **Default allocator**: obtained through `ddwaf_get_default_allocator`, this is the default allocator used by the standard library and it's typically relies directly on `new` / `delete`. When unsure, this is the recommended allocator. The underlying memory resource is [std::pmr::new_delete_resource](https://en.cppreference.com/w/cpp/memory/new_delete_resource.html).
- **Unsynchronized pool allocator**: obtained through `ddwaf_unsynchronized_pool_allocator_init`, this is a thread-unsafe pool allocator. The underlying memory resource is [std::pmr::unsynchronized_pool_resource](https://en.cppreference.com/w/cpp/memory/unsynchronized_pool_resource.html).
- **Synchronized pool allocator**: obtained through `ddwaf_synchronized_pool_allocator_init`, this is a thread-safe version of the previous pool allocator. The underlying memory resource is [std::pmr::synchronized_pool_resource](https://en.cppreference.com/w/cpp/memory/synchronized_pool_resource.html).
- **Monotonic allocator**: obtained through `ddwaf_monotonic_allocator_init`, this is a special allocator which releases all of the allocated memory once destroyed. This allocator is not recommended as a general purpose allocator and should be used with care. The underlying memory resource is [std::pmr::monotonic_buffer_resource](https://en.cppreference.com/w/cpp/memory/monotonic_buffer_resource.html).

Allocators are destroyed using `ddwaf_allocator_destroy`, note that for safety, this must only be done once all of the allocated memory has been freed. Additionally, the default allocator need not be destroyed, as destruction results in a no-op.

## User Allocators

In addition to the available allocators, custom memory management strategies are supported through the use of user allocators. A user allocator has four main components:
- A function to allocate memory (alloc) based on the required size and an alignment.
- A function to deallocate memory (dealloc) based on the allocated size and alignment.
- Optional user data, which may typically correspond to the required structures used to store and manage the allocated memory.
- An optional free function for user data.

As an example, consider the case of a counting allocator, using the default allocator as its upstream allocator. This may be defined through the following structure, which corresponds to the aforementioned user data.

```c
struct counting_allocator {
    unsigned alloc_count{0};
    unsigned free_count{0};
    ddwaf_allocator upstream{ddwaf_get_default_allocator()};
};
```

The allocation function can then be the following:

```c
void *counting_allocator_alloc(void *udata, std::size_t bytes, std::size_t alignment)
{
    counting_allocator *alloc = (counting_allocator *)udata;
    alloc->alloc_count++;
    return ddwaf_allocator_alloc(alloc->upstream, bytes, alignment);
}
```

Where the user data is provided as the first field, followed by the number of bytes (size) and their expected alignment. The function increases the allocation count and calls the upstream allocator.

The deallocation function can then be the following:

```c
void counting_allocator_free(void *udata, void *p, std::size_t bytes, std::size_t alignment)
{
    counting_allocator *alloc = (counting_allocator *)udata;
    alloc->free_count++;
    ddwaf_allocator_free(alloc->upstream, p, bytes, alignment);
}
```

Which requires the user data as the first field, followed by the pointer to deallocate and both the number of bytes and alignment.

This particular allocator doesn't allocate memory for its own use, therefore a free function is not needed, however for illustration purposes, the following would be suitable:

```c
void counting_allocator_udata_free(void *udata)
{
  // noop
}
```

Finally, the user allocator to provide to libddwaf can be instantiated as follows:

```c
counting_allocator udata;
ddwaf_allocator alloc = ddwaf_user_allocator_init(&counting_allocator_alloc, &counting_allocator_free, &udata, &counting_allocator_udata_free);
```
