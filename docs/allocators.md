# Allocators

The ownership of memory crossing the API boundary was one of the pain points of libddwaf v1. To fix this, v2 introduces allocators, which can be used to define the explicit ownership of the allocated memory. 

Four different allocator options are provided:
- **Default allocator**: obtained through `ddwaf_get_default_allocator`, this is the default allocator used by the standard library and it's typically relies directly on `new` / `delete`. When unsure, this is the recommended allocator. The underlying memory resource is [std::pmr::new_delete_resource](https://en.cppreference.com/w/cpp/memory/new_delete_resource.html).
- **Unsynchronized pool allocator**: obtained through `ddwaf_unsynchronized_pool_allocator_init`, this is a thread-unsafe pool allocator. The underlying memory resource is [std::pmr::unsynchronized_pool_resource](https://en.cppreference.com/w/cpp/memory/unsynchronized_pool_resource.html).
- **Synchronized pool allocator**: obtained through `ddwaf_synchronized_pool_allocator_init`, this is a thread-safe version of the previous pool allocator. The underlying memory resource is [std::pmr::synchronized_pool_resource](https://en.cppreference.com/w/cpp/memory/synchronized_pool_resource.html).
- **Monotonic allocator**: obtained through `ddwaf_monotonic_allocator_init`, this is a special allocator which releases all of the allocated memory once destroyed. This allocator is not recommended as a general purpose allocator and should be used with care. The underlying memory resource is [std::pmr::monotonic_buffer_resource](https://en.cppreference.com/w/cpp/memory/monotonic_buffer_resource.html).


Allocators are destroyed using `ddwaf_allocator_destroy`, note that for safety, this must only be done once all of the allocated memory has been freed. Additionally, the default allocator need not be destroyed, as destruction results in a no-op.
