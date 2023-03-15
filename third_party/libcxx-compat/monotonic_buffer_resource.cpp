#include "monotonic_buffer_resource.hpp"
#include <atomic>

namespace std::experimental { // NOLINT
inline namespace fundamentals_v1 {
namespace pmr {

class __new_delete_memory_resource_imp : public memory_resource {
    void *do_allocate(size_t bytes, size_t align) override
    {
        return std::__libcpp_allocate(bytes, align);
    }

    void do_deallocate(void *p, size_t bytes, size_t align) override
    {
        std::__libcpp_deallocate(p, bytes, align);
    }

    [[nodiscard]] bool do_is_equal(const memory_resource &other) const noexcept override
    {
        return &other == this;
    }
};

static __new_delete_memory_resource_imp new_delete_res; // NOLINT

memory_resource *new_delete_resource() noexcept { return &new_delete_res; }

static memory_resource *__default_memory_resource(
    bool set = false, memory_resource *new_res = nullptr) noexcept
{
    static atomic<memory_resource *> __res{&new_delete_res};
    if (set) {
        new_res = new_res != nullptr ? new_res : new_delete_resource();
        return std::atomic_exchange_explicit(&__res, new_res, memory_order_acq_rel);
    }
    return std::atomic_load_explicit(&__res, memory_order_acquire);
}

memory_resource *get_default_resource() noexcept { return __default_memory_resource(); }

memory_resource *set_default_resource(memory_resource *__new_res) noexcept
{
    return __default_memory_resource(true, __new_res);
}

void *monotonic_buffer_resource::__initial_descriptor::__try_allocate_from_chunk(
    size_t bytes, size_t align)
{
    if (__cur_ == nullptr) {
        return nullptr;
    }
    void *new_ptr = static_cast<void *>(__cur_);
    size_t new_capacity = (__end_ - __cur_);
    void *aligned_ptr = std::align(align, bytes, new_ptr, new_capacity);
    if (aligned_ptr != nullptr) {
        __cur_ = static_cast<char *>(new_ptr) + bytes;
    }
    return aligned_ptr;
}

void *monotonic_buffer_resource::__chunk_footer::__try_allocate_from_chunk(
    size_t bytes, size_t align)
{
    void *new_ptr = static_cast<void *>(__cur_);
    size_t new_capacity = (reinterpret_cast<char *>(this) - __cur_); // NOLINT
    void *aligned_ptr = std::align(align, bytes, new_ptr, new_capacity);
    if (aligned_ptr != nullptr) {
        __cur_ = static_cast<char *>(new_ptr) + bytes;
    }
    return aligned_ptr;
}

namespace {
constexpr size_t roundup(size_t count, size_t alignment) // NOLINT
{
    size_t mask = alignment - 1;
    return (count + mask) & ~mask;
}
} // namespace

void *monotonic_buffer_resource::do_allocate(size_t bytes, size_t align)
{
    const size_t footer_size = sizeof(__chunk_footer);
    const size_t footer_align = alignof(__chunk_footer);

    auto previous_allocation_size = [&]() {
        if (__chunks_ != nullptr) {
            return __chunks_->__allocation_size();
        }

        size_t newsize = (__initial_.__start_ != nullptr)
                             ? (__initial_.__end_ - __initial_.__start_)
                             : __initial_.__size_;

        return roundup(newsize, footer_align) + footer_size;
    };

    if (void *result = __initial_.__try_allocate_from_chunk(bytes, align)) {
        return result;
    }
    if (__chunks_ != nullptr) {
        if (void *result = __chunks_->__try_allocate_from_chunk(bytes, align)) {
            return result;
        }
    }

    // Allocate a brand-new chunk.

    if (align < footer_align) {
        align = footer_align;
    }

    size_t aligned_capacity = roundup(bytes, footer_align) + footer_size;
    size_t previous_capacity = previous_allocation_size();

    if (aligned_capacity <= previous_capacity) {
        size_t newsize = 2 * (previous_capacity - footer_size);
        aligned_capacity = roundup(newsize, footer_align) + footer_size;
    }

    char *start = static_cast<char *>(__res_->allocate(aligned_capacity, align));
    // NOLINTNEXTLINE
    auto *footer = reinterpret_cast<__chunk_footer *>(start + aligned_capacity - footer_size);
    footer->__next_ = __chunks_;
    footer->__start_ = start;
    footer->__cur_ = start;
    footer->__align_ = align;
    __chunks_ = footer;

    return __chunks_->__try_allocate_from_chunk(bytes, align);
}
} // namespace pmr
} // namespace fundamentals_v1
} // namespace std::experimental
