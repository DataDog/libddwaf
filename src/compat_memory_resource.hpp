#pragma once

#ifdef HAS_STD_MONOBUFFER
#  include <memory_resource>
#else

#  include <experimental/memory_resource>
#  include <unordered_map>
#  include <unordered_set>

namespace std { // NOLINT(cert-dcl58-cpp)
namespace experimental::pmr {
template <class Key, class T, class Hash = std::hash<Key>, class KeyEqual = std::equal_to<Key>>
using unordered_map =
    std::unordered_map<Key, T, Hash, KeyEqual, polymorphic_allocator<std::pair<const Key, T>>>;

template <class Key, class Hash = std::hash<Key>, class Pred = std::equal_to<Key>>
using unordered_set = std::unordered_set<Key, Hash, Pred, polymorphic_allocator<Key>>;

template <class T> using vector = std::vector<T, polymorphic_allocator<T>>;

using string = std::basic_string<char, std::char_traits<char>, polymorphic_allocator<char>>;

#  ifndef HAS_EXPERIMENTAL_MONOBUFFER

class monotonic_buffer_resource : public memory_resource {
  static const size_t __default_buffer_capacity  = 1024;
  static const size_t __default_buffer_alignment = 16;

  struct __chunk_footer {
    __chunk_footer* __next_;
    char* __start_;
    char* __cur_;
    size_t __align_;
    size_t __allocation_size()
    {
        return (reinterpret_cast<char *>(this) - __start_) + sizeof(*this); // NOLINT
    }
    void* __try_allocate_from_chunk(size_t, size_t);
  };

  struct __initial_descriptor {
    char* __start_;
    char* __cur_;
    union {
      char* __end_;
      size_t __size_;
    };
    void* __try_allocate_from_chunk(size_t, size_t);
  };

public:
    monotonic_buffer_resource()
        : monotonic_buffer_resource(nullptr, __default_buffer_capacity, get_default_resource())
    {}

    explicit monotonic_buffer_resource(size_t __initial_size)
        : monotonic_buffer_resource(nullptr, __initial_size, get_default_resource())
    {}

    monotonic_buffer_resource(void *__buffer, size_t __buffer_size)
        : monotonic_buffer_resource(__buffer, __buffer_size, get_default_resource())
    {}

    explicit monotonic_buffer_resource(memory_resource *__upstream)
        : monotonic_buffer_resource(nullptr, __default_buffer_capacity, __upstream)
    {}

    monotonic_buffer_resource(size_t __initial_size, memory_resource *__upstream)
        : monotonic_buffer_resource(nullptr, __initial_size, __upstream)
    {}

    monotonic_buffer_resource(void *__buffer, size_t __buffer_size, memory_resource *__upstream)
        : __res_(__upstream)
    {
        __initial_.__start_ = static_cast<char *>(__buffer);
        if (__buffer != nullptr) {
            __initial_.__cur_ = static_cast<char *>(__buffer);
            __initial_.__end_ = static_cast<char *>(__buffer) + __buffer_size;
        } else {
            __initial_.__cur_ = nullptr;
            __initial_.__size_ = __buffer_size;
        }
        __chunks_ = nullptr;
  }

  monotonic_buffer_resource(const monotonic_buffer_resource &) = delete;

  monotonic_buffer_resource(monotonic_buffer_resource &&) = delete;

  ~monotonic_buffer_resource() override { release(); }

  monotonic_buffer_resource &operator=(const monotonic_buffer_resource &) = delete;

  monotonic_buffer_resource &operator=(monotonic_buffer_resource &&) = delete;

  void release()
  {
      __initial_.__cur_ = __initial_.__start_;
      while (__chunks_ != nullptr) {
          __chunk_footer *__next = __chunks_->__next_;
          __res_->deallocate(
              __chunks_->__start_, __chunks_->__allocation_size(), __chunks_->__align_);
          __chunks_ = __next;
      }
  }

  [[nodiscard]] memory_resource *upstream_resource() const { return __res_; }

  protected:
  void *do_allocate(size_t bytes, size_t align) override; // key function

  void do_deallocate(void *, size_t, size_t)
  override {}

  [[nodiscard]] bool do_is_equal(const memory_resource &__other) const _NOEXCEPT override
  {
      return this == std::addressof(__other);
  }

  private:
  __initial_descriptor __initial_{};
  __chunk_footer *__chunks_;
  memory_resource *__res_;
};

#  endif

} // namespace experimental::pmr
namespace pmr = std::experimental::pmr;
} // namespace std

#endif
