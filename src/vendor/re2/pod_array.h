// Copyright 2018 The RE2 Authors.  All Rights Reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#ifndef RE2_POD_ARRAY_H_
#define RE2_POD_ARRAY_H_

#include <memory>
#include <type_traits>

// libddwaf: scratch arrays allocated on every search use libddwaf's internal
// allocator (a thread-local block cache) instead of the system allocator.
#include "internal_resource.hpp"

namespace re2 {

template <typename T, typename Allocator = std::allocator<T>>
class PODArray {
 public:
  static_assert(std::is_trivial<T>::value && std::is_standard_layout<T>::value,
                "T must be POD");

  PODArray()
      : ptr_() {}
  explicit PODArray(int len)
      : ptr_(Allocator().allocate(len), Deleter(len)) {}

  T* data() const {
    return ptr_.get();
  }

  int size() const {
    return ptr_.get_deleter().len_;
  }

  T& operator[](int pos) const {
    return ptr_[pos];
  }

 private:
  struct Deleter {
    Deleter()
        : len_(0) {}
    explicit Deleter(int len)
        : len_(len) {}

    void operator()(T* ptr) const {
      Allocator().deallocate(ptr, len_);
    }

    int len_;
  };

  std::unique_ptr<T[], Deleter> ptr_;
};

// libddwaf: per-search scratch space
template <typename T>
using ScratchPODArray = PODArray<T, ddwaf::memory::internal_allocator<T>>;

}  // namespace re2

#endif  // RE2_POD_ARRAY_H_
