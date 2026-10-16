// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <cstddef>

namespace ddwaf::thread_exit {

using callback = void (*)() noexcept;

// The maximum number of callbacks pending on a thread at any time.
inline constexpr std::size_t max_callbacks = 4;

// Arranges for `cb` to be called on the calling thread when it exits, to free
// the caches libddwaf keeps per thread. Callbacks registered on the
// same thread run in reverse order of registration. Returns false if the
// callback can't be registered: the library is being unloaded (or the process
// is exiting), or max_callbacks are already pending. The caller must then not
// keep resources for the thread.
//
// On Linux, callbacks run from the destructor of a pthread key, not from that
// of a C++ thread_local, for two reasons:
//
// - glibc runs the thread_local destructors of a thread once, before its
//   pthread key destructors, so a thread_local destructor registered while
//   those run (e.g. on the first use of a cache from the application's own key
//   destructor) never runs. A key set from a key destructor, by contrast,
//   is destroyed in the next iteration (PTHREAD_DESTRUCTOR_ITERATIONS), so a
//   callback can be registered at any point of the thread's exit, including
//   from another callback.
// - glibc doesn't unload a shared object (dlclose) while one of its
//   thread_local destructors is pending on any thread, which would keep
//   libddwaf.so loaded as long as the threads that used it live. The key is
//   instead deleted when the library is unloaded, leaking the caches of the
//   threads still alive at that point.
//
// As a consequence, on glibc, callbacks run after all the thread_local
// destructors of the exiting thread, which can therefore still evaluate
// with the caches in place. A thread calling exit() doesn't run its key
// destructors: its callbacks run instead when the static objects of libddwaf
// are destroyed (as do those of a thread unloading the library). Static
// destructors which evaluate after that point do so without the caches.
//
// Elsewhere (macOS, Windows), callbacks run from the destructor of a
// thread_local, which is registered when the first callback of the thread is.
// Neither of the issues above applies to macOS, which never unloads images
// with thread_local variables. A callback registered after the thread_local
// destructors of the thread have run doesn't run.
bool register_callback(callback cb) noexcept;

} // namespace ddwaf::thread_exit
