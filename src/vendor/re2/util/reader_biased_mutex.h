// Copyright 2026 Datadog, Inc.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#ifndef UTIL_READER_BIASED_MUTEX_H_
#define UTIL_READER_BIASED_MUTEX_H_

// libddwaf addition to the vendored RE2 (not part of upstream RE2).
//
// ReaderBiasedMutex is a reader-writer mutex for read-mostly data, used for
// the DFA state cache (see DFA::cache_mutex_ in dfa.cc). Every DFA search
// takes the cache's read lock, while the write lock is only taken to discard
// a full cache. A plain rwlock makes every reader write the lock word, so on
// a regex searched by many threads that cache line bounces between cores on
// every search.
//
// This is the BRAVO scheme (Dice and Kogan, "BRAVO -- Biased Locking for
// Reader-Writer Locks", USENIX ATC 2019) on top of re2::Mutex:
//
//  - While the mutex is reader-biased, a reader publishes the mutex's address
//    in a slot of a process-wide table instead of touching the mutex. Each
//    thread is given its own slot (round robin, so threads only share a slot
//    when there are more than kSlots of them), and slots are padded to
//    separate cache lines, so readers on different threads write disjoint
//    cache lines.
//  - A writer takes the underlying mutex for writing, which excludes the
//    slow-path readers, clears the bias, and then waits until no slot holds
//    the mutex's address, which drains the fast-path readers.
//  - Readers that find the bias cleared, or their slot taken (by another
//    thread sharing it, or by this thread holding another ReaderBiasedMutex),
//    take the underlying mutex for reading. Once such a reader holds it no
//    writer can be active, so it restores the bias for the next readers.
//
// The publication and the bias check form a Dekker-style handshake: the
// reader stores its slot and then loads the bias, the writer stores the bias
// and then loads the slots, all sequentially consistent, so at least one of
// them sees the other's store. The reader's release of its slot and the
// writer's acquire load of it order the reader's critical section before
// the writer's.
//
// A writer costs a scan of kSlots cache lines on top of the underlying lock.
// The DFA only writes when it resets its cache, which also frees and rebuilds
// every state, so the scan is cheap in comparison.
//
// The table is shared by all instances, so an instance costs a single flag
// on top of re2::Mutex.

#include <atomic>
#include <cstddef>
#include <thread>

#include "re2/util/mutex.h"

namespace re2 {

class ReaderBiasedMutex {
 public:
  // Identifies how a read lock was acquired; it must be passed back to
  // ReaderUnlock. A null token means the underlying mutex is held.
  class ReaderToken;

  ReaderBiasedMutex() = default;
  ~ReaderBiasedMutex() = default;

  inline ReaderToken* ReaderLock();
  inline void ReaderUnlock(ReaderToken* token);
  inline void WriterLock();
  inline void WriterUnlock() { mutex_.WriterUnlock(); }

  ReaderBiasedMutex(const ReaderBiasedMutex&) = delete;
  ReaderBiasedMutex& operator=(const ReaderBiasedMutex&) = delete;

  // Number of reader slots in the process-wide table.
  static constexpr std::size_t kSlots = 128;

 private:
  // 128 bytes rather than 64: adjacent-line prefetchers pair cache lines.
  static constexpr std::size_t kSlotAlignment = 128;

  struct alignas(kSlotAlignment) Slot {
    std::atomic<const ReaderBiasedMutex*> owner{nullptr};
  };

  static Slot slots_[kSlots];
  static std::atomic<unsigned> next_slot_;

  static inline Slot& ThisThreadSlot();
  inline void RevokeBias();

  std::atomic<bool> reader_bias_{true};
  Mutex mutex_;
};

inline ReaderBiasedMutex::Slot ReaderBiasedMutex::slots_[kSlots];
inline std::atomic<unsigned> ReaderBiasedMutex::next_slot_{0};

class ReaderBiasedMutex::ReaderToken {
 public:
  ReaderToken() = delete;
};

ReaderBiasedMutex::Slot& ReaderBiasedMutex::ThisThreadSlot() {
  // 0 means not assigned yet; otherwise the slot index plus one.
  static thread_local constinit unsigned slot_plus_one = 0;
  unsigned s = slot_plus_one;
  if (s == 0) {
    s = next_slot_.fetch_add(1, std::memory_order_relaxed) % kSlots + 1;
    slot_plus_one = s;
  }
  return slots_[s - 1];
}

ReaderBiasedMutex::ReaderToken* ReaderBiasedMutex::ReaderLock() {
  if (reader_bias_.load(std::memory_order_relaxed)) {
    Slot& slot = ThisThreadSlot();
    const ReaderBiasedMutex* expected = nullptr;
    if (slot.owner.compare_exchange_strong(expected, this,
                                           std::memory_order_seq_cst,
                                           std::memory_order_relaxed)) {
      // Pairs with the store in RevokeBias(); acquire also pairs with the
      // release in the slow path below, which follows the last writer.
      if (reader_bias_.load(std::memory_order_seq_cst))
        return reinterpret_cast<ReaderToken*>(&slot);
      // A writer is revoking the bias and may be waiting for this slot.
      slot.owner.store(nullptr, std::memory_order_release);
    }
  }

  mutex_.ReaderLock();
  // No writer can be active while the read lock is held, and the next one
  // will see the bias (it acquires the mutex after this reader releases it).
  if (!reader_bias_.load(std::memory_order_relaxed))
    reader_bias_.store(true, std::memory_order_release);
  return nullptr;
}

void ReaderBiasedMutex::ReaderUnlock(ReaderToken* token) {
  if (token != nullptr)
    reinterpret_cast<Slot*>(token)->owner.store(nullptr,
                                                std::memory_order_release);
  else
    mutex_.ReaderUnlock();
}

void ReaderBiasedMutex::WriterLock() {
  mutex_.WriterLock();
  // Only readers holding mutex_ set the bias and only writers clear it, so
  // this load sees the latest value.
  if (reader_bias_.load(std::memory_order_relaxed))
    RevokeBias();
}

void ReaderBiasedMutex::RevokeBias() {
  reader_bias_.store(false, std::memory_order_seq_cst);
  for (Slot& slot : slots_) {
    for (unsigned spins = 0;
         slot.owner.load(std::memory_order_seq_cst) == this; ++spins) {
      // Readers hold the lock for one search, which can be long; spin
      // briefly, then let them run.
      if (spins >= 64)
        std::this_thread::yield();
    }
  }
}

}  // namespace re2

#endif  // UTIL_READER_BIASED_MUTEX_H_
