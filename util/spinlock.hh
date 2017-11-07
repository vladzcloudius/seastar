/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright 2016 ScyllaDB
 */

#pragma once

#include <atomic>

#if defined(__x86_64__) || defined(__i386__)
#include <xmmintrin.h>

#define SEASTAR_PAUSE() \
do {                    \
    _mm_pause();        \
} while(0)

#elif defined(__PPC__)

#define SEASTAR_PAUSE()        \
do {                           \
    __asm__ volatile("yield"); \
} while(0)

#elif defined(__s390x__) || defined(__zarch__)

// FIXME: there must be a better way
#define SEASTAR_PAUSE() do { /* do nothing */ } while(0)

#else
#error "SEASTAR_PAUSE() is not defined for this architecture"
#endif

namespace seastar {

namespace util {

// Spin lock implementation.
// BasicLockable.
// Async-signal safe.
// unlock() "synchronizes with" lock().
class spinlock {
    std::atomic<bool> _busy = { false };
public:
    spinlock() = default;
    spinlock(const spinlock&) = delete;
    ~spinlock() { assert(!_busy.load(std::memory_order_relaxed)); }
    void lock() noexcept {
        while (_busy.exchange(true, std::memory_order_acquire)) {
            SEASTAR_PAUSE();
        }
    }
    void unlock() noexcept {
        _busy.store(false, std::memory_order_release);
    }
};

}

}
