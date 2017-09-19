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
 * Copyright 2015 Scylla DB
 */

#include "systemwide_memory_barrier.hh"
#include "cacheline.hh"
#include <sys/mman.h>
#include <unistd.h>
#include <cassert>
#include <sys/syscall.h>
#include <linux/membarrier.h>

namespace seastar {
static alignas(seastar::cache_line_size) bool sys_membarrier_is_available = false;

static int membarrier(int cmd, int flags) {
    return syscall(__NR_membarrier, cmd, flags);
}

void init_membarrier() {
    int ret;

    /* Check that membarrier() is supported. */
    ret = membarrier(MEMBARRIER_CMD_QUERY, 0);
    if (ret < 0) {
        sys_membarrier_is_available = false;
        return;
    }

    if (!(ret & MEMBARRIER_CMD_SHARED)) {
        sys_membarrier_is_available = false;
        return;
    }

    sys_membarrier_is_available = true;
}

// cause all threads to invoke a full memory barrier
void
systemwide_memory_barrier() {
    if (sys_membarrier_is_available) {
        membarrier(MEMBARRIER_CMD_SHARED, 0);
        return;
    }

    static thread_local char* mem = [] {
       void* mem = mmap(nullptr, getpagesize(),
               PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0) ;
       assert(mem != MAP_FAILED);
       return reinterpret_cast<char*>(mem);
    }();
    int r1 = mprotect(mem, getpagesize(), PROT_READ | PROT_WRITE);
    assert(r1 == 0);
    // Force page into memory to avoid next mprotect() attempting to be clever
    *mem = 3;
    // Force page into memory
    // lower permissions to force kernel to send IPI to all threads, with
    // a side effect of executing a memory barrier on those threads
    // FIXME: does this work on ARM?
    int r2 = mprotect(mem, getpagesize(), PROT_READ);
    assert(r2 == 0);
}
}

