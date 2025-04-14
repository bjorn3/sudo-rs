/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2004-2005, 2010-2018 Todd C. Miller <Todd.Miller@sudo.ws>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// On Linux we can use a seccomp() filter to disable exec.

#[cfg(not(target_os = "linux"))]
compile_error!("sudo_noexec shouldn't be compiled for non-Linux systems");

use std::mem::offset_of;
use std::ptr::addr_of;

use libc::{
    BPF_ABS, BPF_JEQ, BPF_JMP, BPF_JUMP, BPF_K, BPF_LD, BPF_RET, BPF_STMT, EACCES,
    PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, SECCOMP_RET_ALLOW, SECCOMP_RET_DATA,
    SECCOMP_RET_ERRNO, SYS_execve, SYS_execveat, c_uint, prctl, seccomp_data, sock_filter,
    sock_fprog,
};

#[used]
#[unsafe(link_section = ".init_array")]
static NOEXEC_CTOR: extern "C" fn() = noexec_ctor;

extern "C" fn noexec_ctor() {
    // SAFETY: libc unnecessarily marks these functions as unsafe
    let exec_filter: [sock_filter; 5] = unsafe {
        [
            // Load syscall number into the accumulator
            BPF_STMT((BPF_LD | BPF_ABS) as _, offset_of!(seccomp_data, nr) as _),
            // Jump to deny for execve/execveat
            BPF_JUMP((BPF_JMP | BPF_JEQ | BPF_K) as _, SYS_execve as _, 2, 0),
            BPF_JUMP((BPF_JMP | BPF_JEQ | BPF_K) as _, SYS_execveat as _, 1, 0),
            // Allow non-matching syscalls
            BPF_STMT((BPF_RET | BPF_K) as _, SECCOMP_RET_ALLOW),
            // Deny execve/execveat syscall
            BPF_STMT(
                (BPF_RET | BPF_K) as _,
                (SECCOMP_RET_ERRNO | (EACCES as c_uint & SECCOMP_RET_DATA)) as _,
            ),
        ]
    };

    let exec_fprog = sock_fprog {
        len: 5,
        filter: addr_of!(exec_filter) as *mut sock_filter,
    };

    // SAFETY: The first prctl is trivially safe as it doesn't touch any memory
    // and the second prctl passes a valid sock_fprog as argument.
    unsafe {
        // SECCOMP_MODE_FILTER will fail unless the process has
        // CAP_SYS_ADMIN or the no_new_privs bit is set.
        if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 {
            prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &exec_fprog);
        }
    }
}
