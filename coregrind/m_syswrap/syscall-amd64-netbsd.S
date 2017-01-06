/*--------------------------------------------------------------------*/
/*--- Support for doing system calls.       syscall-amd64-netbsd.S ---*/
/*--------------------------------------------------------------------*/

/*
  This file is part of Valgrind, a dynamic binary instrumentation
  framework.

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 2 of the
  License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
  02111-1307, USA.

  The GNU General Public License is contained in the file COPYING.
*/

#include "pub_core_basics_asm.h"

#if defined(VGP_amd64_netbsd)

#include "pub_core_vkiscnums_asm.h"
#include "libvex_guest_offsets.h"

/* from vki-netbsd.h, checked at startup by m_vki.c */
#define VKI_SIG_SETMASK 3

/* Prototype:
 * Int ML_(do_syscall_for_client_WRK)(
 *    Int syscallno,                // %rdi = %rbp-40
 *    void *guest_state,            // %rsi = %rbp-32
 *    const vki_sigset_t *sysmask,  // %rdx = %rbp-24
 *    const vki_sigset_t *postmask, // %rcx = %rbp-16
 *    UChar *cflag)                 // %r8  = %rbp-8
 */

/* Establish stack frame. */
.macro ESTABLISH_STACKFRAME
    pushq   %rbp
    movq    %rsp, %rbp

    /* Push the parameters on the stack. */
    pushq   %r8   /* cflag       at %rbp-8 */
    pushq   %rcx  /* postmask    at %rbp-16 */
    pushq   %rdx  /* sysmask     at %rbp-24 */
    pushq   %rsi  /* guest_state at %rbp-36 */
    pushq   %rdi  /* syscallno   at %rbp-40 */
.endm

/* Set the signal mask which should be current during the syscall. */
.macro UNBLOCK_SIGNALS
    /* Set up for sigprocmask(SIG_SETMASK, sysmask, postmask). */
    movq    $__NR_sigprocmask, %rax
    movq    $VKI_SIG_SETMASK, %rdi
    movq    -24(%rbp), %rsi
    movq    -16(%rbp), %rdx
    syscall
    jc      sigprocmask_failed
.endm

.macro REBLOCK_SIGNALS
    /* Set up for sigprocmask(SIG_SETMASK, postmask, NULL). */
    movq    $__NR_sigprocmask, %rax
    movq    $VKI_SIG_SETMASK, %rdi
    movq    -16(%rbp), %rsi
    movq    $0, %rdx
    syscall
    /* The syscall above changes the carry flag.  This means that if the
     * syscall fails and we receive an interrupt after it then we've got
     * an invalid carry flag value in the fixup code.  We don't care about
     * it because this syscall should never fail and if it does then we're
     * going to stop Valgrind anyway. */
    jc      sigprocmask_failed
.endm

/* Success: return 0x0000 */
.macro SIMPLE_RETURN
    xorq    %rax, %rax
    movq    %rbp, %rsp
    popq    %rbp
    ret
.endm

/* Failure: return 0x8000 | error code. */
.macro ERROR_RETURN
    andq    $0x7FFF, %rax
    orq     $0x8000, %rax
    movq    %rbp, %rsp
    popq    %rbp
    ret
.endm

.text
.globl ML_(do_syscall_for_client_WRK)
.type  ML_(do_syscall_for_client_WRK), @function
ML_(do_syscall_for_client_WRK):
    ESTABLISH_STACKFRAME

    /* Even though we can't take a signal until the sigprocmask completes,
     * start the range early. If rip is in the range [1,2), the
     * syscall hasn't been started yet */
1:  UNBLOCK_SIGNALS

    /* Copy syscall parameters to registers and the stack - assume no
     * more than 8 plus the return address. */
    /* 6 register parameters. */
    movq    -32(%rbp), %rax
    movq    OFFSET_amd64_RDI(%rax), %rdi
    movq    OFFSET_amd64_RSI(%rax), %rsi
    movq    OFFSET_amd64_RDX(%rax), %rdx
    movq    OFFSET_amd64_R10(%rax), %r10
    movq    OFFSET_amd64_R8(%rax), %r8
    movq    OFFSET_amd64_R9(%rax), %r9
    /* 2 stack parameters */
    movq    OFFSET_amd64_RSP(%rax), %rax
    movq    16(%rax), %r11
    pushq   %r11
    movq    8(%rax), %r11
    pushq   %r11
    /* Return address. */
    movq    0(%rax), %r11
    pushq   %r11

    /* Put syscall number in %rax. */
    movq    -40(%rbp), %rax

    /* If rip==2, then the syscall was either just about to start,
     * or was interrupted and the kernel was restarting it. */
2:  syscall

    /* In the range [3, 4), the syscall result is in %rax, %rdx and C,
     * but hasn't been committed to the thread state. If we get
     * interrupted in this section then we'll just use values saved in
     * the ucontext structure.
     *
     * Important note for this and the following section: Don't add here
     * any code that alters the carry flag or worse, call any function.
     * That would completely break the fixup after an interrupt.
     */
3:  movq    -32(%rbp), %rcx
    movq    %rax, OFFSET_amd64_RAX(%rcx) /* save %rax to VEX */
    movq    %rdx, OFFSET_amd64_RDX(%rcx) /* save %rdx to VEX */
    movq    -8(%rbp), %rcx
    setc    0(%rcx)         /* save returned carry flag */

    /* Re-block signals.  If eip is in [4,5), then the syscall is
     * complete and we needn't worry about it. We have to only
     * correctly save the carry flag.  If we get interrupted in this
     * section then we just have to propagate the carry flag from the
     * ucontext structure to the thread state, %rax and %rdx values are
     * already saved.*/
4:  REBLOCK_SIGNALS

    /* Now safe from signals. */
5:  SIMPLE_RETURN

sigprocmask_failed:
    ERROR_RETURN
.size ML_(do_syscall_for_client_WRK), . - ML_(do_syscall_for_client_WRK)

.section .rodata
/* export the ranges so that
 * VG_(fixup_guest_state_after_syscall_interrupted) can do the
 * right thing */

.globl ML_(blksys_setup)
.globl ML_(blksys_restart)
.globl ML_(blksys_complete)
.globl ML_(blksys_committed)
.globl ML_(blksys_finished)
ML_(blksys_setup):      .long 1b
ML_(blksys_restart):    .long 2b
ML_(blksys_complete):   .long 3b
ML_(blksys_committed):  .long 4b
ML_(blksys_finished):   .long 5b
.previous

#endif // defined(VGP_amd64_netbsd)

/* Let the linker know we don't need an executable stack */
MARK_STACK_NO_EXEC

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
