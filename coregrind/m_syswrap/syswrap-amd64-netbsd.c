/* -*- mode: C; c-basic-offset: 3; -*- */
/*--------------------------------------------------------------------*/
/*--- Platform-specific syscalls stuff.       syswrap-x86-netbsd.c ---*/
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

#if defined(VGP_amd64_netbsd)

#include "libvex_guest_offsets.h"

#include "pub_core_basics.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcsignal.h"
#include "pub_core_syscall.h"
#include "pub_core_syswrap.h"
#include "pub_core_threadstate.h"
#include "pub_core_vkiscnums.h"

#include "priv_types_n_macros.h"
#include "priv_syswrap-generic.h"
#include "priv_syswrap-netbsd.h"

/* Call f(arg1), but first switch stacks, using 'stack' as the new stack, and
   use 'retaddr' as f's return-to address.  Also, clear all the integer
   registers before entering f. */
__attribute__((noreturn))
void ML_(call_on_new_stack_0_1)(Addr stack,             /* %rdi */
                                Addr retaddr,           /* %rsi */
                                void (*f)(Word),        /* %rdx */
                                Word arg1);             /* %rcx */
__asm__ (
".text\n"
".globl vgModuleLocal_call_on_new_stack_0_1\n"
"vgModuleLocal_call_on_new_stack_0_1:\n"
"   movq  %rdi, %rsp\n"         /* set stack */
"   movq  %rcx, %rdi\n"         /* set arg1 */
"   pushq %rsi\n"               /* retaddr to stack */
"   pushq %rdx\n"               /* f to stack */
"   movq  $0, %rax\n"           /* zero all GP regs (except %rdi) */
"   movq  $0, %rbx\n"
"   movq  $0, %rcx\n"
"   movq  $0, %rdx\n"
"   movq  $0, %rsi\n"
"   movq  $0, %rbp\n"
"   movq  $0, %r8\n"
"   movq  $0, %r9\n"
"   movq  $0, %r10\n"
"   movq  $0, %r11\n"
"   movq  $0, %r12\n"
"   movq  $0, %r13\n"
"   movq  $0, %r14\n"
"   movq  $0, %r15\n"
"   ret\n"                      /* jump to f */
"   ud2\n"                      /* should never get here */
".previous\n"
);

/* This function is called to setup a context of a new Valgrind thread (which
   will run the client code). */
void ML_(setup_start_thread_context)(ThreadId tid, vki_ucontext_t *uc)
{
   ThreadState *tst = VG_(get_ThreadState)(tid);
   UWord *stack = (UWord*)tst->os_state.valgrind_stack_init_SP;

   VG_(do_syscall1)(__NR_getcontext, (UWord)uc);
   uc->uc_link = NULL;

   /* Start the thread with everything blocked. */
   VG_(sigfillset)(&uc->uc_sigmask);
   uc->uc_flags |= VKI_UC_SIGMASK;

   /* Set up the stack, it should be always 16-byte aligned before doing
      a function call, i.e. the first parameter is also 16-byte aligned. */
   vg_assert(VG_IS_16_ALIGNED(stack));
   stack -= 1;
   stack[0] = 0; /* bogus return value */
   uc->uc_flags &= ~VKI_UC_STACK; /* We don't know the size of our stack */

   /* Set up the registers. */
   uc->uc_mcontext.__gregs[VKI_REG_RDI] = (UWord)tst; /* the parameter */
   uc->uc_mcontext.__gregs[VKI_REG_RIP] = (UWord)ML_(start_thread_NORETURN);
   uc->uc_mcontext.__gregs[VKI_REG_RSP] = (UWord)stack;
   uc->uc_flags |= VKI_UC_CPU;

   /* We don't have TLS. */
   uc->uc_flags &= ~VKI_UC_TLSBASE;
}

void VG_(cleanup_thread) ( ThreadArchState *arch )
{
   /* Do nothing for amd64. */
}

/* Architecture-specific part of VG_(save_context). */
static void save_mc_cpu(ThreadId tid, vki_ucontext_t *uc,
                        CorePart part)
{
   ThreadState *tst = VG_(get_ThreadState)(tid);

   /* Copy general registers member by member */
   /* Common registers */
   uc->uc_mcontext.__gregs[VKI_REG_RIP] = tst->arch.vex.guest_RIP;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_RIP,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RIP], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_RAX] = tst->arch.vex.guest_RAX;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_RAX,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RAX], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_RBX] = tst->arch.vex.guest_RBX;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_RBX,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RBX], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_RCX] = tst->arch.vex.guest_RCX;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_RCX,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RCX], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_RDX] = tst->arch.vex.guest_RDX;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_RDX,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RDX], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_RBP] = tst->arch.vex.guest_RBP;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_RBP,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RBP], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_RSI] = tst->arch.vex.guest_RSI;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_RSI,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RSI], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_RDI] = tst->arch.vex.guest_RDI;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_RDI,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RDI], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_R8] = tst->arch.vex.guest_R8;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_R8,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R8], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_R9] = tst->arch.vex.guest_R9;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_R9,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R9], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_R10] = tst->arch.vex.guest_R10;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_R10,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R10], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_R11] = tst->arch.vex.guest_R11;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_R11,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R11], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_R12] = tst->arch.vex.guest_R12;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_R12,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R12], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_R13] = tst->arch.vex.guest_R13;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_R13,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R13], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_R14] = tst->arch.vex.guest_R14;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_R14,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R14], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_R15] = tst->arch.vex.guest_R15;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_R15,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R15], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_RSP] = tst->arch.vex.guest_RSP;
   VG_TRACK(copy_reg_to_mem, part, tid, OFFSET_amd64_RSP,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RSP], sizeof(UWord));

   /* ERR and TRAPNO */
   uc->uc_mcontext.__gregs[VKI_REG_ERR] = 0;
   VG_TRACK(post_mem_write, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_ERR], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_TRAPNO] = 0;
   VG_TRACK(post_mem_write, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_TRAPNO], sizeof(UWord));

   /* Segment registers */
   /* Valgrind does not support moves from/to segment registers on AMD64.  The
      values returned below are the ones that are set by the kernel when
      a program is started. */
   uc->uc_mcontext.__gregs[VKI_REG_CS] = 0;
   VG_TRACK(post_mem_write, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_CS], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_DS] = 0;
   VG_TRACK(post_mem_write, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_DS], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_SS] = 0;
   VG_TRACK(post_mem_write, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_SS], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_ES] = 0;
   VG_TRACK(post_mem_write, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_ES], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_FS] = 0;
   VG_TRACK(post_mem_write, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_FS], sizeof(UWord));
   uc->uc_mcontext.__gregs[VKI_REG_GS] = 0;
   VG_TRACK(post_mem_write, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_GS], sizeof(UWord));

   /* Save rflags. There is no unused area in ucontext_t so we can't
    * do anything special as in syswrap-amd64-solaris.c */
   uc->uc_mcontext.__gregs[VKI_REG_RFLAGS] =
      LibVEX_GuestAMD64_get_rflags(&tst->arch.vex);
   VG_TRACK(post_mem_write, part, tid,
         (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RFLAGS], sizeof(UWord));

   /* Now we saved the CPU state. */
   uc->uc_flags |= VKI_UC_CPU;
}

static void save_mc_fpu(ThreadId tid, vki_ucontext_t *uc,
                        CorePart part)
{
   ThreadState *tst = VG_(get_ThreadState)(tid);
   vki_fpregset_t *fs = &uc->uc_mcontext.__fpregs;

   /* The fpregset_t structure on amd64 follows the layout that is used by the
    * FXSAVE instruction, therefore it is only necessary to call a VEX
    * function that simulates this instruction. */
   LibVEX_GuestAMD64_fxsave(&tst->arch.vex, (HWord)fs);
   VG_TRACK(post_mem_write, part, tid, (Addr)fs, sizeof(*fs));

   /* Now we saved the FPU state. */
   uc->uc_flags |= VKI_UC_FPU;
}

static void save_mc_tlsbase(ThreadId tid, vki_ucontext_t *uc,
                            CorePart part)
{
   ThreadState *tst = VG_(get_ThreadState)(tid);

   /* Segment bases (only %fs base needs to be saved on amd64) */
   uc->uc_mcontext._mc_tlsbase = tst->arch.vex.guest_FS_CONST;
   VG_TRACK(post_mem_write, part, tid,
            (Addr)&uc->uc_mcontext._mc_tlsbase, sizeof(UWord));

   /* Now we saved the TLS base. */
   uc->uc_flags |= VKI_UC_TLSBASE;
}

void ML_(save_machine_context)(ThreadId tid, vki_ucontext_t *uc,
                               CorePart part)
{
   save_mc_cpu(tid, uc, part);
   save_mc_fpu(tid, uc, part);
   save_mc_tlsbase(tid, uc, part);
}

static void restore_mc_cpu(ThreadId tid, vki_ucontext_t *uc,
                           CorePart part)
{
   ThreadState *tst = VG_(get_ThreadState)(tid);

   /* Common registers */
   tst->arch.vex.guest_RIP = uc->uc_mcontext.__gregs[VKI_REG_RIP];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RIP], OFFSET_amd64_RIP,
            sizeof(UWord));
   tst->arch.vex.guest_RAX = uc->uc_mcontext.__gregs[VKI_REG_RAX];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RAX], OFFSET_amd64_RAX,
            sizeof(UWord));
   tst->arch.vex.guest_RBX = uc->uc_mcontext.__gregs[VKI_REG_RBX];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RBX], OFFSET_amd64_RBX,
            sizeof(UWord));
   tst->arch.vex.guest_RCX = uc->uc_mcontext.__gregs[VKI_REG_RCX];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RCX], OFFSET_amd64_RCX,
            sizeof(UWord));
   tst->arch.vex.guest_RDX = uc->uc_mcontext.__gregs[VKI_REG_RDX];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RDX], OFFSET_amd64_RDX,
            sizeof(UWord));
   tst->arch.vex.guest_RBP = uc->uc_mcontext.__gregs[VKI_REG_RBP];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RBP], OFFSET_amd64_RBP,
            sizeof(UWord));
   tst->arch.vex.guest_RSI = uc->uc_mcontext.__gregs[VKI_REG_RSI];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RSI], OFFSET_amd64_RSI,
            sizeof(UWord));
   tst->arch.vex.guest_RDI = uc->uc_mcontext.__gregs[VKI_REG_RDI];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RDI], OFFSET_amd64_RDI,
            sizeof(UWord));
   tst->arch.vex.guest_R8 = uc->uc_mcontext.__gregs[VKI_REG_R8];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R8], OFFSET_amd64_R8,
            sizeof(UWord));
   tst->arch.vex.guest_R9 = uc->uc_mcontext.__gregs[VKI_REG_R9];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R9], OFFSET_amd64_R9,
            sizeof(UWord));
   tst->arch.vex.guest_R10 = uc->uc_mcontext.__gregs[VKI_REG_R10];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R10], OFFSET_amd64_R10,
            sizeof(UWord));
   tst->arch.vex.guest_R11 = uc->uc_mcontext.__gregs[VKI_REG_R11];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R11], OFFSET_amd64_R11,
            sizeof(UWord));
   tst->arch.vex.guest_R12 = uc->uc_mcontext.__gregs[VKI_REG_R12];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R12], OFFSET_amd64_R12,
            sizeof(UWord));
   tst->arch.vex.guest_R13 = uc->uc_mcontext.__gregs[VKI_REG_R13];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R13], OFFSET_amd64_R13,
            sizeof(UWord));
   tst->arch.vex.guest_R14 = uc->uc_mcontext.__gregs[VKI_REG_R14];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R14], OFFSET_amd64_R14,
            sizeof(UWord));
   tst->arch.vex.guest_R15 = uc->uc_mcontext.__gregs[VKI_REG_R15];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_R15], OFFSET_amd64_R15,
            sizeof(UWord));
   tst->arch.vex.guest_RSP = uc->uc_mcontext.__gregs[VKI_REG_RSP];
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RSP], OFFSET_amd64_RSP,
            sizeof(UWord));

   /* Ignore ERR and TRAPNO. */

   /* Ignore segment registers. */

   /* Rflags are only partially restored. */
   VG_TRACK(pre_mem_read, part, tid,
            "restore_mc_cpu(uc->uc_mcontext.__gregs[VKI_REG_RFLAGS])",
            (Addr)&uc->uc_mcontext.__gregs[VKI_REG_RFLAGS], sizeof(UWord));

   ULong new_rflags  = uc->uc_mcontext.__gregs[VKI_REG_RFLAGS] & VKI_PSL_USER;
   LibVEX_GuestAMD64_put_rflags(new_rflags, &tst->arch.vex);

   VG_TRACK(post_reg_write, part, tid,
            offsetof(VexGuestAMD64State, guest_CC_DEP1), sizeof(UWord));
   VG_TRACK(post_reg_write, part, tid,
            offsetof(VexGuestAMD64State, guest_CC_DEP2), sizeof(UWord));
}

static void restore_mc_fpu(ThreadId tid, vki_ucontext_t *uc,
                           CorePart part)
{
   ThreadState *tst = VG_(get_ThreadState)(tid);
   vki_fpregset_t *fs = &uc->uc_mcontext.__fpregs;

   VG_TRACK(pre_mem_read, part, tid,
            "restore_mc_fpu(uc->uc_mcontext.__fpregs)",
            (Addr)fs, sizeof(*fs));
   VexEmNote note = LibVEX_GuestAMD64_fxrstor((HWord)fs, &tst->arch.vex);
   if (note != EmNote_NONE)
      VG_(message)(Vg_UserMsg,
                   "Error restoring FP state in thread %u: %s.\n",
                   tid, LibVEX_EmNote_string(note));
   // XXX: How do we tell tools that we did copy_mem_to_reg while our
   // vki_fpregset_t is just an array of char?
}

static void restore_mc_tlsbase(ThreadId tid, vki_ucontext_t *uc,
                               CorePart part)
{
   ThreadState *tst = VG_(get_ThreadState)(tid);

   /* Segment bases (only %fs base needs to be restored on amd64) */
   tst->arch.vex.guest_FS_CONST = uc->uc_mcontext._mc_tlsbase;
   VG_TRACK(copy_mem_to_reg, part, tid,
            (Addr)&uc->uc_mcontext._mc_tlsbase,
            offsetof(VexGuestAMD64State, guest_FS_CONST), sizeof(UWord));
}

void ML_(restore_machine_context)(ThreadId tid, vki_ucontext_t *uc,
                                  CorePart part)
{
   if ((uc->uc_flags & VKI_UC_CPU) != 0) {
      restore_mc_cpu(tid, uc, part);
   }
   if ((uc->uc_flags & VKI_UC_FPU) != 0) {
      restore_mc_fpu(tid, uc, part);
   }
   if ((uc->uc_flags & VKI_UC_TLSBASE) != 0) {
      restore_mc_tlsbase(tid, uc, part);
   }
}

#endif // defined(VGP_amd64_netbsd)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
