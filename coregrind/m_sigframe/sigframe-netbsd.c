/* -*- mode: C; c-basic-offset: 3; -*- */
/*--------------------------------------------------------------------*/
/*--- Create/destroy signal delivery frames.                       ---*/
/*---                                            sigframe-netbsd.c ---*/
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

#if defined(VGO_netbsd)

#include "libvex_guest_offsets.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcprint.h"
#include "pub_core_machine.h"
#include "pub_core_options.h"
#include "pub_core_sigframe.h"      /* Self */
#include "pub_core_syswrap.h"
#include "pub_core_tooliface.h"
#include "priv_sigframe.h"

/* This module creates and removes signal frames for signal deliveries
 * on NetBSD. */

/* Create a signal frame for thread 'tid'. */
void VG_(sigframe_create)(ThreadId tid, Bool on_altstack,
                          Addr sp_top_of_frame, const vki_siginfo_t *siginfo,
                          const struct vki_ucontext *siguc,
                          void *handler, UInt flags, const vki_sigset_t *mask,
                          void *trampoline, UInt tramp_abi)
{
   ThreadState *tst = VG_(get_ThreadState)(tid);

   /* Check if the trampoline ABI is actually supported. */
   switch (tramp_abi) {
   case 2:
   case 3:
      /* siginfo, user supplied trampoline */
      vg_assert(trampoline != NULL);
      break;

   default:
      VG_(unimplemented)("NetBSD signal trampoline ABI %u", tramp_abi);
   }

   /* Calculate new stack pointer. The original stack redzone, if
    * present, has already been skipped by the caller but we have to
    * increase the size of frame because ML_(sf_maybe_extend_stack)
    * slides the validity area down. XXX: I think it's a bug. */
   Addr sp;
   const SizeT frame_size = sizeof(struct vki_sigframe_siginfo) + VG_STACK_REDZONE_SZB;

#if defined(VGA_amd64)
   sp = sp_top_of_frame - frame_size;
   sp = VG_ROUNDDN(sp, 16) - sizeof(UWord);
#else
#  error Unknown architecture
#endif

   if (!ML_(sf_maybe_extend_stack)(tst, sp, frame_size, flags))
      return;

   /* Start filling in the signal frame. */
   struct vki_sigframe_siginfo *fr = (struct vki_sigframe_siginfo *)sp;

   /* Save the current context. This has to be done before the thread
    * state is modified in any way. */
   VG_(save_context)(tid, &fr->sf_uc, Vg_CoreSignal);

   /* Save ERR and TRAPNO if siguc is present. */
   if (siguc) {
      fr->sf_uc.uc_mcontext.__gregs[VKI_REG_ERR]
         = siguc->uc_mcontext.__gregs[VKI_REG_ERR];
      VG_TRACK(post_mem_write, Vg_CoreSignal, tid,
               (Addr)&fr->sf_uc.uc_mcontext.__gregs[VKI_REG_ERR], sizeof(UWord));

      fr->sf_uc.uc_mcontext.__gregs[VKI_REG_TRAPNO]
         = siguc->uc_mcontext.__gregs[VKI_REG_TRAPNO];
      VG_TRACK(post_mem_write, Vg_CoreSignal, tid,
               (Addr)&fr->sf_uc.uc_mcontext.__gregs[VKI_REG_TRAPNO], sizeof(UWord));
   }

   /* Upon returning from the handler, the client should land on the
    * trampoline it provided. The trampoline is supposed to invoke
    * setcontext(2) to actually return to the original
    * site. Unfortunately there is no unused area in ucontext_t to
    * store "signo" so we cannot inform the tool that the processing
    * for the given signal has ended.
    */
   VG_TRACK(pre_mem_write, Vg_CoreSignal, tid, "fr.sf_ra",
            (Addr)&fr->sf_ra, sizeof(UWord));
   fr->sf_ra = (UWord)trampoline;
   VG_TRACK(post_mem_write, Vg_CoreSignal, tid,
            (Addr)&fr->sf_ra, sizeof(fr->sf_ra));

   /* Fill in the siginfo. */
   VG_TRACK(pre_mem_write, Vg_CoreSignal, tid, "fr.sf_si",
            (Addr)&fr->sf_si, sizeof(fr->sf_si));
   fr->sf_si = *siginfo;

   /* Set expected si_addr value.
    *
    * Manual page siginfo(3) describes that some signals define
    * si_addr to be an address of the faulting instruction
    * (SIGILL). Then it is needed to change the real CPU address to
    * the VCPU address. Some signals define si_addr to be an address
    * of the faulting memory reference (SIGSEGV, SIGBUS). Then the
    * address should be passed unmodified.
    */
   switch (siginfo->si_signo) {
   case VKI_SIGSEGV:
      switch (siginfo->si_code) {
      case VKI_SEGV_MADE_UP_GPF:
         /* Translate si_code synthesized by Valgrind to
          * SEGV_MAPERR. */
         fr->sf_si.si_code = VKI_SEGV_MAPERR;
         break;
      default:
         break;
      }
      break;
   case VKI_SIGILL:
   case VKI_SIGFPE:
   case VKI_SIGTRAP:
      fr->sf_si.si_addr = (void*)VG_(get_IP)(tid);
      break;
   default:
      break;
   }
   VG_TRACK(post_mem_write, Vg_CoreSignal, tid,
            (Addr)&fr->sf_si, sizeof(fr->sf_si));

   /* Now we have a complete signal frame. Set up parameters for the
    * signal handler. */
#if defined(VGA_amd64)
   tst->arch.vex.guest_RDI = siginfo->si_signo;
   VG_TRACK(post_reg_write, Vg_CoreSignal, tid, OFFSET_amd64_RDI, sizeof(UWord));

   /* On this ABI the kernel is supposed to provide 3 args regardless
    * of whether SA_SIGINFO has been requested or not. */
   tst->arch.vex.guest_RSI = (UWord)&fr->sf_si;
   VG_TRACK(post_reg_write, Vg_CoreSignal, tid, OFFSET_amd64_RSI, sizeof(UWord));

   tst->arch.vex.guest_RDX = (UWord)&fr->sf_uc;
   VG_TRACK(post_reg_write, Vg_CoreSignal, tid, OFFSET_amd64_RDX, sizeof(UWord));

   /* The address of ucontext is supposed to be saved also in r15. It
    * will be used by the trampoline.
    */
   tst->arch.vex.guest_R15 = (UWord)&fr->sf_uc;
   VG_TRACK(post_reg_write, Vg_CoreSignal, tid, OFFSET_amd64_R15, sizeof(UWord));

#else
#  error Unknown architecture
#endif

   /* Set up the stack pointer. */
   vg_assert(sp == (Addr)&fr->sf_ra);
   VG_(set_SP)(tid, sp);
   VG_TRACK(post_reg_write, Vg_CoreSignal, tid, VG_O_STACK_PTR, sizeof(Addr));

   /* Set up the program counter. Note that we don't inform a tool
    * about IP write because IP is always defined. */
   VG_(set_IP)(tid, (Addr)handler);

   if (VG_(clo_trace_signals))
      VG_(message)(Vg_DebugMsg,
                   "sigframe_create (thread %u): next IP=%#lx, next SP=%#lx\n",
                   tid, (Addr)handler, (Addr)fr);
}

void VG_(sigframe_destroy)( ThreadId tid, Bool isRT )
{
   /* Not used on NetBSD */
   vg_assert(0);
}

#endif // defined(VGO_netbsd)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
