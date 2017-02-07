/* -*- mode: C; c-basic-offset: 3; -*- */

/*--------------------------------------------------------------------*/
/*--- NetBSD-specific syscalls, etc.              syswrap-netbsd.c ---*/
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

#include "pub_core_aspacemgr.h"
#include "pub_core_basics.h"
#include "pub_core_clientstate.h"
#include "pub_core_debuglog.h"
#include "pub_core_inner.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcfile.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"
#include "pub_core_machine.h"
#include "pub_core_options.h"
#include "pub_core_scheduler.h"
#include "pub_core_signals.h"
#include "pub_core_syscall.h"
#include "pub_core_syswrap.h"
#include "pub_core_vki.h"
#include "pub_core_vkiscnums.h"

#include "priv_types_n_macros.h"
#include "priv_syswrap-generic.h"
#include "priv_syswrap-netbsd.h"
#include "priv_syswrap-main.h"

// Run a thread from beginning to end and return the thread's
// scheduler-return-code.
static VgSchedReturnCode thread_wrapper(Word /*ThreadId*/ tidW)
{
   VgSchedReturnCode ret;
   ThreadId     tid = (ThreadId)tidW;
   ThreadState* tst = VG_(get_ThreadState)(tid);

   VG_(debugLog)(1, "syswrap-netbsd",
                    "thread_wrapper(tid=%u): entry\n",
                    tid);

   vg_assert(tst->status == VgTs_Init);

   /* make sure we get the CPU lock before doing anything significant */
   VG_(acquire_BigLock)(tid, "thread_wrapper(starting new thread)");

   if (0)
      VG_(printf)("thread tid %u started: stack = %p\n",
          tid, (void *)&tid);

   /* Make sure error reporting is enabled in the new thread. */
   tst->err_disablement_level = 0;

   VG_TRACK(pre_thread_first_insn, tid);

   tst->os_state.lwpid = VG_(gettid)();
   tst->os_state.threadgroup = VG_(getpid)();

   /* Thread created with all signals blocked; scheduler will set the
      appropriate mask */

   ret = VG_(scheduler)(tid);

   vg_assert(VG_(is_exiting)(tid));

   vg_assert(tst->status == VgTs_Runnable);
   vg_assert(VG_(is_running_thread)(tid));

   VG_(debugLog)(1, "syswrap-netbsd",
                    "thread_wrapper(tid=%u): exit, schedreturncode %s\n",
                    tid, VG_(name_of_VgSchedReturnCode)(ret));

   /* Return to caller, still holding the lock. */
   return ret;
}

/* Run a thread all the way to the end, then do appropriate exit actions
   (this is the last-one-out-turn-off-the-lights bit).  */
static void run_a_thread_NORETURN (Word tidW)
{
   ThreadId          tid = (ThreadId)tidW;
   VgSchedReturnCode src;
   Int               c;
   ThreadState*      tst;
#ifdef ENABLE_INNER_CLIENT_REQUEST
   Int               registered_vgstack_id;
#endif

   VG_(debugLog)(1, "syswrap-netbsd",
                    "run_a_thread_NORETURN(tid=%u): pre-thread_wrapper\n",
                    tid);

   tst = VG_(get_ThreadState)(tid);
   vg_assert(tst);

   /* A thread has two stacks:
    * * the simulated stack (used by the synthetic cpu. Guest process
    *   is using this stack).
    * * the valgrind stack (used by the real cpu. Valgrind code is running
    *   on this stack).
    * When Valgrind runs as an inner, it must signal that its (real) stack
    * is the stack to use by the outer to e.g. do stacktraces.
    */
   INNER_REQUEST
      (registered_vgstack_id
       = VALGRIND_STACK_REGISTER (tst->os_state.valgrind_stack_base,
                                  tst->os_state.valgrind_stack_init_SP));

   /* Run the thread all the way through. */
   src = thread_wrapper(tid);

   VG_(debugLog)(1, "syswrap-netbsd",
                    "run_a_thread_NORETURN(tid=%u): post-thread_wrapper\n",
                    tid);

   c = VG_(count_living_threads)();
   vg_assert(c >= 1); /* stay sane */

   // Tell the tool this thread is exiting
   VG_TRACK( pre_thread_ll_exit, tid );

   /* If the thread is exiting with errors disabled, complain loudly;
    * doing so is bad (does the user know this has happened?)  Also,
    * in all cases, be paranoid and clear the flag anyway so that the
    * thread slot is safe in this respect if later reallocated. This
    * should be unnecessary since the flag should be cleared when the
    * slot is reallocated, in thread_wrapper(). */
   if (tst->err_disablement_level > 0) {
      VG_(umsg)(
         "WARNING: exiting thread has error reporting disabled.\n"
         "WARNING: possibly as a result of some mistake in the use\n"
         "WARNING: of the VALGRIND_DISABLE_ERROR_REPORTING macros.\n"
      );
      VG_(debugLog)(
         1, "syswrap-netbsd",
            "run_a_thread_NORETURN(tid=%u): "
            "WARNING: exiting thread has err_disablement_level = %u\n",
            tid, tst->err_disablement_level
      );
   }
   tst->err_disablement_level = 0;

   if (c == 1) {
      VG_(debugLog)(1, "syswrap-netbsd",
                       "run_a_thread_NORETURN(tid=%u): "
                          "last one standing\n",
                          tid);

      /* We are the last one standing.  Keep hold of the lock and
         carry on to show final tool results, then exit the entire system.
         Use the continuation pointer set at startup in m_main. */
      ( * VG_(address_of_m_main_shutdown_actions_NORETURN) ) (tid, src);
   }
   else {
      VG_(debugLog)(1, "syswrap-netbsd",
                       "run_a_thread_NORETURN(tid=%u): "
                          "not last one standing\n",
                          tid);

       /* OK, thread is dead, but others still exist.  Just exit. */

      /* This releases the run lock */
      VG_(exit_thread)(tid);
      vg_assert(tst->status == VgTs_Zombie);
      vg_assert(sizeof(tst->status) == 4);

      INNER_REQUEST (VALGRIND_STACK_DEREGISTER (registered_vgstack_id));

      /* We have to use this sequence to terminate the thread to
       * prevent a subtle race.  If VG_(exit_thread)() had left the
       * ThreadState as Empty, then it could have been reallocated,
       * reusing the stack while we're doing these last cleanups.
       * Instead, VG_(exit_thread) leaves it as Zombie to prevent
       * reallocation.  We need to make sure we don't touch the stack
       * between marking it Empty and exiting.  Hence the
       * assembler. */
#if defined(VGP_amd64_netbsd)
      __asm__ __volatile__ (
         "movl  %[EMPTY], %[status]\n"  /* set tst->status = VgTs_Empty */
         "movq  $"VG_STRINGIFY(__NR_lwp_exit)", %%rax\n"
         "syscall\n"                    /* lwp_exit() */
         : [status] "=m" (tst->status)
         : [EMPTY] "n" (VgTs_Empty)
         : "rax", "rdx", "cc", "memory");
#else
#  error "Unknown platform"
#endif

      VG_(core_panic)("Thread exit failed?\n");
   }

   /*NOTREACHED*/
   vg_assert(0);
}

Word ML_(start_thread_NORETURN) (void* arg)
{
   ThreadState* tst = (ThreadState*)arg;
   ThreadId     tid = tst->tid;

   run_a_thread_NORETURN ( (Word)tid );
   /*NOTREACHED*/
   vg_assert(0);
}

/* Allocate a stack for this thread, if it doesn't already have one.
 * They're allocated lazily, and never freed. Returns the initial stack
 * pointer value to use, or 0 if allocation failed. */
Addr ML_(allocstack)(ThreadId tid)
{
   ThreadState* tst = VG_(get_ThreadState)(tid);
   VgStack*     stack;
   Addr         initial_SP;

   /* Either the stack_base and stack_init_SP are both zero (in which
    * case a stack hasn't been allocated) or they are both non-zero,
    * in which case it has. */

   if (tst->os_state.valgrind_stack_base == 0)
      vg_assert(tst->os_state.valgrind_stack_init_SP == 0);

   if (tst->os_state.valgrind_stack_base != 0)
      vg_assert(tst->os_state.valgrind_stack_init_SP != 0);

   /* If no stack is present, allocate one. */

   if (tst->os_state.valgrind_stack_base == 0) {
      stack = VG_(am_alloc_VgStack)( &initial_SP );
      if (stack) {
         tst->os_state.valgrind_stack_base    = (Addr)stack;
         tst->os_state.valgrind_stack_init_SP = initial_SP;
      }
   }

   if (0)
      VG_(printf)( "stack for tid %u at %p; init_SP=%p\n",
                   tid,
                   (void*)tst->os_state.valgrind_stack_base,
                   (void*)tst->os_state.valgrind_stack_init_SP );

   return tst->os_state.valgrind_stack_init_SP;
}

/* Allocate a stack for the main thread, and run it all the way to the
 * end.  Although we already have a working VgStack
 * (VG_(interim_stack)) it's better to allocate a new one, so that
 * overflow detection works uniformly for all threads.
 */
void VG_(main_thread_wrapper_NORETURN)(ThreadId tid)
{
   Addr sp;
   VG_(debugLog)(1, "syswrap-netbsd",
                    "entering VG_(main_thread_wrapper_NORETURN)\n");

   sp = ML_(allocstack)(tid);
#if defined(ENABLE_INNER_CLIENT_REQUEST)
   {
      // we must register the main thread stack before the call
      // to ML_(call_on_new_stack_0_1), otherwise the outer valgrind
      // reports 'write error' on the non registered stack.
      ThreadState* tst = VG_(get_ThreadState)(tid);
      INNER_REQUEST
         ((void)
          VALGRIND_STACK_REGISTER (tst->os_state.valgrind_stack_base,
                                   tst->os_state.valgrind_stack_init_SP));
   }
#endif

   /* If we can't even allocate the first thread's stack, we're hosed.
      Give up. */
   vg_assert2(sp != 0, "Cannot allocate main thread's stack.");

   /* shouldn't be any other threads around yet */
   vg_assert( VG_(count_living_threads)() == 1 );

   ML_(call_on_new_stack_0_1)(
      (Addr)sp,              /* stack */
      0,                     /*bogus return address*/
      run_a_thread_NORETURN, /* fn to call */
      (Word)tid              /* arg to give it */
   );

   /*NOTREACHED*/
   vg_assert(0);
}

/* Save a complete context (VCPU state, sigmask) of a given client thread
   into the vki_ucontext_t structure.  This structure is supposed to be
   allocated in the client memory, a caller must make sure that the memory can
   be dereferenced.  The active tool is informed about the save. */
void VG_(save_context)(ThreadId tid, vki_ucontext_t *uc, CorePart part)
{
   ThreadState *tst = VG_(get_ThreadState)(tid);

   VG_TRACK(pre_mem_write, part, tid, "save_context(uc)", (Addr)uc,
            sizeof(*uc));

   /* The ucontext is initially empty. */
   uc->uc_flags = 0;

   /* Old context */
   uc->uc_link = tst->os_state.oldcontext;
   VG_TRACK(post_mem_write, part, tid, (Addr)&uc->uc_link,
            sizeof(uc->uc_link));

   /* Save the current sigmask */
   uc->uc_sigmask = tst->sig_mask;
   uc->uc_flags |= VKI_UC_SIGMASK;
   VG_TRACK(post_mem_write, part, tid, (Addr)&uc->uc_sigmask,
            sizeof(uc->uc_sigmask));

   /* Stack */
   if ((tst->altstack.ss_flags & VKI_SS_ONSTACK) == 0) {
      uc->uc_stack.ss_sp    = (void*)tst->client_stack_highest_byte;
      uc->uc_stack.ss_size  = tst->client_stack_szB;
      uc->uc_stack.ss_flags = 0;
   }
   else {
      /* Simply copy alternate signal execution stack. */
      uc->uc_stack = tst->altstack;
   }
   uc->uc_flags |= VKI_UC_STACK;
   VG_TRACK(post_mem_write, part, tid, (Addr)&uc->uc_stack,
            sizeof(uc->uc_stack));

   /* Now notify tools that we have written the flags. */
   VG_TRACK(post_mem_write, part, tid, (Addr)&uc->uc_flags,
            sizeof(uc->uc_flags));

   /* Save the architecture-specific part of the context. */
   ML_(save_machine_context)(tid, uc, part);
}

/* Set a complete context (VCPU state, sigmask) of a given client thread
   according to values passed in the vki_ucontext_t structure.  This structure
   is supposed to be allocated in the client memory, a caller must make sure
   that the memory can be dereferenced.  The active tool is informed about
   what parts of the structure are read.

   This function is a counterpart to VG_(save_context)(). */
void VG_(restore_context)(ThreadId tid, vki_ucontext_t *uc, CorePart part)
{
   ThreadState *tst = VG_(get_ThreadState)(tid);
   Addr old_esp = VG_(get_SP)(tid);

   VG_TRACK(pre_mem_read, part, tid, "restore_context(uc->uc_flags)",
            (Addr)&uc->uc_flags, sizeof(uc->uc_flags));

   /* Old context */
   VG_TRACK(pre_mem_read, part, tid, "restore_context(uc->uc_link)",
            (Addr)&uc->uc_link, sizeof(uc->uc_link));
   tst->os_state.oldcontext = uc->uc_link;

   /* Sigmask */
   if ((uc->uc_flags & VKI_UC_SIGMASK) != 0) {
      SysRes res;

      VG_TRACK(pre_mem_read, part, tid, "restore_context(uc->uc_sigmask)",
               (Addr)&uc->uc_sigmask, sizeof(uc->uc_sigmask));
      res = VG_(do_sys_sigprocmask)(tid, VKI_SIG_SETMASK, &uc->uc_sigmask,
                                    NULL);
      /* Setting signal mask should never fail. */
      vg_assert(!sr_isError(res));
   }

   /* Stack */
   if ((uc->uc_flags & VKI_UC_STACK) != 0) {
      VG_TRACK(pre_mem_read, part, tid, "restore_context(uc->uc_stack)",
               (Addr)&uc->uc_stack, sizeof(uc->uc_stack));

      /* The only thing the kernel does is to update
       * tst->altstack.ss_flags equivalent, but since it's calculated
       * dynamically in m_signals.c we don't do anything here. */
   }

   /* Restore the architecture-specific part of the context. */
   ML_(restore_machine_context)(tid, uc, part);

   /* If the thread stack is already known, kill the deallocated stack area.
      This is important when returning from a signal handler. */
   if (tst->client_stack_highest_byte && tst->client_stack_szB) {
      Addr end     = tst->client_stack_highest_byte;
      Addr start   = end + 1 - tst->client_stack_szB;
      Addr new_esp = VG_(get_SP)(tid);

      /* Make sure that the old and new stack pointer are on the same (active)
         stack.  Alternate stack is currently never affected by this code. */
      if (start <= old_esp && old_esp <= end
          && start <= new_esp && new_esp <= end
          && new_esp > old_esp)
         VG_TRACK(die_mem_stack, old_esp - VG_STACK_REDZONE_SZB,
                  (new_esp - old_esp) + VG_STACK_REDZONE_SZB);
   }
}

/* ---------------------------------------------------------------------
   PRE/POST wrappers for NetBSD-specific syscalls
   ------------------------------------------------------------------ */

#define PRE(name)       DEFN_PRE_TEMPLATE(netbsd, name)
#define POST(name)      DEFN_POST_TEMPLATE(netbsd, name)

/* prototypes */
DECL_TEMPLATE(netbsd, sys_syscall);
DECL_TEMPLATE(netbsd, sys___syscall);
DECL_TEMPLATE(netbsd, sys_exit);
DECL_TEMPLATE(netbsd, sys_pipe);
DECL_TEMPLATE(netbsd, sys_ioctl);
DECL_TEMPLATE(netbsd, sys_connect);
DECL_TEMPLATE(netbsd, sys_sendto);
DECL_TEMPLATE(netbsd, sys_mmap);
DECL_TEMPLATE(netbsd, sys_ftruncate);
DECL_TEMPLATE(netbsd, sys_sysctl);
DECL_TEMPLATE(netbsd, sys_issetugid);
DECL_TEMPLATE(netbsd, sys_getcontext);
DECL_TEMPLATE(netbsd, sys_setcontext);
DECL_TEMPLATE(netbsd, sys_lwp_create);
DECL_TEMPLATE(netbsd, sys_lwp_exit);
DECL_TEMPLATE(netbsd, sys_lwp_self);
DECL_TEMPLATE(netbsd, sys_lwp_wakeup);
DECL_TEMPLATE(netbsd, sys_lwp_getprivate);
DECL_TEMPLATE(netbsd, sys_lwp_setprivate);
DECL_TEMPLATE(netbsd, sys_lwp_kill);
DECL_TEMPLATE(netbsd, sys_lwp_unpark);
DECL_TEMPLATE(netbsd, sys_lwp_unpark_all);
DECL_TEMPLATE(netbsd, sys_lwp_ctl);
DECL_TEMPLATE(netbsd, sys_sched_yield);
DECL_TEMPLATE(netbsd, sys_sigaction_sigtramp);
DECL_TEMPLATE(netbsd, sys_socket);
DECL_TEMPLATE(netbsd, sys_lwp_park);

/* implementation */
PRE(sys_syscall)
{
   /* int
    * syscall(int number, ...);
    */
   *flags |= SfMayBlock;

   /* This is the trickiest. It's a syscall indirection which takes a
    * syscall number and arguments...
    */
   PRINT("sys_syscall ( %#lx, %#lx, %#lx, %#lx, %#lx, %#lx, %#lx, %#lx )",
         ARG1, ARG2, ARG3, ARG4, ARG5, ARG6, ARG7, ARG8);

   // XXX
}

POST(sys_syscall)
{
   // XXX
}

PRE(sys___syscall)
{
   /* __quad_t
    * __syscall(quad_t number, ...);
    */
   *flags |= SfMayBlock;

   /* This is the trickiest. It's a syscall indirection which takes a
    * syscall number and arguments...
    */
   PRINT("sys___syscall ( %#lx, %#lx, %#lx, %#lx, %#lx, %#lx, %#lx, %#lx )",
         ARG1, ARG2, ARG3, ARG4, ARG5, ARG6, ARG7, ARG8);

   // XXX
}

POST(sys___syscall)
{
   // XXX
}

PRE(sys_exit)
{
   /* void _exit(int status); */
   PRINT("sys_exit( %ld )", SARG1);
   PRE_REG_READ1(void, "exit", int, status);

   for (ThreadId t = 1; t < VG_N_THREADS; t++) {
      if (VG_(threads)[t].status == VgTs_Empty)
         continue;

      /* Assign the exit code, VG_(nuke_all_threads_except) will assign
         the exitreason. */
      VG_(threads)[t].os_state.exitcode = ARG1;
   }

   /* Indicate in all other threads that the process is exiting.
      Then wait using VG_(reap_threads) for these threads to disappear.
      See comments in syswrap-linux.c, PRE(sys_exit_group) wrapper,
      for reasoning why this cannot give a deadlock. */
   VG_(nuke_all_threads_except)(tid, VgSrc_ExitProcess);
   VG_(reap_threads)(tid);
   VG_(threads)[tid].exitreason = VgSrc_ExitThread;
   /* We do assign VgSrc_ExitThread and not VgSrc_ExitProcess, as this thread
      is the thread calling exit_group and so its registers must be considered
      as not reachable. See pub_tool_machine.h VG_(apply_to_GP_regs). */

   /* We have to claim the syscall already succeeded. */
   SET_STATUS_Success(0);
}

PRE(sys_pipe)
{
   /* {int, int} pipe(); */
   PRINT("sys_pipe ( )");
   PRE_REG_READ0(int, "pipe");
}

POST(sys_pipe)
{
   if (!ML_(fd_allowed)(RES  , "pipe", tid, True) ||
       !ML_(fd_allowed)(RESHI, "pipe", tid, True)) {
      VG_(close)(RES);
      VG_(close)(RESHI);
      SET_STATUS_Failure(VKI_EMFILE);
   }
#if defined(OS_SUPPORTS_RESOLVING_FILENAME_FROM_FD)
   else if (VG_(clo_track_fds)) {
#else
   else {
#endif
      ML_(record_fd_open_nameless)(tid, RES);
      ML_(record_fd_open_nameless)(tid, RESHI);
   }
}

PRE(sys_ioctl)
{
   /* int
    * ioctl(int d, unsigned long request, ...); */
   *flags |= SfMayBlock;

   /* We first handle the ones that don't use ARG3 (even as a
    * scalar/non-pointer argument).
    */
   switch ((ULong)ARG2) {
   default:
      PRINT("sys_ioctl ( %lu, %#lx, %#lx )", ARG1, ARG2, ARG3);
      PRE_REG_READ3(int, "ioctl",
                    int, d, unsigned long, request, unsigned long, arg);
   }

   /* We now handle those that do look at ARG3 (and unknown ones fall into
    * this category).
    */
   switch ((ULong)ARG2) {
      /* <sys/ttycom.h> */
   case VKI_TIOCGETA:
      PRINT("{TIOCGETA}");
      PRE_MEM_WRITE("ioctl(TIOCGETA)", ARG3, sizeof(struct vki_termios));
      break;

   default:
      ML_(PRE_unknown_ioctl)(tid, ARG2, ARG3);
   }

   /* Be strict. */
   if (!ML_(fd_allowed)(ARG1, "ioctl", tid, False)) {
      SET_STATUS_Failure(VKI_EBADF);
   }
}

POST(sys_ioctl)
{
   switch ((ULong)ARG2) {
      /* <sys/ttycom.h> */
   case VKI_TIOCGETA:
      POST_MEM_WRITE(ARG3, sizeof(struct vki_termios));
      break;

   default:
      ML_(POST_unknown_ioctl)(tid, RES, ARG2, ARG3);
      break;
   }
}

PRE(sys_connect)
{
   /* int
    * connect(int s, const struct sockaddr *name, socklen_t namelen);
    */
   *flags |= SfMayBlock;
   PRINT("sys_connect ( %ld, %#lx, %lu )", SARG1, ARG2, ARG3);
   PRE_REG_READ3(int, "connect", int, s, const struct vki_sockaddr *, name,
                 vki_socklen_t, namelen);
   ML_(generic_PRE_sys_connect)(tid, ARG1, ARG2, ARG3);
}

PRE(sys_sendto)
{
   /* ssize_t
    * sendto(int s, const void *msg, size_t len, int flags,
    *     const struct sockaddr *to, socklen_t tolen);
    */
   *flags |= SfMayBlock;
   PRINT("sys_sendto ( %ld, %#lx, %lu, %ld, %#lx, %lu )",
         SARG1, ARG2, ARG3, SARG4, ARG5, ARG6);
   PRE_REG_READ6(vki_ssize_t, "sendto", int, s, const void *, msg,
                 vki_size_t, len, int, flags, const struct vki_sockaddr *, to,
                 vki_socklen_t, tolen);
   ML_(generic_PRE_sys_sendto)(tid, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6);
}

PRE(sys_mmap)
{
   /* void *
    * mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
    */
   SysRes r;
   ULong u;
   OffT offset;

   PRINT("sys_mmap ( %#lx, %#lx, %#lx, %#lx, %ld, %#lx, %#lx )",
         ARG1, ARG2, ARG3, ARG4, SARG5, ARG6, ARG7);

#if defined(VGA_amd64)
   PRE_REG_READ7(long, "mmap", void *, start, vki_size_t, length,
                 int, prot, int, flags, int, fd, long, pad,
                 vki_off_t, off);

   u = ARG7;
   offset = *(OffT*)&u;

#else
#  error Unknown architecture
#endif

   if (ARG2 == 0) {
      /* On NetBSD length being zero isn't an error, instead kernel
       * returns the given address without doing anything
       * meaningful. */
      r = VG_(mk_SysRes_Success)(ARG1);
   }
   else {
      r = ML_(generic_PRE_sys_mmap)(tid, ARG1, ARG2, ARG3, ARG4, ARG5, offset);
   }
   SET_STATUS_from_SysRes(r);
}

PRE(sys_ftruncate)
{
   /* int ftruncate(int fd, off_t length); */
   *flags |= SfMayBlock;
   PRINT("sys_ftruncate ( %lu, %lu, %lu )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(int, "ftruncate", int, fd, int, pad, vki_off_t, length);
}

PRE(sys_sysctl)
{
   /* int
    * sysctl(const int *name, u_int namelen, void *oldp, size_t *oldlenp,
    *     const void *newp, size_t newlen);
    */
   PRINT("sys_sysctl ( %#lx, %lu, %#lx, %#lx, %#lx, %lu )",
         ARG1, ARG2, ARG3, ARG4, ARG5, ARG6);
   PRE_REG_READ6(int, "sysctl",
                 int *, name, unsigned, namelen, void *, oldp, vki_size_t *, oldlenp,
                 void *, newp, vki_size_t, newlen);

   PRE_MEM_READ("sysctl(name)", ARG1, (unsigned)ARG2 * sizeof(int));
   if (ARG3) {
      vki_size_t *oldlenp = (vki_size_t *)ARG4;

      if (!ML_(safe_to_deref)(oldlenp, sizeof(vki_size_t))) {
         SET_STATUS_Failure( VKI_EFAULT );
         return;
      }
      PRE_MEM_WRITE("sysctl(oldp)", ARG3, *oldlenp);
   }
   if (ARG5) {
      PRE_MEM_READ("sysctl(newp)", ARG5, (vki_size_t)ARG6);
   }
}

POST(sys_sysctl)
{
   if (ARG3) {
      vki_size_t *oldlenp = (vki_size_t *)ARG4;

      POST_MEM_WRITE(ARG4, sizeof(*oldlenp));
      POST_MEM_WRITE(ARG3, *oldlenp);
   }
}

PRE(sys_issetugid)
{
   /* int issetugid(void); */
   PRINT("sys_issetugid ( )");
   PRE_REG_READ0(int, "issetugid");
}

PRE(sys_getcontext)
{
   /* int getcontext(ucontext_t *ucp); */
   PRINT("sys_getcontext ( %#lx )", ARG1);
   PRE_REG_READ1(int, "getcontext", vki_ucontext_t *, ucp);
   PRE_MEM_WRITE("getcontext(ucp)", ARG1, sizeof(vki_ucontext_t));

   if (!ML_(safe_to_deref)((void *)ARG1, sizeof(vki_ucontext_t))) {
      SET_STATUS_Failure(VKI_EFAULT);
      return;
   }

   VG_(save_context)(tid, (vki_ucontext_t *)ARG1, Vg_CoreSysCall);
   SET_STATUS_Success(0);
}

PRE(sys_setcontext)
{
   /* int setcontext(ucontext_t *ucp); */
   PRINT("sys_setcontext ( %#lx )", ARG1);
   PRE_REG_READ1(int, "setcontext", vki_ucontext_t *, ucp);

   if (!ML_(safe_to_deref)((void *)ARG1, sizeof(vki_ucontext_t))) {
      SET_STATUS_Failure(VKI_EFAULT);
      return;
   }

   VG_(restore_context)(tid, (vki_ucontext_t *)ARG1, Vg_CoreSysCall);

   /* Tell the driver not to update the guest state with the "result",
    * and set a bogus result to keep it happy. */
   *flags |= SfNoWriteResult;
   SET_STATUS_Success(0);

   /* Check to see if any signals arose as a result of this. */
   *flags |= SfPollAfter;
}

PRE(sys_lwp_create)
{
   /* int
    * _lwp_create(ucontext_t *context, unsigned long flags, lwpid_t *new_lwp); */
   PRINT("sys_lwp_create ( %#lx, %ld, %#lx )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(int, "_lwp_create",
                 vki_ucontext_t *, context, unsigned long, flags, vki_lwpid_t *, new_lwp);
   PRE_MEM_WRITE("_lwp_create(new_lwp)", ARG3, sizeof(vki_lwpid_t));

   /* If we can't deref ucontext_t then we can't do anything. */
   if (!ML_(safe_to_deref)((void*)ARG1, sizeof(vki_ucontext_t))) {
      SET_STATUS_Failure(VKI_EFAULT);
      return;
   }

   SysRes res;
   Bool tool_informed = False;

   ThreadId ctid = VG_(alloc_ThreadState)();
   ThreadState *ptst = VG_(get_ThreadState)(tid);
   ThreadState *ctst = VG_(get_ThreadState)(ctid);

   /* Allocate a V stack for the child. */
   Addr vstack = ML_(allocstack)(ctid);
   if (!vstack) {
      res = VG_(mk_SysRes_Error)(VKI_ENOMEM);
      goto out;
   }

   /* Stay sane. */
   vg_assert(VG_(is_running_thread)(tid));
   vg_assert(VG_(is_valid_tid)(ctid));

   /* First inherit parent's guest state */
   ctst->arch.vex = ptst->arch.vex;
   ctst->arch.vex_shadow1 = ptst->arch.vex_shadow1;
   ctst->arch.vex_shadow2 = ptst->arch.vex_shadow2;

   /* Set up some values. */
   ctst->os_state.parent = tid;
   ctst->os_state.threadgroup = ptst->os_state.threadgroup;
   ctst->sig_mask = ptst->sig_mask;
   ctst->tmp_sig_mask = ptst->sig_mask;

   /* Set up a stack for the child LWP */
   vki_ucontext_t *uc = (vki_ucontext_t*)ARG1;
   if ((uc->uc_flags & VKI_UC_STACK) != 0) {
      if (uc->uc_stack.ss_flags == 0) {
         /* If the sanity check of ss_flags passed register the
          * stack. But remember, it's the client that allocates the
          * client stack so we cannot really trust it's valid.
          */
         ML_(guess_and_register_stack)(
            (Addr)uc->uc_stack.ss_sp + uc->uc_stack.ss_size - 1, ctst);
      }
      else {
         VG_(debugLog)(1, "syswrap-netbsd",
                       "sys_lwp_create(tid=%u): invalid stack flags: %d\n",
                       tid, uc->uc_stack.ss_flags);
         res = VG_(mk_SysRes_Error)(VKI_EINVAL);
         goto out;
      }
   }
   else {
      VG_(debugLog)(1, "syswrap-netbsd",
                    "sys_lwp_create(tid=%u): no stack in ucontext\n", tid);
      res = VG_(mk_SysRes_Error)(VKI_EINVAL);
      goto out;
   }

   /* Inform a tool that a new thread is created.  This has to be done before
      any other core->tool event is sent. */
   vg_assert(VG_(owns_BigLock_LL)(tid));
   VG_TRACK(pre_thread_ll_create, tid, ctid);
   tool_informed = True;

   /* Now set the context of new thread according to ucontext_t. */
   VG_(restore_context)(ctid, uc, Vg_CoreSysCall);

   /* Set up V thread (this also tells the kernel to block all signals in the
      thread). */
   vki_ucontext_t kern_uc;
   ML_(setup_start_thread_context)(ctid, &kern_uc);

   /* Actually create the new thread. */
   res = VG_(do_syscall3)(__NR_lwp_create, (UWord)&kern_uc, ARG2, ARG3);

   if (!sr_isError(res)) {
      POST_MEM_WRITE(ARG3, sizeof(vki_lwpid_t));
   }

   /* New thread creation is now completed. Inform the tool. */
   VG_TRACK(pre_thread_first_insn, tid);

  out:
   if (sr_isError(res)) {
      if (tool_informed) {
         /* Tell a tool the thread exited in a hurry. */
         VG_TRACK(pre_thread_ll_exit, ctid);
      }

      /* lwp_create failed. */
      VG_(cleanup_thread)(&ctst->arch);
      ctst->status = VgTs_Empty;
   }

   SET_STATUS_from_SysRes(res);
}

PRE(sys_lwp_exit)
{
   /* void _lwp_exit(void); */
   PRINT("sys_lwp_exit ( )");
   PRE_REG_READ0(void, "_lwp_exit");

   /* Set the thread's status to be exiting, then claim that the syscall
    * succeeded. */
   ThreadState *tst = VG_(get_ThreadState)(tid);
   tst->exitreason = VgSrc_ExitThread;
   tst->os_state.exitcode = 0;
   SET_STATUS_Success(0);
}

PRE(sys_lwp_self)
{
   /* lwpid_t _lwp_self(void); */
   PRINT("sys_lwp_self ( )");
   PRE_REG_READ0(vki_lwpid_t, "_lwp_self");
}

PRE(sys_lwp_wakeup)
{
   /* int _lwp_wakeup(lwpid_t lwp); */
   PRINT("sys_lwp_wakeup ( %ld )", ARG1);
   PRE_REG_READ1(int, "_lwp_wakeup", vki_lwpid_t, lwp);
}

PRE(sys_lwp_getprivate)
{
   /* void* _lwp_getprivate(void); */
   ThreadState *tst = VG_(get_ThreadState)(tid);
   PRINT("sys_lwp_getprivate ( %#lx )", ARG1);
   PRE_REG_READ0(void, "_lwp_getprivate");

   /* We do the syscall ourselves. The kernel won't see it.
    */
#if defined(VGA_amd64)
   SET_STATUS_Success(tst->arch.vex.guest_FS_CONST);

#else
#  error Unknown architecture
#endif
}

PRE(sys_lwp_setprivate)
{
   /* void _lwp_setprivate(void *ptr); */
   ThreadState *tst = VG_(get_ThreadState)(tid);
   PRINT("sys_lwp_setprivate ( %#lx )", ARG1);
   PRE_REG_READ1(void, "_lwp_setprivate", uintptr_t, ptr);

   /* We do the syscall ourselves. The kernel won't see it.
    */
#if defined(VGA_amd64)
   tst->arch.vex.guest_FS_CONST = ARG1;

#else
#  error Unknown architecture
#endif

   /* _lwp_set_private(2) never fails. */
   SET_STATUS_Success(0);
}

PRE(sys_lwp_kill)
{
   /* int _lwp_kill(lwpid_t target_lwp, int sig); */
   PRINT("sys_lwp_kill ( %ld, %ld )", SARG1, SARG2);
   PRE_REG_READ2(long, "_lwp_kill", vki_lwpid_t, target_lwp, int, sig);

   if (!ML_(client_signal_OK)(SARG2)) {
      SET_STATUS_Failure(VKI_EINVAL);
      return;
   }

   /* If we're sending SIGKILL, check to see if the target is one of our
    * threads and handle it specially. */
   if (SARG2 == VKI_SIGKILL && ML_(do_sigkill)(SARG1, -1))
      SET_STATUS_Success(0);
   else
      SET_STATUS_from_SysRes( VG_(do_syscall2)(SYSNO, ARG1, ARG2) );

   if (VG_(clo_trace_signals))
      VG_(message)(Vg_DebugMsg, "_lwp_kill: sent signal %lu to thread %lu\n",
                   SARG2, SARG1);

   /* This kill might have given us a pending signal.  Ask for a check once
    * the syscall is done. */
   *flags |= SfPollAfter;
}

PRE(sys_lwp_unpark)
{
   /* int
    * _lwp_unpark(lwpid_t lwp, const void *hint);
    */
   PRINT("sys_lwp_unpark ( %lu, %#lx )", ARG1, ARG2);
   PRE_REG_READ2(int, "_lwp_unpark", vki_lwpid_t, lwp, const void *, hint);
}

PRE(sys_lwp_unpark_all)
{
   /* ssize_t
    * _lwp_unpark_all(const lwpid_t *targets, size_t ntargets,
    *     const void *hint);
    */
   PRINT("sys_lwp_unpark_all ( %#lx, %lu, %#lx )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(ssize_t, "_lwp_unpark_all",
                 vki_lwpid_t *, targets, vki_size_t, ntargets, void *, hint);
   if (ARG1)
      PRE_MEM_READ("_lwp_unpark_all(targets)", ARG1, ARG2 * sizeof(vki_lwpid_t));
}

PRE(sys_lwp_ctl)
{
   /* int
    * _lwp_ctl(int features, struct lwpctl **address);
    */
   PRINT("sys_lwp_ctl ( %lu, %#lx )", ARG1, ARG2);
   PRE_REG_READ2(int, "_lwp_ctl", int, features, struct vki_lwpctl **, address);
   PRE_MEM_WRITE("_lwp_ctl(address)", ARG2, sizeof(struct vki_lwpctl *));
}

POST(sys_lwp_ctl)
{
   struct vki_lwpctl* ctl = *(struct vki_lwpctl **)ARG2;
   Addr  addr = VG_PGROUNDDN((Addr)ctl);
   SizeT len  = VG_PGROUNDUP(sizeof(struct vki_lwpctl));

   POST_MEM_WRITE(ARG2, sizeof(ctl));

   /* The _lwp_ctl(2) call maps an anonymous region to user space. */
   UInt prot  = VKI_PROT_READ | VKI_PROT_WRITE;
   UInt flags = VKI_MAP_ANONYMOUS;
   ML_(notify_core_and_tool_of_mmap)(addr, len, prot, flags, -1, 0);
}

PRE(sys_sched_yield)
{
   /* int sched_yield(void);
    */
   *flags |= SfMayBlock;
   PRINT("sys_sched_yield ( )");
   PRE_REG_READ0(int, "sched_yield");
}

PRE(sys_sigaction_sigtramp)
{
   /* int
    * __sigaction_sigtramp(int sig, const struct sigaction *act,
    *       struct sigaction *oact, void *tramp, int vers);
    */
   PRINT("sys_sigaction_sigtramp ( %lu, %#lx, %#lx, %#lx, %lu )",
         ARG1, ARG2, ARG3, ARG4, ARG5);
   PRE_REG_READ5(int, "__sigaction_sigtramp",
                 int, sig, const struct sigaction *, act,
                 struct sigaction *, oact, void *, tramp, int, vers);
   if (ARG2) {
      vki_sigaction_fromK_t *act = (vki_sigaction_fromK_t*)ARG2;
      PRE_FIELD_READ("sigaction(act->sa_flags)", act->sa_flags);
      PRE_FIELD_READ("sigaction(act->sa_handler)", act->ksa_handler);
      PRE_FIELD_READ("sigaction(act->sa_mask)", act->sa_mask);
   }

   if (ARG3)
      PRE_MEM_WRITE("__sigaction_sigtramp(oact)", ARG3, sizeof(vki_sigaction_fromK_t));

   if (ARG4)
      PRE_MEM_READ("__sigaction_sigtramp(tramp)", ARG4, sizeof(UWord));

   if (ARG2 && !ML_(safe_to_deref)((void*)ARG2, sizeof(vki_sigaction_fromK_t)))
      SET_STATUS_Failure(VKI_EFAULT);

   if (ARG3 && !ML_(safe_to_deref)((void*)ARG3, sizeof(vki_sigaction_fromK_t)))
      SET_STATUS_Failure(VKI_EFAULT);

   if (ARG4 && !ML_(safe_to_deref)((void*)ARG4, sizeof(UWord))) {
      SET_STATUS_Failure(VKI_EFAULT);
   }

   if (!FAILURE) {
      /* tramp and vers have to be implanted in vki_sigaction_toK_t */
      vki_sigaction_toK_t actCopy;
      vki_sigaction_toK_t *real_act = ARG2 ? &actCopy : NULL;

      if (real_act) {
         vki_sigaction_fromK_t *act = (vki_sigaction_fromK_t*)ARG2;

         real_act->ksa_handler  = act->ksa_handler;
         real_act->sa_mask      = act->sa_mask;
         real_act->sa_flags     = act->sa_flags;
         real_act->sa_tramp     = (void*)ARG4;
         real_act->sa_tramp_abi = ARG5;
      }

      SET_STATUS_from_SysRes(
         VG_(do_sys_sigaction)(ARG1, real_act, (vki_sigaction_fromK_t*)ARG3));
   }
}

POST(sys_sigaction_sigtramp)
{
   if (ARG3)
      POST_MEM_WRITE(ARG3, sizeof(vki_sigaction_fromK_t));
}

PRE(sys_socket)
{
   /* int
    * socket(int domain, int type, int protocol);
    */
   PRINT("sys_socket ( %ld, %ld, %ld )", SARG1, SARG2, SARG3);
   PRE_REG_READ3(int, "socket", int, domain, int, type, int, protocol);
}

POST(sys_socket)
{
   SysRes r = ML_(generic_POST_sys_socket)(tid, VG_(mk_SysRes_Success)(RES));
   SET_STATUS_from_SysRes(r);
}

PRE(sys_lwp_park)
{
   /* int
    * _lwp_park(clockid_t clock_id, int flags, const struct timespec *ts,
    *     lwpid_t unpark, const void *hint, const void *unparkhint);
    */
   *flags |= SfMayBlock;
   PRINT("sys_lwp_park ( %lu, %lu, %#lx, %lu, %#lx, %#lx )",
         ARG1, ARG2, ARG3, ARG4, ARG5, ARG6);
   PRE_REG_READ6(int, "_lwp_park",
                 vki_clockid_t, clock_id, int, flags, const struct vki_timespec *, ts,
                 vki_lwpid_t, unpark, const void *, hint, const void *, unparkhint);
   if (ARG3)
      PRE_MEM_READ("_lwp_park(ts)", ARG3, sizeof(struct vki_timespec));
}

/* ---------------------------------------------------------------------
 * The NetBSD syscall table
 * ------------------------------------------------------------------ */

/* Add a Netbsd-specific, arch-independent wrapper to a syscall table. */
#define NBDX_(sysno, name)                      \
   WRAPPER_ENTRY_X_(netbsd, sysno, name)
#define NBDXY(sysno, name)                      \
   WRAPPER_ENTRY_XY(netbsd, sysno, name)

#if defined(VGP_amd64_netbsd)
/* Add an amd64-netbsd specific wrapper to a syscall table. */
#define PLAX_(sysno, name)                      \
   WRAPPER_ENTRY_X_(amd64_netbsd, sysno, name)
#define PLAXY(sysno, name)                      \
   WRAPPER_ENTRY_XY(amd64_netbsd, sysno, name)

#else
#  error "Unknown platform"
#endif

/* GEN   : handlers are in syswrap-generic.c
 * NBD   : handlers are in this file
 *    X_ : PRE handler only
 *    XY : PRE and POST handlers
 */

static SyscallTableEntry syscall_table[] = {
   NBDXY(__NR_syscall,              sys_syscall),               /*   0 */
   NBDX_(__NR_exit,                 sys_exit),                  /*   1 */
   GENX_(__NR_fork,                 sys_fork),                  /*   2 */
   GENXY(__NR_read,                 sys_read),                  /*   3 */
   GENX_(__NR_write,                sys_write),                 /*   4 */
   GENXY(__NR_open,                 sys_open),                  /*   5 */
   GENXY(__NR_close,                sys_close),                 /*   6 */
   GENX_(__NR_unlink,               sys_unlink),                /*  10 */
   GENX_(__NR_getpid,               sys_getpid),                /*  20 */
   GENX_(__NR_access,               sys_access),                /*  33 */
   GENX_(__NR_kill,                 sys_kill),                  /*  37 */
   NBDXY(__NR_pipe,                 sys_pipe),                  /*  42 */
   NBDXY(__NR_ioctl,                sys_ioctl),                 /*  54 */
   GENX_(__NR_readlink,             sys_readlink),              /*  58 */
   GENXY(__NR_munmap,               sys_munmap),                /*  73 */
   GENXY(__NR_mprotect,             sys_mprotect),              /*  74 */
   NBDX_(__NR_connect,              sys_connect),               /*  98 */
   NBDX_(__NR_sendto,               sys_sendto),                /* 133 */
   GENXY(__NR_getrlimit,            sys_getrlimit),             /* 194 */
   NBDX_(__NR_mmap,                 sys_mmap),                  /* 197 */
   GENXY(__NR_select,               sys_select),                /* 417 */
   NBDXY(__NR___syscall,            sys___syscall),             /* 198 */
   NBDX_(__NR_ftruncate,            sys_ftruncate),             /* 201 */
   NBDXY(__NR_sysctl,               sys_sysctl),                /* 202 */
   GENX_(__NR_vfork,                sys_vfork),                 /* 282 */
   GENXY(__NR_sigprocmask,          sys_sigprocmask),           /* 293 */
   GENX_(__NR_sigsuspend,           sys_sigsuspend),            /* 294 */
   NBDX_(__NR_issetugid,            sys_issetugid),             /* 305 */
   NBDX_(__NR_getcontext,           sys_getcontext),            /* 307 */
   NBDX_(__NR_setcontext,           sys_setcontext),            /* 308 */
   NBDX_(__NR_lwp_create,           sys_lwp_create),            /* 309 */
   NBDX_(__NR_lwp_exit,             sys_lwp_exit),              /* 310 */
   NBDX_(__NR_lwp_self,             sys_lwp_self),              /* 311 */
   NBDX_(__NR_lwp_wakeup,           sys_lwp_wakeup),            /* 315 */
   NBDX_(__NR_lwp_getprivate,       sys_lwp_getprivate),        /* 316 */
   NBDX_(__NR_lwp_setprivate,       sys_lwp_setprivate),        /* 317 */
   NBDX_(__NR_lwp_kill,             sys_lwp_kill),              /* 318 */
   NBDX_(__NR_lwp_unpark,           sys_lwp_unpark),            /* 321 */
   NBDX_(__NR_lwp_unpark_all,       sys_lwp_unpark_all),        /* 322 */
   NBDXY(__NR_lwp_ctl,              sys_lwp_ctl),               /* 325 */
   NBDXY(__NR_sigaction_sigtramp,   sys_sigaction_sigtramp),    /* 340 */
   NBDX_(__NR_sched_yield,          sys_sched_yield),           /* 350 */
   NBDXY(__NR_socket,               sys_socket),                /* 394 */
   GENXY(__NR_gettimeofday,         sys_gettimeofday),          /* 418 */
   GENXY(__NR_setitimer,            sys_setitimer),             /* 425 */
   GENXY(__NR_clock_gettime,        sys_clock_gettime),         /* 427 */
   GENXY(__NR_nanosleep,            sys_nanosleep),             /* 430 */
   GENXY(__NR_fstat,                sys_newfstat),              /* 440 */
   GENXY(__NR_pselect,              sys_pselect),               /* 436 */
   GENXY(__NR_wait4,                sys_wait4),                 /* 449 */
   NBDX_(__NR_lwp_park,             sys_lwp_park)               /* 478 */
};

SyscallTableEntry *ML_(get_netbsd_syscall_entry)(UInt sysno)
{
   const UInt syscall_table_size
      = sizeof(syscall_table) / sizeof(syscall_table[0]);

   if (sysno < syscall_table_size) {
      SyscallTableEntry *sys = &syscall_table[sysno];
      if (!sys->before)
         return NULL; /* no entry */
      return sys;
   }

   /* Can't find a wrapper. */
   return NULL;
}

#endif // defined(VGO_netbsd)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
