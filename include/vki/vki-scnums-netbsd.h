
/*--------------------------------------------------------------------*/
/*--- System call numbers for NetBSD.          vki-scnums-netbsd.h ---*/
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

#ifndef __VKI_SCNUMS_NETBSD_H
#define __VKI_SCNUMS_NETBSD_H

/* Note: Basic information about NetBSD syscalls can be found in the
 * kernel source file sys/kern/syscalls.master and
 * sys/arch/.../syscall.c
 */

/* Include sys/syscall.h to get SYS_* constants to avoid any copyright
 * issues connected with their potential copying out of the header
 * file.
 */
#include <sys/syscall.h>

#define __NR_access             SYS_access
#define __NR_clock_gettime      SYS___clock_gettime50
#define __NR_close              SYS_close
#define __NR_connect            SYS_connect
#define __NR_dup                SYS_dup
#define __NR_dup2               SYS_dup2
#define __NR_execve             SYS_execve
#define __NR_exit               SYS_exit
#define __NR_fcntl              SYS_fcntl
#define __NR_fork               SYS_fork
#define __NR_fstat              SYS___fstat50
#define __NR_ftruncate          SYS_ftruncate
#define __NR_getcontext         SYS_getcontext
#define __NR_getcwd             SYS___getcwd
#define __NR_getdents           SYS___getdents30
#define __NR_getegid            SYS_getegid
#define __NR_geteuid            SYS_geteuid
#define __NR_getgroups          SYS_getgroups
#define __NR_getpeername        SYS_getpeername
#define __NR_getpgrp            SYS_getpgrp
#define __NR_getppid            SYS_getppid
#define __NR_getpid             SYS_getpid
#define __NR_getrlimit          SYS_getrlimit
#define __NR_getsockname        SYS_getsockname
#define __NR_getsockopt         SYS_getsockopt
#define __NR_gettimeofday       SYS___gettimeofday50
#define __NR_ioctl              SYS_ioctl
#define __NR_issetugid          SYS_issetugid
#define __NR_kill               SYS_kill
#define __NR_lseek              SYS_lseek
#define __NR_lwp_create         SYS__lwp_create
#define __NR_lwp_ctl            SYS__lwp_ctl
#define __NR_lwp_exit           SYS__lwp_exit
#define __NR_lwp_getprivate     SYS__lwp_getprivate
#define __NR_lwp_kill           SYS__lwp_kill
#define __NR_lwp_park           SYS____lwp_park60
#define __NR_lwp_self           SYS__lwp_self
#define __NR_lwp_setprivate     SYS__lwp_setprivate
#define __NR_lwp_unpark         SYS__lwp_unpark
#define __NR_lwp_unpark_all     SYS__lwp_unpark_all
#define __NR_lwp_wakeup         SYS__lwp_wakeup
#define __NR_mkfifo             SYS_mkfifo
#define __NR_mknod              SYS___mknod50
#define __NR_mmap               SYS_mmap
#define __NR_mprotect           SYS_mprotect
#define __NR_mq_close           SYS_mq_close
#define __NR_mq_getattr         SYS_mq_getattr
#define __NR_mq_notify          SYS_mq_notify
#define __NR_mq_receive         SYS_mq_receive
#define __NR_mq_send            SYS_mq_send
#define __NR_mq_setattr         SYS_mq_setattr
#define __NR_mq_timedreceive    SYS___mq_timedreceive50
#define __NR_mq_timedsend       SYS___mq_timedsend50
#define __NR_mq_unlink          SYS_mq_unlink
#define __NR_mq_open            SYS_mq_open
#define __NR_mremap             SYS_mremap
#define __NR_munmap             SYS_munmap
#define __NR_nanosleep          SYS___nanosleep50
#define __NR_open               SYS_open
#define __NR_pipe               SYS_pipe
#define __NR_pipe2              SYS_pipe2
#define __NR_poll               SYS_poll
#define __NR_pread              SYS_pread
#define __NR_pselect            SYS___pselect50
#define __NR_ptrace             SYS_ptrace
#define __NR_read               SYS_read
#define __NR_readlink           SYS_readlink
#define __NR_rename             SYS_rename
#define __NR_sched_yield        SYS_sched_yield
#define __NR_select             SYS___select50
#define __NR_semctl             SYS_____semctl50
#define __NR_sendto             SYS_sendto
#define __NR_setcontext         SYS_setcontext
#define __NR_setitimer          SYS___setitimer50
#define __NR_setrlimit          SYS_setrlimit
#define __NR_setsockopt         SYS_setsockopt
#define __NR_shmctl             SYS___shmctl50
#define __NR_sigaction_sigtramp SYS___sigaction_sigtramp
#define __NR_sigprocmask        SYS___sigprocmask14
#define __NR_sigsuspend         SYS___sigsuspend14
#define __NR_sigtimedwait       SYS_____sigtimedwait50
#define __NR_socket             SYS___socket30
#define __NR_stat               SYS___stat50
#define __NR_syscall            SYS_syscall
#define __NR___syscall          SYS___syscall
#define __NR_sysctl             SYS___sysctl
#define __NR_unlink             SYS_unlink
#define __NR_vfork              SYS___vfork14
#define __NR_wait4              SYS___wait450
#define __NR_write              SYS_write

#endif
