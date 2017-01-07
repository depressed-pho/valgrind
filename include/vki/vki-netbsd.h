
/*--------------------------------------------------------------------*/
/*--- NetBSD-specific kernel interface.               vki-netbsd.h ---*/
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

/* Unlike vki-linux, this NetBSD kernel interface includes system
 * headers directly, to avoid copyright complexity.
 */

#ifndef __VKI_NETBSD_H
#define __VKI_NETBSD_H

#include "../../config.h"

/* Make all NetBSD features available. See <sys/featuretest.h> */
#define _NETBSD_SOURCE 1

#include <arpa/inet.h>
#define vki_in_addr in_addr

#include <dirent.h>
#define vki_dirent dirent

#include <limits.h>
#define VKI_NGROUPS_MAX     NGROUPS_MAX
#define VKI_PATH_MAX        PATH_MAX
/* Used in launcher-linux.c which we share with Linux port. */
#define VKI_BINPRM_BUF_SIZE VKI_PATH_MAX

#include <lwp.h>
#define vki_lwpid_t lwpid_t

#include <machine/frame.h>
#define vki_sigframe_siginfo sigframe_siginfo

#include <machine/mcontext.h>
#if defined(VGA_amd64)
#  define VKI_REG_RDI    _REG_RDI
#  define VKI_REG_RSI    _REG_RSI
#  define VKI_REG_RDX    _REG_RDX
#  define VKI_REG_RCX    _REG_RCX
#  define VKI_REG_R8     _REG_R8
#  define VKI_REG_R9     _REG_R9
#  define VKI_REG_R10    _REG_R10
#  define VKI_REG_R11    _REG_R11
#  define VKI_REG_R12    _REG_R12
#  define VKI_REG_R13    _REG_R13
#  define VKI_REG_R14    _REG_R14
#  define VKI_REG_R15    _REG_R15
#  define VKI_REG_RBP    _REG_RBP
#  define VKI_REG_RBX    _REG_RBX
#  define VKI_REG_RAX    _REG_RAX
#  define VKI_REG_GS     _REG_GS
#  define VKI_REG_FS     _REG_FS
#  define VKI_REG_ES     _REG_ES
#  define VKI_REG_DS     _REG_DS
#  define VKI_REG_TRAPNO _REG_TRAPNO
#  define VKI_REG_ERR    _REG_ERR
#  define VKI_REG_RIP    _REG_RIP
#  define VKI_REG_CS     _REG_CS
#  define VKI_REG_RFLAGS _REG_RFLAGS
#  define VKI_REG_RSP    _REG_RSP
#  define VKI_REG_SS     _REG_SS

#else
#  error "Unknown architecture"
#endif
#define vki_fpregset_t __fpregset_t

#include <machine/psl.h>
#define VKI_PSL_USER    PSL_USER
#define VKI_PSL_USERSET PSL_USERSET

#include <machine/trap.h>
#define VKI_T_BPTFLT T_BPTFLT

#include <machine/vmparam.h>
#define VKI_PAGE_SHIFT     PAGE_SHIFT
#define VKI_PAGE_SIZE      PAGE_SIZE
#define VKI_MAX_PAGE_SHIFT VKI_PAGE_SHIFT
#define VKI_MAX_PAGE_SIZE  VKI_PAGE_SIZE

#include <netinet/in.h>
#define vki_sockaddr_in  sockaddr_in
#define vki_sockaddr_in6 sockaddr_in6

#include <netinet/tcp.h>
#define VKI_TCP_NODELAY TCP_NODELAY

#include <poll.h>
#define vki_pollfd pollfd

/* /usr/src/libexec/ld.elf_so/rtld.h */
struct __VKI_Obj_Entry;
typedef struct __VKI_Obj_Entry VKI_Obj_Entry;

#include <signal.h>
#define _VKI_NSIG       128
#define _VKI_NSIG_BPW   32
#define _VKI_NSIG_WORDS 4
#define sig             __bits
/* <sys/siginfo.h> defines several accessor macros for siginfo_t, like
 * si_signo, si_code, si_errno, etc. We don't need to define own
 * macros. But this means we cannot use those names as real symbols
 * e.g. variable names. */

#define VKI_BUS_ADRALN   BUS_ADRALN
#define VKI_BUS_ADRERR   BUS_ADRERR
#define VKI_BUS_OBJERR   BUS_OBJERR
#define VKI_FPE_INTDIV   FPE_INTDIV
#define VKI_FPE_INTOVF   FPE_INTOVF
#define VKI_FPE_FLTDIV   FPE_FLTDIV
#define VKI_FPE_FLTOVF   FPE_FLTOVF
#define VKI_FPE_FLTUND   FPE_FLTUND
#define VKI_FPE_FLTRES   FPE_FLTRES
#define VKI_FPE_FLTINV   FPE_FLTINV
#define VKI_FPE_FLTSUB   FPE_FLTSUB
#define VKI_ILL_ILLOPC   ILL_ILLOPC
#define VKI_ILL_ILLOPN   ILL_ILLOPN
#define VKI_ILL_ILLADR   ILL_ILLADR
#define VKI_ILL_ILLTRP   ILL_ILLTRP
#define VKI_ILL_PRVOPC   ILL_PRVOPC
#define VKI_ILL_PRVREG   ILL_PRVREG
#define VKI_ILL_COPROC   ILL_COPROC
#define VKI_ILL_BADSTK   ILL_BADSTK
#define VKI_MINSIGSTKSZ  MINSIGSTKSZ
#define VKI_SA_NOCLDSTOP SA_NOCLDSTOP
#define VKI_SA_NOCLDWAIT SA_NOCLDWAIT
#define VKI_SA_NOMASK    SA_NODEFER
#define VKI_SA_ONESHOT   SA_RESETHAND
#define VKI_SA_ONSTACK   SA_ONSTACK
#define VKI_SA_RESTART   SA_RESTART
#define VKI_SA_SIGINFO   SA_SIGINFO
#define VKI_SA_RESTORER  0 /* NetBSD doesn't have this */
#define VKI_SEGV_ACCERR  SEGV_ACCERR
#define VKI_SEGV_MAPERR  SEGV_MAPERR
#define VKI_SI_USER      SI_USER
#define VKI_SS_DISABLE   SS_DISABLE
#define VKI_SS_ONSTACK   SS_ONSTACK
#define VKI_SIG_BLOCK    SIG_BLOCK
#define VKI_SIG_DFL      SIG_DFL
#define VKI_SIG_IGN      SIG_IGN
#define VKI_SIG_SETMASK  SIG_SETMASK
#define VKI_SIG_UNBLOCK  SIG_UNBLOCK
#define VKI_SIGABRT      SIGABRT
#define VKI_SIGALRM      SIGALRM
#define VKI_SIGBUS       SIGBUS
#define VKI_SIGCHLD      SIGCHLD
#define VKI_SIGCONT      SIGCONT
#define VKI_SIGFPE       SIGFPE
#define VKI_SIGHUP       SIGHUP
#define VKI_SIGILL       SIGILL
#define VKI_SIGINT       SIGINT
#define VKI_SIGIO        SIGIO
#define VKI_SIGKILL      SIGKILL
#define VKI_SIGPIPE      SIGPIPE
#define VKI_SIGPROF      SIGPROF
#define VKI_SIGQUIT      SIGQUIT
#define VKI_SIGSEGV      SIGSEGV
#define VKI_SIGSYS       SIGSYS
#define VKI_SIGSTOP      SIGSTOP
#define VKI_SIGTERM      SIGTERM
#define VKI_SIGTRAP      SIGTRAP
#define VKI_SIGTSTP      SIGTSTP
#define VKI_SIGTTIN      SIGTTIN
#define VKI_SIGTTOU      SIGTTOU
#define VKI_SIGURG       SIGURG
#define VKI_SIGUSR1      SIGUSR1
#define VKI_SIGUSR2      SIGUSR2
#define VKI_SIGVTALRM    SIGVTALRM
#define VKI_SIGWINCH     SIGWINCH
#define VKI_SIGXCPU      SIGXCPU
#define VKI_SIGXFSZ      SIGXFSZ
#define VKI_TRAP_BRKPT   TRAP_BRKPT
#define ksa_handler      sa_handler
typedef struct {
   /* Original struct sigaction */
   union {
      void (*_sa_handler)(int);
      void (*_sa_sigaction)(int, siginfo_t *, void *);
   } _sa_u;
   sigset_t sa_mask;
   int      sa_flags;
   /* Additional arguments for sigaction(2). See signal(9) for
    * details. */
   void*    sa_tramp;
   int      sa_tramp_abi;
} vki_sigaction_toK_t;
typedef struct sigaction vki_sigaction_fromK_t;
#define vki_siginfo_t    siginfo_t
#define vki_sigset_t     sigset_t
#define vki_stack_t      stack_t

#include <stddef.h>
#define vki_size_t size_t

#include <termios.h>
#define vki_termios termios

#include <time.h>
#define VKI_CLOCK_MONOTONIC CLOCK_MONOTONIC
#define vki_clockid_t       clockid_t
#define vki_time_t          time_t
#define vki_timespec        timespec

#include <ucontext.h>
#define VKI_UC_SIGMASK _UC_SIGMASK
#define VKI_UC_STACK   _UC_STACK
#define VKI_UC_CPU     _UC_CPU
#define VKI_UC_FPU     _UC_FPU
#define VKI_UC_TLSBASE _UC_TLSBASE
#define vki_ucontext   __ucontext
#define vki_ucontext_t ucontext_t

#include <unistd.h>
#define VKI_R_OK     R_OK
#define VKI_SEEK_SET SEEK_SET
#define VKI_W_OK     W_OK
#define VKI_X_OK     X_OK

#include <sys/errno.h>
#define VKI_E2BIG     E2BIG
#define VKI_EACCES    EACCES
#define VKI_EAGAIN    EAGAIN
#define VKI_EBADF     EBADF
#define VKI_EBUSY     EBUSY
#define VKI_ECHILD    ECHILD
#define VKI_EDOM      EDOM
#define VKI_EEXIST    EEXIST
#define VKI_EFAULT    EFAULT
#define VKI_EFBIG     EFBIG
#define VKI_EPERM     EPERM
#define VKI_EINTR     EINTR
#define VKI_EINVAL    EINVAL
#define VKI_EIO       EIO
#define VKI_EISDIR    EISDIR
#define VKI_EMFILE    EMFILE
#define VKI_EMLINK    EMLINK
#define VKI_ENFILE    ENFILE
#define VKI_ENODEV    ENODEV
#define VKI_ENOENT    ENOENT
#define VKI_ENOEXEC   ENOEXEC
#define VKI_ENOMEM    ENOMEM
#define VKI_ENOSPC    ENOSPC
#define VKI_ENOSYS    ENOSYS
#define VKI_ENOTBLK   ENOTBLK
#define VKI_ENOTDIR   ENOTDIR
#define VKI_ENOSYS    ENOSYS
#define VKI_ENOTTY    ENOTTY
#define VKI_ENXIO     ENXIO
#define VKI_EOVERFLOW EOVERFLOW
#define VKI_EPIPE     EPIPE
#define VKI_ERANGE    ERANGE
#define VKI_EROFS     EROFS
#define VKI_ESPIPE    ESPIPE
#define VKI_ESRCH     ESRCH
#define VKI_ERANGE    ERANGE
#define VKI_ETXTBSY   ETXTBSY
#define VKI_EXDEV     EXDEV

#include <sys/exec.h>
#define vki_ps_strings ps_strings

#include <sys/fcntl.h>
#define VKI_F_DUPFD    F_DUPFD
#define VKI_F_GETFL    F_GETFL
#define VKI_F_SETFD    F_SETFD
#define VKI_F_SETFL    F_SETFL
#define VKI_FD_CLOEXEC FD_CLOEXEC
#define VKI_O_APPEND   O_APPEND
#define VKI_O_CREAT    O_CREAT
#define VKI_O_EXCL     O_EXCL
#define VKI_O_NONBLOCK O_NONBLOCK
#define VKI_O_RDONLY   O_RDONLY
#define VKI_O_RDWR     O_RDWR
#define VKI_O_TRUNC    O_TRUNC
#define VKI_O_WRONLY   O_WRONLY

#include <sys/ioccom.h>
#define _VKI_IOC_DIR(x)  ((x) & IOC_DIRMASK)
#define _VKI_IOC_SIZE(x) IOCPARM_LEN(x)
#define _VKI_IOC_NONE    IOC_VOID
#define _VKI_IOC_READ    IOC_OUT
#define _VKI_IOC_WRITE   IOC_IN

#include <sys/lwpctl.h>
#define vki_lwpctl lwpctl

#include <sys/mman.h>
#define VKI_MAP_ANONYMOUS MAP_ANON
#define VKI_MAP_PRIVATE   MAP_PRIVATE
#define VKI_MAP_SHARED    MAP_SHARED
#define VKI_MAP_FIXED     MAP_FIXED
#define VKI_PROT_EXEC     PROT_EXEC
#define VKI_PROT_READ     PROT_READ
#define VKI_PROT_WRITE    PROT_WRITE
#define VKI_PROT_NONE     PROT_NONE

#include <sys/resource.h>
#define VKI_RLIMIT_CORE   RLIMIT_CORE
#define VKI_RLIMIT_DATA   RLIMIT_DATA
#define VKI_RLIMIT_NOFILE RLIMIT_NOFILE
#define VKI_RLIMIT_STACK  RLIMIT_STACK
#define vki_rlimit        rlimit
#define vki_rusage        rusage

#include <sys/select.h>
#define vki_fd_set fd_set

#include <sys/sem.h>
#define VKI_GETALL   GETALL
#define VKI_SETALL   SETALL
#define vki_sembuf   sembuf
#define vki_semid_ds semid_ds
union vki_semun {
   int val;
   struct semid_ds *buf;
   unsigned short *array;
};

#include <sys/shm.h>
#define VKI_IPC_SET    IPC_SET
#define VKI_IPC_STAT   IPC_STAT
#define VKI_SHM_RDONLY SHM_RDONLY
#define VKI_SHMLBA     VKI_PAGE_SIZE /* This is actually sysconf(_SC_PAGESIZE) */
#define vki_shmid_ds   shmid_ds

#include <sys/socket.h>
#define VKI_AF_INET       AF_INET
#define VKI_AF_INET6      AF_INET6
#define VKI_AF_UNIX       AF_UNIX
#define VKI_AF_UNSPEC     AF_UNSPEC
#define VKI_CMSG_ALIGN    __CMSG_ALIGN
#define VKI_CMSG_DATA     CMSG_DATA
#define VKI_CMSG_FIRSTHDR CMSG_FIRSTHDR
#define VKI_CMSG_NXTHDR   CMSG_NXTHDR
#define VKI_IPPROTO_TCP   IPPROTO_TCP
#define VKI_SCM_RIGHTS    SCM_RIGHTS
#define VKI_SO_NOSIGPIPE  SO_NOSIGPIPE
#define VKI_SO_TYPE       SO_TYPE
#define VKI_SOCK_STREAM   SOCK_STREAM
#define VKI_SOL_SOCKET    SOL_SOCKET
#define vki_cmsghdr       cmsghdr
#define vki_msghdr        msghdr
#define vki_sa_family_t   sa_family_t
#define vki_sockaddr      sockaddr

#include <sys/stat.h>
#define st_atime_nsec st_atimensec
#define st_mtime_nsec st_mtimensec
#define st_ctime_nsec st_ctimensec
#define VKI_S_IFIFO   S_IFIFO
#define VKI_S_IRGRP   S_IRGRP
#define VKI_S_IROTH   S_IROTH
#define VKI_S_IRUSR   S_IRUSR
#define VKI_S_ISBLK   S_ISBLK
#define VKI_S_ISCHR   S_ISCHR
#define VKI_S_ISDIR   S_ISDIR
#define VKI_S_ISGID   S_ISGID
#define VKI_S_ISLNK   S_ISLNK
#define VKI_S_ISREG   S_ISREG
#define VKI_S_ISUID   S_ISUID
#define VKI_S_IWGRP   S_IWGRP
#define VKI_S_IWOTH   S_IWOTH
#define VKI_S_IWUSR   S_IWUSR
#define VKI_S_IXGRP   S_IXGRP
#define VKI_S_IXOTH   S_IXOTH
#define VKI_S_IXUSR   S_IXUSR
#define vki_mode_t    mode_t
#define vki_stat      stat

#include <sys/time.h>
#define vki_itimerval itimerval
#define vki_timeval   timeval
#define vki_timezone  timezone

#include <sys/times.h>
#define vki_tms tms

#include <sys/ttycom.h>
#define VKI_TIOCGETA TIOCGETA

#include <sys/types.h>
#define vki_caddr_t caddr_t
#define vki_gid_t   gid_t
#define vki_off_t   off_t
#define vki_pid_t   pid_t
#define vki_uid_t   uid_t
typedef uint32_t    vki_u32;

#include <sys/uio.h>
#define vki_iovec iovec

#include <sys/un.h>
#define vki_sockaddr_un sockaddr_un

#include <sys/utsname.h>
#define vki_new_utsname utsname

#endif
