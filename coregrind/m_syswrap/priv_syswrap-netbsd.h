/*--------------------------------------------------------------------*/
/*--- Private syscalls header for NetBSD.    priv_syswrap-netbsd.h ---*/
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

#ifndef __PRIV_SYSWRAP_NETBSD_H
#define __PRIV_SYSWRAP_NETBSD_H

#include "pub_core_basics.h"     // ThreadId
#include "priv_types_n_macros.h" // DECL_TEMPLATE

// Thread-related functions
extern void ML_(call_on_new_stack_0_1) ( Addr stack, Addr retaddr,
                                         void (*f)(Word), Word arg1 );
extern Word ML_(start_thread_NORETURN) ( void* arg );
extern Addr ML_(allocstack)            ( ThreadId tid );
extern void ML_(setup_start_thread_context)(ThreadId tid, vki_ucontext_t *uc);

// User contexts
extern void ML_(save_machine_context)(ThreadId tid, vki_ucontext_t *uc,
                                      CorePart part);
extern void ML_(restore_machine_context)(ThreadId tid, vki_ucontext_t *uc,
                                         CorePart part);

#endif

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
