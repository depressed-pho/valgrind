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

#if defined(VGP_amd64_netbsd)

#include "pub_core_sigframe.h"      /* Self */

/* This module creates and removes signal frames for signal deliveries
   on amd64-netbsd. */

/* Create a signal frame for thread 'tid'.  Make a 3-arg frame regardless of
   whether the client originally requested a 1-arg version (no SA_SIGINFO) or
   a 3-arg one (SA_SIGINFO) since in the former case, the x86/amd64 calling
   conventions will simply cause the extra 2 args to be ignored (inside the
   handler). */
#include "pub_core_libcassert.h" // XXX
void VG_(sigframe_create)(ThreadId tid, Bool on_altstack,
                          Addr sp_top_of_frame, const vki_siginfo_t *siginfo,
                          const struct vki_ucontext *siguc,
                          void *handler, UInt flags, const vki_sigset_t *mask,
                          void *restorer)
{
   vg_assert(0); // XXX
}

#endif // defined(VGP_amd64_netbsd)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
