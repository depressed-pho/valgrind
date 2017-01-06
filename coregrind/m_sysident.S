/*--------------------------------------------------------------------*/
/*--- System Identifier                               m_sysident.S ---*/
/*--------------------------------------------------------------------*/

/*
  This file is part of Valgrind, a dynamic binary instrumentation
  framework.

  Copyright (C) 2000-2015 Julian Seward
     jseward@acm.org

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

/* Some platforms require special .note sections in executables in order to be
 * accepted by kernel. Those sections are usually stored in crt*.o but
 * since we build tools with -nostartfiles we must provide them
 * ourselves.
 */

#include "pub_core_basics_asm.h"

#if defined(VGO_netbsd)
    .section ".note.netbsd.ident", "a"
    .p2align 2

    .long   ELF_NOTE_NETBSD_NAMESZ
    .long   ELF_NOTE_NETBSD_DESCSZ
    .long   ELF_NOTE_TYPE_NETBSD_TAG
    .ascii  "NetBSD\0\0" /* ELF_NOTE_NETBSD_NAME */
    .long   __NetBSD_Version__

    .section ".note.netbsd.pax", "a"
    .p2align 2

    .long   ELF_NOTE_PAX_NAMESZ
    .long   ELF_NOTE_PAX_DESCSZ
    .long   ELF_NOTE_TYPE_PAX_TAG
    .ascii  "Pax\0" /* ELF_NOTE_PAX_NAME */
    .long   0
#endif

/* Let the linker know we don't need an executable stack */
MARK_STACK_NO_EXEC

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
