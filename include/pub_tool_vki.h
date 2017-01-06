
/*--------------------------------------------------------------------*/
/*--- Top level for kernel interface declarations.                 ---*/
/*---                                               pub_tool_vki.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2015 Julian Seward
      jseward@acm.org
   Copyright (C) 2005-2015 Nicholas Nethercote
      njn@valgrind.org
   Copyright (C) 2006-2015 OpenWorks LLP
      info@open-works.co.uk

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

/* This file defines types and constants for the kernel interface, and to
   make that clear everything is prefixed VKI_/vki_.

   This file is merely a top-level "steering" file, which pulls in the
   correct bits for the relevant platform.  You should not directly
   #include any file in include/vki; instead #include only this one or
   pub_core_vki.h.
*/

#ifndef __PUB_TOOL_VKI_H
#define __PUB_TOOL_VKI_H

#if defined(VGO_linux)
#  include "vki/vki-linux.h"
#  include "vki/vki-linux-drm.h"
#elif defined(VGO_darwin)
#  include "vki/vki-darwin.h"
#elif defined(VGO_solaris)
#  include "vki/vki-solaris.h"
#elif defined(VGO_netbsd)
#  include "vki/vki-netbsd.h"
#else
#  error Unknown Plat/OS
#endif

#if defined(VGP_amd64_linux) || defined(VGP_x86_linux)
#  include "vki/vki-xen.h"
#endif


#endif // __PUB_TOOL_VKI_H

/*--------------------------------------------------------------------*/
/*--- end                                           pub_tool_vki.h ---*/
/*--------------------------------------------------------------------*/
