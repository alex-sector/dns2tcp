/*
** Copyright (C) 2006 Nicolas COLLIGNON
** $Id: mywin32.h,v 1.5.4.4 2009/12/28 15:11:17 dembour Exp $
**
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with This program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __MY_WIN32_H__
#define __MY_WIN32_H__

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <winsock2.h>
#include <time.h>
#include <stdint.h>

typedef SOCKET socket_t;
typedef HANDLE process_t;

#define getpid		GetCurrentProcessId

#define strncasecmp	_strnicmp

#define read(f,b,l)	recv(f, b, (int) l, 0)
#define write(f,b,l)	send(f, b, (int) l, 0)

#define close		closesocket
#define HANDLE_SIZE	1024

#endif
