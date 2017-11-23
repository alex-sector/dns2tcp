/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: socket.h,v 1.4.4.3 2009/12/28 15:11:16 dembour Exp $
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

#ifndef __SOCKET_H__
#define __SOCKET_H__


#ifndef _WIN32
#define IS_THIS_SOCKET(sd, handle, descriptors, offset)		FD_ISSET((sd), (descriptors))
#else
#define IS_THIS_SOCKET(sd, handle, descriptors, offset)		(((offset) <= HANDLE_SIZE) && (descriptors[offset] == handle))
#endif

int		socket_is_valid(socket_t );
int		bind_socket(t_conf *);
socket_t	create_socket(t_conf *);
uint16_t	get_simple_reply(t_conf *, char *, uint16_t);

#endif
