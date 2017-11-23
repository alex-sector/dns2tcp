/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: socket.h,v 1.1.1.1.6.1 2010/01/06 12:50:41 dembour Exp $
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

#include <netinet/in.h>
#include <sys/socket.h>

union	sockaddr_u			{
  struct sockaddr_storage	storage;
  struct sockaddr_in		in;
  struct sockaddr_in6		in6;
  struct sockaddr		sockaddr;
};

int connect_socket(char *, uint16_t, int *);
int bind_socket(t_conf *);

#endif
