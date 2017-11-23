/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: control.h,v 1.6.4.1 2009/12/28 15:11:16 dembour Exp $
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

#ifndef __CONTROL_H__
#define __CONTROL_H__

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#define MAX_CLIENT_ERROR	10

typedef	struct		s_control {
  uint16_t		nop_pending;
  uint16_t		data_pending;
  uint8_t		cumul_errors;
#ifdef _WIN32
  WSAEVENT		event;
  OVERLAPPED		aio;
  int			io_pending;
#endif
  struct sockaddr_in	peer;
}			t_control;

typedef struct		s_control_peer {
  uint16_t		ack_seq;
  uint16_t		id;
  uint16_t		old_id;
  uint8_t		type;
}			t_control_peer;


#endif
