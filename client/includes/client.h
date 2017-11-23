/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: client.h,v 1.15.4.6 2010/06/01 16:02:46 collignon Exp $
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

#ifndef __CLIENT_H__
#define __CLIENT_H__


/* 
   QUEUE_SIZE must the same that server value 
*/

#define RESOLV_CONF	"/etc/resolv.conf"
#define QUEUE_SIZE	48

#define WINDOW_SIZE	(QUEUE_SIZE / 2)
#define	NOP_SIZE	(WINDOW_SIZE / 3)
#define	MAX_NOP_SIZE	(NOP_SIZE * 2)
#define	MAX_DATA_SIZE	(WINDOW_SIZE - NOP_SIZE)

#define SOCKET_TIMEOUT  1 /* 1s */
#define REPLY_TIMEOUT	1 /* 1s */


#include "packet.h"

typedef struct		s_conf {
  struct s_simple_list	*client;
  struct sockaddr_in	sa;
  char			*dns_server;
  char			*cmdline;
  char			*output_file;
#ifdef _WIN32
  WSAEVENT		event_tcp;
  WSAEVENT		event_udp;
#endif
  socket_t		sd_udp;
  socket_t		sd_tcp;
  uint16_t		local_port;
  uint8_t		use_stdin;
  uint16_t		id;
  char			*domain;
  char			*key;
  struct s_rr_functions *query_functions;
  uint16_t		query_size;
  char			*resource;
  uint8_t		disable_compression;
  uint8_t		conn_timeout;
}			t_conf;

int		add_client(t_conf *conf, socket_t fd_ro,
			   socket_t fd_wo, process_t pid);

int delete_client(t_conf *conf, struct s_simple_list *client);
int do_client(t_conf *);

#ifdef _WIN32
typedef WSAEVENT t_fd_event ;
#else
typedef fd_set	t_fd_event;
#endif

#endif
