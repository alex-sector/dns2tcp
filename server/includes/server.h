/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: server.h,v 1.14.4.4 2010/02/11 15:05:50 collignon Exp $
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

#ifndef __SERVER_H__
#define __SERVER_H__

#include "packet.h"

#define DEFAULT_PIDFILE  "/var/run/dns2tcpd.pid"

#define CLIENT_TIMEOUT	8 /* seconds */


/* Req will be flushed after REQUEST_TIMEOUT + REQUEST_UTIMEOUT */
#define REQUEST_TIMEOUT 0 /* sec */
#define REQUEST_UTIMEOUT 500000 /* microsec */

/* when we have more than FLUSH_TRIGGER  queries in queue, we try to flush */
#define FLUSH_TRIGGER	(QUEUE_SIZE /4)

/* 
   QUEUE_SIZE must the same that server value 
*/
#define QUEUE_SIZE      48


typedef struct		s_conf {
  struct s_list		*resources;
  struct s_simple_list	*client;
  int			sd_udp;
  char			*my_domain;
  char			*chroot;
  char			*pid_file;
  char			*user;
  char			*my_ip;
  char			*pidfile;
  char			*key;
  uint16_t		port;
  uint8_t		list_resource;
  uint8_t		trace_enable;
#define TRACE_AVAILABLE	(1 << 0)
#define TRACE_ENABLE	(1 << 1)
  time_t		trace_timeout;
  uint8_t		foreground;
}			t_conf;

typedef	struct		s_request {
  // FIXME BUG ipv6 support
  struct sockaddr_in	sa;
  void			*data;
  char			*domain;
  int			len;
  uint16_t		edns_size;
  const struct s_command	*cmd;
  const struct s_rr_functions *reply_functions;
} t_request;

int	do_server(t_conf *);
int	delete_client(t_conf *conf, struct s_simple_list *client);
void	delete_zombie(t_conf *conf);

#endif
