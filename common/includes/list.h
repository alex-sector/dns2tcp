/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: list.h,v 1.14.4.3 2009/12/28 15:11:17 dembour Exp $
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

#ifndef __LIST_H__
#define __LIST_H__

#include <sys/types.h>
#ifndef _WIN32
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>
typedef int socket_t;
typedef pid_t process_t;
#else
#include "mywin32.h"
#endif
#include "dns.h"
#include "control.h"

#undef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))

typedef struct		s_list {
  char			status;
#define FREE		0
#define USED		1 /* IN only */
#define RECEIVED	2 /* SERVER : To be free when all prev received */
#define SENT		3 /* CLIENT : sent; serveur : IN + ACK */
  union			{
    uint16_t	num_seq;	/* for data */
    uint16_t	port;		/* for server config  */
  }			info;
  char			data[MAX_EDNS_LEN + 1];
  int			len;
  /* peer define in server or client */
  struct s_control_peer	peer;
  struct timeval	timeout;
  struct s_list		*next;
}			t_list;

typedef struct		s_simple_list {
  uint16_t		num_seq;	/* first seq acceptable */
  uint16_t		session_id;
#define sd_tcp		fd_ro /* for server side compatibility */
  socket_t		fd_ro;
  socket_t		fd_wo;
  process_t		pid;
  struct s_list		*queue; 
  struct s_list		*saved_queue; 
  struct s_simple_list	*next;
  struct s_control	control; /* different in client and server */
}			t_simple_list;

#define FREE_CELL(cell)	{cell->status = FREE;}
#define LOCK_CELL(cell)	{cell->status = USED;}

t_list		*list_create_cell();
t_simple_list	*list_create_simple_cell();
int		list_destroy_cell(t_list *);
int		list_destroy_simple_cell(t_simple_list *);
int		list_add_cell(t_list *, t_list *);

#endif
