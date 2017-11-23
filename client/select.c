/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: select.c,v 1.1.2.4 2010/01/20 15:42:56 dembour Exp $
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

#include <stdio.h>

#ifndef _WIN32
#include <sys/wait.h>
#include <sys/select.h>
#include <strings.h>
#else
#include "mywin32.h"
#endif

#include "dns.h"
#include "list.h"
#include "myerror.h"
#include "client.h"
#include "debug.h"
#include "queue.h"
#include "socket.h"

#ifdef _WIN32
int		add_event(WSAEVENT event, HANDLE *rfds, int max_fd)
{
  rfds[max_fd] = event;
  return ((int) (max_fd+1));
}
#else
int		add_socket(socket_t socket, fd_set *rfds, socket_t max_fd)
{
  FD_SET(socket, rfds);
  return ((int)(MAX(max_fd, socket)));
}
#endif

#ifdef _WIN32
int		win_prepare_select(t_conf *conf, WSAEVENT *rfds, struct timeval *tv)
{
  int		max_fd = 0;
  t_simple_list	*client;

  max_fd = add_event(conf->event_udp, rfds, max_fd);
  
  for (client = conf->client; client; client = client->next)
    {
      if (socket_is_valid(client->fd_ro))
	{
	  queue_put_nop(conf, client);
	  if ((client->control.data_pending < MAX_DATA_SIZE)
	      && ((client->control.data_pending + client->control.nop_pending < WINDOW_SIZE)))
	    {
	      if (client->control.event && socket_is_valid(client->fd_ro)) 
		max_fd = add_event(client->control.event, rfds, max_fd);
	      else 
		{
		  if (client->pid != (process_t)-1) {
		    // watch for pipe I/O completion
		    max_fd = add_event(client->control.aio.hEvent, rfds, max_fd);
		  }
		}
	    } 
	  else 
	    {
	      if (client->control.nop_pending == 0xffff) 
		{
		  DPRINTF(1, "WTF !\n");
		  exit(0);
		}
	      SetEvent(conf->event_udp);
	    }
	  if (client->pid != (process_t)-1) {
	    // watch for process event (dead)
	    max_fd = add_event(client->pid, rfds, max_fd);
	  }
	}
    }
  /* select only if sd_tcp is alive */
  if (socket_is_valid(conf->sd_tcp))
    max_fd = add_event(conf->event_tcp, rfds, max_fd);
  tv->tv_sec = SOCKET_TIMEOUT;
  tv->tv_usec = 0;
  return (max_fd);
}

#else

int		unix_prepare_select(t_conf *conf, fd_set *rfds, struct timeval *tv)
{
  int		max_fd = 0;
  t_simple_list	*client;
  
  FD_ZERO(rfds);
  for (client = conf->client; client; client = client->next)
    {
      if (socket_is_valid(client->fd_ro))
	{
	  queue_put_nop(conf, client);
	  if (!(client->control.data_pending >= MAX_DATA_SIZE)
	      && (!(client->control.data_pending + client->control.nop_pending >= WINDOW_SIZE)))
	    {
	      if (socket_is_valid(client->fd_ro))
		max_fd = add_socket(client->fd_ro, rfds, max_fd);
	    }
	}
    }
  max_fd = add_socket(conf->sd_udp, rfds, max_fd);
  // fuck Windows, not queue debug
  if ((!conf->use_stdin) && (debug > 1))
    max_fd = add_socket(0, rfds, max_fd);
  
  /* select only if sd_tcp is alive */
  if (socket_is_valid(conf->sd_tcp))
    max_fd = add_socket(conf->sd_tcp, rfds, max_fd);
  tv->tv_sec = SOCKET_TIMEOUT;
  tv->tv_usec = 0;
  return (max_fd);
}
#endif

/**
 * @brief prepare the fd_set for select or HANDLE for Windows
 * @param[in] conf configuration
 * @param[in] rfds the fd_set
 * @param[in] tv timeval structure
 * @retval last file descriptor
 */

int	prepare_select(t_conf *conf, fd_set *rfds, struct timeval *tv)
{
#ifndef _WIN32
  return (unix_prepare_select(conf, rfds, tv));
#else
  return (win_prepare_select(conf, (WSAEVENT *)rfds, tv));
#endif
}
