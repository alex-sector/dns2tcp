/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: client.c,v 1.22.4.7 2010/01/06 12:50:40 dembour Exp $
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

/**
 * @file client.c
 * @brief clients management
 */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef _WIN32
#include <sys/wait.h>
#else
#include "mywin32.h"
#endif


#include "dns.h"
#include "list.h"
#include "myerror.h"
#include "client.h"
#include "queue.h"
#include "auth.h"
#include "debug.h"
#include "command.h"
#include "socket.h"
#include "select.h"

/**
 * @brief disconnect client
 * @param[in] conf configuration
 * @param[in] client list item
 * @retval 0 on success
 * @retval -1 on error or finish request
 **/

int		delete_client(t_conf *conf, t_simple_list *client)
{
  t_simple_list	*tmp;
#ifndef _WIN32
  int		status;
#endif  
  
  DPRINTF(1, "free client \n");
#ifndef _WIN32
  if (client->pid > 0)
    kill(client->pid, SIGKILL);
  if (conf->sd_tcp)
    waitpid(-1, &status, WNOHANG);
#else
  if (client->pid != (process_t)-1)
    {
      TerminateProcess(client->pid, 0);
      CloseHandle(client->pid);
      client->pid = (process_t) -1;
    }
#endif
  if (conf->client == client)
    {
      if ((client->fd_ro != client->fd_wo) && (client->fd_ro != -1))
	close (client->fd_wo);
      if (!(client->fd_ro < 0))
	close (client->fd_ro);
      tmp = client->next;
      delete_queue(client->saved_queue);
      list_destroy_simple_cell(conf->client);
      conf->client = tmp;
      /* Exit no listenning port and no valid socket */
      return ( !conf->local_port && !socket_is_valid(conf->sd_tcp));
    }
  for (tmp = conf->client; tmp; tmp = tmp->next)
    {
      if (tmp->next == client)
	{
	  tmp->next = client->next;
	  delete_queue(client->saved_queue);
	  return (list_destroy_simple_cell(client) && 
		  /* Exit no listenning port and no valid socket */
		  (!conf->local_port) && !socket_is_valid(conf->sd_tcp));
	}
    }
  return (-1);
}

static int	delete_all_client(t_conf *conf)
{
  t_simple_list	*client;
  
  while ((client = conf->client))
    delete_client(conf, client);
  return (0);
}

/**
 * @brief register new client session
 * @param[in] conf configuration
 * @param[in] fd_ro read file descriptor
 * @param[in] fd_wo write file descriptor (may be same as fd_ro)
 * @param[in] pid process id related to this session (-1 if no fork)
 * @retval 0 on success
 * @retval -1 on error
 */
int		add_client(t_conf *conf, socket_t fd_ro,
			   socket_t fd_wo, process_t pid)
{
  uint16_t	session_id;
  t_simple_list	*client;
#ifdef _WIN32
  HANDLE	evt;
#endif
  
  if (!((session_id = create_session(conf))))
    return (-1);
  if (connect_resource(conf, session_id))
    return (-1);
  DPRINTF(1, "Adding client auth OK: 0x%hx\n", session_id);
  if (!(conf->client))
    {
      if (!(conf->client = list_create_simple_cell()))
	return (-1);
      client = conf->client;
    }
  else
    {
      client = conf->client;
      while (client->next)
	client = client->next;
      if (!(client->next = list_create_simple_cell()))
	return (-1);
      client = client->next;
    }
#ifdef _WIN32
  if (pid == (process_t) -1)
    {
      if ((!((client->control.event = WSACreateEvent())))
	  || (WSAEventSelect(fd_ro, client->control.event, FD_READ |FD_ACCEPT|FD_CLOSE) == SOCKET_ERROR))
	{
	  MYERROR("WSAEvent error\n");
	  return (-1);
	}
      DPRINTF(1, "Client event = 0x%p\n", client->control.event);
    } else {
    evt = CreateEvent(NULL, FALSE, TRUE, NULL);	
    if (!evt) {
      MYERROR("CreateEvent error\n");
      return (-1);
    }
    DPRINTF(1, "Pipe event = 0x%x\n", (unsigned int ) evt);
    ZeroMemory(&client->control.aio, sizeof(OVERLAPPED));
    client->control.aio.hEvent = evt;
    client->control.event = NULL;
    client->control.io_pending = 0;
  }
#endif
  client->session_id = session_id;
  client->fd_ro = fd_ro;
  client->fd_wo = fd_wo;
  client->pid = pid;
  client->control.data_pending = 0;
  client->control.nop_pending = 0;
  client->num_seq = 0;
  client->saved_queue = 0;
  if (! (client->queue = init_queue()))
    return (-1);
  client->saved_queue = client->queue;
  return (0);
}


static int	check_incoming_ns_reply(t_conf *conf, char *buffer)
{
  int		len = 0;
  
  /* Can be blocking here */
  while ((len = read(conf->sd_udp, buffer, MAX_DNS_LEN)) > 0)
    {
      if ((conf->client) && (queue_get_udp_data(conf, buffer, len)))
	{
	  DPRINTF(2, "Error in queue_get_udp_data\n"); 
	  return (-1);
	}
    }
#ifdef _WIN32
  if (len < 0) 
    {
      if (GetLastError() != WSAEWOULDBLOCK) 
	{
	  DPRINTF(1, "failed to recv UDP data (%lu)\n", GetLastError());
	  return (-1);
	}
    }
  /* We can clear the event, we've read all data available */
  ResetEvent(conf->event_udp);
#endif
  return (0);
}

static int	check_incoming_client_data(t_conf *conf, t_fd_event *descriptors, int offset)
{
  t_simple_list	*client;
  
  for (client = conf->client; client; client = client->next)
    {      
      if (socket_is_valid(client->fd_ro)) 
	{
	  if (IS_THIS_SOCKET(client->fd_ro, client->control.event, descriptors, offset))
	    {
	      if (queue_get_tcp_data(conf, client))
		return (delete_client(conf, client));
	      return (0);
#ifdef _WIN32
	    } 
	  else if (IS_THIS_SOCKET(0, client->control.aio.hEvent, descriptors, offset)) 
	    {
	      if (queue_get_tcp_data(conf, client))
		return (delete_client(conf, client));
	      return  (0);
#endif
	    }
	}
    }
  return (1);
}

static int	check_incoming_client(t_conf *conf, t_fd_event *descriptors, int offset)
{
  socket_t	sd;
    
  /* New client */
  if (!(conf->use_stdin))
    {
      if (socket_is_valid(conf->sd_tcp) 
	  && (IS_THIS_SOCKET(conf->sd_tcp, conf->event_tcp, descriptors, offset)))
	{
	  if ((sd = accept(conf->sd_tcp, 0, 0)) == -1)
	    {
	      MYERROR("accept");
	      return (-1);
	    }
#ifdef _WIN32
	  ResetEvent(conf->event_tcp);
#endif
	  if (add_client(conf, sd, sd, (process_t)-1))
	    {
	      close(sd);
	      return (-1);
	    }
	  return (0);
	}
    }
  return (1);
}

/**
 * @brief read data from an socket (TCP or UDP)
  * @param[in] conf configuration
  * @param[in] rfds file descriptor table
  * @retval 0 on success
  * @retval -1 on error
 **/

#define MINI_BUFF 64

static int	get_socket_data(t_conf *conf, t_fd_event *descriptors, int offset)
{
  char		buffer[MAX_EDNS_LEN+1];
  int		res;
  
  buffer[MAX_EDNS_LEN] = 0;

#ifdef DEBUG
  t_simple_list  *client;

  if ((debug > 0) && ((!conf->use_stdin) && (IS_THIS_SOCKET(0, 0, descriptors, offset))))
    {
      read(0, buffer, MINI_BUFF);
      if ((client = conf->client))
	{
	  for (; client; client = client->next)
	    queue_dump(client);
	}
      else
	DPRINTF(2, "No more client\n");
      return (0);
    }
#endif
  
  /* Incoming NS packet */
  if (IS_THIS_SOCKET(conf->sd_udp, conf->event_udp, descriptors, offset))
    return (check_incoming_ns_reply(conf, (char *) buffer));

  /* Incoming client packet */
  if ((res = check_incoming_client_data(conf, descriptors, offset)) != 1)
    return (res);

  /* Incoming TCP client */
  if ((res = check_incoming_client(conf,descriptors, offset)) != 1)
    return (res);

  return (-1);
}

/**
 * @brief open a local file and wait for data from DNS stream
 * @param[in] conf configuration
 * @retval 0 on success
 * @retval -1 on error
 * @note
 *   copy-over-DNS
 */

int			open_file(t_conf *conf)
{
  int			fd;
  
  DPRINTF(1, "Output file is %s\n", (conf->output_file));

  fd = open(conf->output_file,O_CREAT|O_WRONLY|O_TRUNC, 0700);
  if ( fd == -1)
    {
      perror("In open file");
      return (-1);
    }
  /* read will be done in STDIN (unused) */
  if (add_client(conf, -2, fd, (process_t)-1))
    {
      close(fd);
      return (-1);
    }
  return (0);
}

/**
 * @brief main client loop (wait & process data)
 * @param[in] conf configuration
 * @retval -1 on error
 * @retval 0 when finished
 */	
int			check_child(t_conf *conf)
{
#ifndef _WIN32
  int			status;

  if (waitpid(-1, &status, WNOHANG) > 0)
    {
      DPRINTF(1, "Child finished\n");
      delete_all_client(conf);
      return (1);
    }
#endif
  return (0);
}

#ifndef _WIN32
int	unix_check_for_data(t_conf *conf, fd_set *rfds, int max_fd, struct timeval *tv)
{
  int	retval;

  if ((retval =  select(max_fd+1, rfds, 0, 0, tv)) == -1)
    {	  
      DPRINTF(1, "Select error ..\n");
      return (-1);
    }
  if (retval)
    {
      if ((get_socket_data(conf, rfds, 0)) && (!conf->local_port))
	{
	  DPRINTF(1, "Exiting ..\n");
	  delete_all_client(conf);
	  return (-1);
	}
    }
  return (0);
}

#else

int		win_check_for_data(t_conf *conf, WSAEVENT *descriptors, int max_fd, struct timeval *tv)
{
  DWORD		retval;
  
  retval = WaitForMultipleObjects(max_fd, descriptors, FALSE, tv->tv_sec * 1000);
  if (retval == WAIT_FAILED)
    {
      DPRINTF(1, "WaitForMultipleObjects error (%li)\n", GetLastError());
      return (-1);
    }
  if ((retval != WAIT_TIMEOUT) && (retval >= WAIT_OBJECT_0))
    {
      if ((get_socket_data(conf, descriptors, (int)(retval - WAIT_OBJECT_0))) 
	  && (!conf->local_port))
	{
	  DPRINTF(1, "Exiting ..\n");
	  delete_all_client(conf);
	  return (-1);
	}
    }
  return (0);
}

#endif

int	check_for_data(t_conf *conf, t_fd_event *rfds, int max_fd, struct timeval *tv)
{
#ifdef _WIN32
  return (win_check_for_data(conf, rfds, max_fd, tv));
#else
  return (unix_check_for_data(conf, rfds, max_fd, tv));
#endif
}

/**
 * @brief main client loop (wait & process data)
 * @param[in] conf configuration
 * @retval -1 on error
 * @retval 0 when finished
 */
int			do_client(t_conf *conf)
{
#ifndef _WIN32
  fd_set                rfds;
#else
  WSAEVENT              rfds[HANDLE_SIZE];
#endif
  struct timeval        tv;
  int                   retval;
  int                   max_fd;
  
  if (debug >= 2)
    fprintf(stderr, "When connected press enter at any time to dump the queue\n");
  if ((conf->cmdline) && ((retval = create_process(conf))))
    return (-1);
  if ((conf->use_stdin) && ((retval = add_client(conf, 0, 1, (process_t)-1))))
    return (-1);
  if ((conf->output_file) && ((retval = open_file(conf))))
    return (-1);
  while (1)
    {
#ifndef _WIN32
      /* Check for defunc child */
      if (check_child(conf))
	return (0);
      max_fd = prepare_select(conf, &rfds, &tv);
      if (check_for_data(conf, &rfds, max_fd, &tv))
	return (-1);
#else
      max_fd = prepare_select(conf, rfds, &tv);
      if (check_for_data(conf, rfds, max_fd, &tv))
	return (-1);
#endif
      check_for_resent(conf);
    }
  return (-1);
}
