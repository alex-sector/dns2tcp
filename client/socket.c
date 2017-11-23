/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: socket.c,v 1.17.4.4 2009/12/28 15:11:16 dembour Exp $
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
#include <string.h>
#include <fcntl.h>

#ifndef _WIN32
#include <netdb.h>
#include <sys/socket.h>
#include <termios.h>
#endif

#include "client.h"
#include "dns.h"
#include "myerror.h"
#include "debug.h"
#include "queue.h"
#include "socket.h"
#include "select.h"

int	socket_is_valid(socket_t socket)
{
#ifndef _WIN32
  return (socket != -1);
#else
  // TODO
  return (socket != -1);
#endif
}

#ifndef _WIN32

uint16_t		unix_get_simple_reply(t_conf *conf, char *buffer, uint16_t id)
{
  fd_set                rfds;
  int                   retval;
  struct timeval        tv;
  struct dns_hdr	*hdr;
  int			len = 0; 
  
  tv.tv_sec = (time_t) conf->conn_timeout;
  tv.tv_usec = 0;
  hdr = (struct dns_hdr	*) buffer;
  FD_ZERO(&rfds);

  add_socket(conf->sd_udp, &rfds, 0);
  while ((retval = select(conf->sd_udp+1, &rfds, NULL, NULL, &tv)) != -1)
    {
      if (!retval)
	{
	  fprintf(stderr, "No response from DNS %s\n", conf->dns_server);
	  return (0);
	}
      if ((IS_THIS_SOCKET(conf->sd_udp, conf->event_udp, &rfds,  retval)) 
	  && ((len = read(conf->sd_udp, buffer, MAX_DNS_LEN)) > 0))
	{
	  if (hdr->id == id)
	    return (len);
	  else 
	    queue_get_udp_data(conf, buffer, len);
	}
      add_socket(conf->sd_udp, &rfds, 0);
      tv.tv_sec = (time_t) conf->conn_timeout;
    }
  MYERROR("Select error");
  return (0);
}

#else

uint16_t		win_get_simple_reply(t_conf *conf, char *buffer, uint16_t id)
{
  DWORD                 retval;
  struct dns_hdr	*hdr;
  int			len = 0; 
  
  hdr = (struct dns_hdr	*) buffer;
  
  while ((retval = WaitForSingleObject(conf->event_udp, conf->conn_timeout*1000)) != WAIT_FAILED)
    {
      if (retval != WAIT_OBJECT_0)
	{
	  fprintf(stderr, "No response from DNS %s\n", conf->dns_server);
	  return (0);
	}
      if ((len = read(conf->sd_udp, buffer, MAX_DNS_LEN)) > 0)
	{
	  if (hdr->id == id)
	    return (len);
	  else 
	    queue_get_udp_data(conf, buffer, len);
	}
    }
  MYERROR("Select error");
  return (0);
}
#endif

/**
 * @brief get a reply based on the DNS transaction ID
 * @param[in] conf configuration
 * @param[in] buffer where to write the reply
 * @param[in] id DNS transaction id
 * @retval 0 on error
 * @retval len on success
 **/

uint16_t		get_simple_reply(t_conf *conf, char *buffer, uint16_t id)
{
#ifndef _WIN32
  return (unix_get_simple_reply(conf, buffer, id));
#else
  return (win_get_simple_reply(conf, buffer, id));
#endif
  
}


/**
 * @brief non blocking IO
 * @param[in] sd socket
 * @retval 0 on success
 * @retval -1 on error
 **/

static int	set_nonblock(socket_t sd)
{
#ifndef _WIN32
  int		opt;

  if ((opt = fcntl(sd, F_GETFL)) == -1)
    return (-1);
  if ((opt = fcntl(sd, F_SETFL, opt|O_NONBLOCK)) == -1)
    return (-1);
#endif
  return (0);
}

/**
 * @brief listen on wanted interfaces
 * @param[in] conf configuration
 * @retval 0 on success
 * @retval -1 on error
 **/

int			bind_socket(t_conf *conf)
{
  struct sockaddr_in	sa;
#ifndef _WIN32
  int			optval = 1;
#else
  const		char	optval = 1;
#endif

  memset(&sa,0,sizeof(struct sockaddr_in));
  sa.sin_port = htons(conf->local_port);
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_family = AF_INET;
  if ((conf->sd_tcp = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
      MYERROR("socket error %hd", conf->local_port);
      return (-1);
    }
  if (!setsockopt(conf->sd_tcp, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)))
    {
      if (bind(conf->sd_tcp, (struct sockaddr *) &sa, sizeof(struct sockaddr_in)) < 0)
	{
	  perror("bind error");
	  return (-1);
	}
#ifdef _WIN32
      if (!(conf->event_tcp = WSACreateEvent())
	  || (WSAEventSelect(conf->sd_tcp, conf->event_tcp, FD_ACCEPT) == SOCKET_ERROR))
	MYERROR("WSAEvent error\n");
#endif
      if ((!set_nonblock(conf->sd_tcp))
	  && (!listen(conf->sd_tcp, 10)))
	{
	  fprintf(stderr, "Listening on port : %d\n", conf->local_port);
	  return (0);
	}
    }
  MYERROR("Socket_error");
  return (-1);      
}

/**
 * @brief bind fake DNS server
 * @param[in] conf configuration
 **/

socket_t		create_socket(t_conf *conf)
{
  struct hostent        *hostent;
  socket_t		sd;
#ifdef _WIN32
  WSADATA		wsa;

  WSAStartup(MAKEWORD(2,2), &wsa);
#endif
  if (!(hostent = gethostbyname(conf->dns_server)))
    {
      MYERROR("Gethostbyname \'%s\'",conf->dns_server);
      return (-1);
    }
  conf->sa.sin_port = htons(53);
  memcpy(&conf->sa.sin_addr.s_addr, hostent->h_addr, sizeof(conf->sa.sin_addr.s_addr));
  conf->sa.sin_family = AF_INET;
  if ( ((sd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    || (set_nonblock(sd)) )
    {
      MYERROR("socket error");
      return (-1);
    }
  DPRINTF(3, "Create socket for dns : \'%s\' \n", conf->dns_server);
  return (sd);      
}


