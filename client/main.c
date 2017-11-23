/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: main.c,v 1.12.4.4 2009/12/28 15:11:15 dembour Exp $
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
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>

#ifndef _WIN32
#include <sys/time.h>
#else
#include "mywin32.h"
#endif

#include "client.h"
#include "options.h"
#include "socket.h"
#include "auth.h"
#include "myerror.h"
#include "dns.h"

/**
 * @brief main part
 * @retval 0 on success
 * @retval -1 on error
 **/

int			main(int argc, char **argv)
{
  t_conf		conf;
  
  if ((get_option(argc, argv, &conf)) ||  
      ((conf.sd_udp = create_socket(&conf)) == -1))
    return (-1);
  srand(getpid() ^ (unsigned int) time(0));
#ifdef _WIN32
  if (!(conf.event_udp = WSACreateEvent()))
    {
      MYERROR("WSACreateEvent error\n");
      return (-1);
    }
  WSAEventSelect(conf.sd_udp, conf.event_udp, FD_READ);
#endif
  if (!conf.resource)
    return (list_resources(&conf));
  if ((!conf.local_port) || (!bind_socket(&conf)))
    do_client(&conf);
  return (0);
}
