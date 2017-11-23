/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: auth.c,v 1.19.4.3 2010/01/06 12:50:40 dembour Exp $
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

#include <string.h>
#include <stdio.h>       

#include "client.h"
#include "dns.h"
#include "myerror.h"
#include "list.h"
#include "requests.h"
#include "socket.h"
#include "base64.h"
#include "myrand.h"
#include "session.h"
#include "myerror.h"
#include "debug.h"
#include "rr.h"

/**
 * @brief ask and list remote resource available
 * @param[in] conf configuration
 * @retval 0 on success
 * @retval -1 on error
 **/

int			list_resources(t_conf *conf)
{
  char			domain[MAX_DNS_LEN + 1];
  char			buffer[MAX_DNS_LEN + 1];
  int			len;
  uint16_t		id, session_id;
  t_request		request;
  uint32_t		count = 0;
  uint8_t		compress;

  if (!((session_id = create_session(conf))))
    return (-1);
  if (create_simple_req(conf, &request, RESOURCE, (char *)&domain, session_id))
    return (-1);
  DPRINTF(1, "Requesting resource\n");
  if ((id = send_query(conf, &request)) == 0)
    return (-1);
  if (!(request.len = get_simple_reply(conf, (char *)&request.req_data, id)))
    return (-1);
  printf("Available connection(s) : \n");
  while ((len = request.request_functions->rr_decode_next_reply(&request, (char *)&buffer, MAX_DNS_LEN , count++)))
    {
      buffer[len] = 0;
      printf("\t%s\n", &buffer[PACKET_LEN]);
    }
  compress = query_is_compressed((char *)&(request.req_data), request.len);
  printf("\nNote : Compression %s available !\n", compress ? "SEEMS" : "NOT");
  return (0);
}

/**
 * @brief connect to a specific ressource
 * @param[in] conf configuration
 * @param[in] session_id session identifier
 * @retval 0 on success
 * @retval 1 on error
 **/

uint16_t		connect_resource(t_conf *conf, uint16_t session_id)
{
  char			domain[MAX_DNS_LEN + 1];
  char			*resource;
  char			buffer[MAX_DNS_LEN + 1];
  int			len;
  t_request		request;
  t_packet		*packet;

  if (create_simple_req(conf, &request, CONNECT, (char *)&domain, session_id))
    return(-1);
  resource = &request.req_data[PACKET_LEN];
  DPRINTF(1, "Connect to resource \"%s\"\n", conf->resource);
  strncpy(resource, conf->resource, sizeof(request.req_data) - PACKET_LEN - 1);
  request.len = PACKET_LEN + strlen(conf->resource);
  if ((len = transceive_query(conf, &request, (char *)&buffer, sizeof(buffer)-1 )) == -1)
    return (1);
  buffer[len] = 0;
  packet = (t_packet *)&buffer;
  if (packet->type != OK)
    fprintf(stderr, "Error : %s\n", (char *) (packet+1));
  return (packet->type != OK);
}

