/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: auth.c,v 1.19.4.7 2010/06/16 08:40:11 dembour Exp $
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

#include <time.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>

#include "mycrypto.h"
#include "server.h"
#include "dns.h"
#include "list.h"
#include "requests.h"
#include "base64.h"
#include "myrand.h"
#include "socket.h"
#include "queue.h"
#include "debug.h"
#include "log.h"
#include "queue.h"
#include "session.h"

/**
 * @brief try to connect a client to a ressource
 * @param[in] conf configuration
 * @param[in] req DNS request
 * @param[out] packet where to write the packet request
 * @param[out] socket socket created
 * @retval 0 on success
 * @retval -1 on error
 **/

static int		connect_resource(t_conf *conf, t_request *req, t_packet *packet, int *sd)
{
  t_list		*list_resource;
  char			*resource;
  int			len;
  
  resource = ((char *)packet) + PACKET_LEN;
  if (!(len = strlen(resource)))
    return (-1);
  DPRINTF(1, "Ask for resource \'%s\'\n", resource);
  for (list_resource = conf->resources; list_resource; list_resource = list_resource->next)
    {
      if ((!strncmp(list_resource->data, resource, len)) 
	  && (list_resource->data[len] == ':'))
      {
	if (!(connect_socket(strchr(list_resource->data, ':') + 1, list_resource->info.port, sd)))
	  return (0);
	packet->type = ERR;
	send_ascii_reply(conf, req, packet, ERR_CONN_REFUSED);
	return (-1);
      }
    }
  packet->type = ERR;
  send_ascii_reply(conf, req, packet, ERR_RESOURCE);
  return (-1);
}


/**
 * @brief try to bind a client to a ressource
 * @param[in] conf configuration
 * @param[in] req DNS request
 * @param[in] packet packet request
 * @param[in] client client to bind
 * @retval 0 on success
 * @retval -1 on error
 **/

int			bind_user(t_conf *conf, t_request *req, t_packet *packet, t_simple_list *client)
{
  int			sd;
  char			*resource;
  char			*compress;

  if (connect_resource(conf, req, packet, &sd))
    return (-1);
  resource = ((char *)packet) + PACKET_LEN;
  client_update_timer(client);
  if (!(compress = jump_end_query(req, 
				   GET_16(&(((struct dns_hdr *)req->data)->qdcount)), req->len)))
    {
      fprintf(stderr, "invalid reply\n");
      return (-1);
    }

  client->sd_tcp = sd;
  // FIXME bug ipv6 support
  LOG("Bind client id: 0x%x address = %u.%u.%u.%u to resource %s", client->session_id,
#ifndef WORDS_BIGENDIAN
      (unsigned int) ((req->sa.sin_addr.s_addr) & 0xff),
      (unsigned int) ((req->sa.sin_addr.s_addr >> 8) & 0xff),
      (unsigned int) ((req->sa.sin_addr.s_addr >> 16) & 0xff),
      (unsigned int) ((req->sa.sin_addr.s_addr >> 24) & 0xff)
#else
      (unsigned int) ((req->sa.sin_addr.s_addr >> 24) & 0xff),
      (unsigned int) ((req->sa.sin_addr.s_addr >> 16) & 0xff),
      (unsigned int) ((req->sa.sin_addr.s_addr >> 8) & 0xff),
      (unsigned int) ((req->sa.sin_addr.s_addr) & 0xff)
#endif
      , resource);
  packet->type = OK;
  return (send_ascii_reply(conf, req, packet, ""));
}


/**
 * @brief try to authenticate (more a indentification) a client with CHAP
 * @param[in] conf configuration
 * @param[in] req DNS request
 * @param[in] packet packet request
 * @retval 0 on success
 * @retval -1 on error
 **/

int		login_user(t_conf *conf, t_request *req, t_packet *packet)
{
  char		*data;
  t_simple_list	*client;
  char		 buffer[SHA1_SIZE*2+1];
  
  memset(buffer, 0, sizeof(buffer));
  if (req->len <= PACKET_LEN)
    return (-1);
  data =  ((char *) packet) + PACKET_LEN;
  client = find_client_by_session_id(conf, packet->session_id);
  if (client)
    {	
      if (conf->key)
	{
	  sign_challenge(client->control.challenge, CHALLENGE_SIZE, conf->key, (char *)&buffer, sizeof(buffer));
	  if (strncmp(buffer, data, SHA1_SIZE*2))
	    {
	      packet->type = ERR;
	      LOG("Authentication failed");
	      send_ascii_reply(conf, req, packet, ERR_AUTH_FAILED);	        
	      return (delete_client(conf, client));
	    }
	}
      client_update_timer(client);
      client->control.authenticated = 1;
      client->sd_tcp = -1;
      packet->type = OK;
      return (send_ascii_reply(conf, req, packet, ""));
    }
  if (!(client = create_session(conf, req, packet)))
    return (-1);
  alphanum_random(client->control.challenge, CHALLENGE_SIZE);
  packet->type = OK;
  packet->session_id = client->session_id;
  return (send_ascii_reply(conf, req, packet, client->control.challenge));
}

