/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: session.c,v 1.5.4.2 2010/02/11 16:06:38 dembour Exp $
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

#include "mycrypto.h"
#include "server.h"
#include "myerror.h"
#include "queue.h"
#include "requests.h"
#include "auth.h"
#include "myrand.h"
#include "log.h"


/**
 * @brief generate a new session number
 * @param[in] conf configuration
 * @note not really good
 **/

static uint16_t		new_sessionid(t_conf *conf)
{
  uint16_t		rand;
  uint32_t		try = (1<<16) * 2;
  uint8_t		bad = 0;
  t_simple_list		*client;

  client = (t_simple_list *)conf->client;
  while (!(rand = myrand()));
  if (!client)
    return (myrand());
  do {
    for (client = (t_simple_list *)conf->client; client; client = client->next)
      {
	if (client->session_id == rand)
	  bad = 1;
      }
    if (!bad)
      return (rand);
    while (!(rand = myrand()));
  } while (try--);
  return (0);
}

/**
 * @brief create a session for an incoming (unauthenticated) client
 * @param[in] conf configuration
 * @param[in] req request
 * @param[in] packet
 * @retval client
 * @retval -1 on error
 **/

t_simple_list		*create_session(t_conf *conf, t_request *req, t_packet *packet)
{
  t_simple_list		*client;
  uint16_t		rand;
  
  if (!(rand = new_sessionid(conf)))
    return (0);
  client = (t_simple_list *)conf->client;
  if (!client)
    {
      conf->client = list_create_simple_cell();
      client = conf->client;
    }
  else
    {
      while (client->next)
	client = client->next;
      if (!(client->next = list_create_simple_cell()))
	return (0);
      client = client->next;
    }
  client->session_id = rand;
  client->saved_queue = 0;
  
  if (!(client->queue = init_queue()))
    {
      list_destroy_simple_cell(client);
      LOG("No more memory\n");
      return (0);
    }
  client->saved_queue =  client->queue;
  client->num_seq = 1;
  client->sd_tcp = -1; /* No endpoint yet */
  client_update_timer(client);

  if ((packet->type & USE_COMPRESS) == USE_COMPRESS)
    client->control.use_compress = 1;
  
  LOG("Creating session id: 0x%x address = %u.%u.%u.%u (compression %s wanted)", client->session_id,
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
      , client->control.use_compress ? "" :"NOT"
      );
  return (client);
}


/**
 * @brief deal session request
 * @param[in] conf configuration
 * @param[in] request received
 * @param[in] data packet structure received
 * @retval 0 on success
 * @retval -1 on error
 **/

int			session_request(t_conf *conf, t_request *req, t_data *data)
{
  t_packet		*packet;
  t_simple_list		*client;

  if (data->len < PACKET_LEN)
    return (-1);
  packet = (void *)data->buffer;
  data->buffer[data->len] = 0;
  if (!req->cmd->authenticated)
    return (req->cmd->deal_cmd(conf, req, packet, 0));
  client = find_client_by_session_id(conf, packet->session_id);
  /* ----- Authenticated user below ---- */
  if ((!client) || (client->sd_tcp > 0))
    {
      packet->type = ERR;
      return (send_ascii_reply(conf, req, packet, ERR_AUTH_FAILED));
    }
  if (client && client->control.authenticated)
  /* deal_cmd is in request.c */
    return (req->cmd->deal_cmd(conf, req, packet, client));
  return (-1);
}
