/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: session.c,v 1.5.4.3 2010/06/02 14:38:23 collignon Exp $
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
#include "client.h"
#include "myerror.h"
#include "requests.h"
#include "debug.h"
#include "rr.h"
#include "myrand.h"



/**
 * @brief ask for a challenge
 * @param[in] conf configuration
 * @param[in] request request to use
 * @param[out] buffer packet received
 * @retval session id
 **/

uint16_t		request_challenge(t_conf *conf, t_request *request, char *buffer)
{
  t_packet		*packet;
  int			len;

  DPRINTF(2, "Request challenge\n");  
  if ((len = transceive_query(conf, request, buffer, MAX_DNS_LEN )) == -1)
    return (0);
  packet = (t_packet *)buffer;
  if (packet->type != OK)
    return (0);
  buffer[len] = 0;
  DPRINTF(2,"Challenge = \'%s\'\n", (char *)(packet+1));
  DPRINTF(1,"Session created (0x%x)\n", packet->session_id);
  return (packet->session_id); /* Not my challenge */
}


/**
 * @brief send the challenge response
 * @param[in] conf configuration
 * @param[out] request where to create the request
 * @param[in] challenge challenge 
 * @retval 0 on success
 * @retval -1 on error
 **/

uint8_t		send_response(t_conf *conf, t_request *request, char *challenge)
{
  char		buffer[MAX_DNS_LEN + 1];
  t_packet	*packet;
  int		len;
  
  packet = (t_packet *) &(request->u.packet);
  request->len = sign_challenge(challenge, CHALLENGE_SIZE, conf->key, (char *)(packet+1), 
				 MAX_DNS_LEN - sizeof(t_packet)) + PACKET_LEN;
  DPRINTF(2, "Sending response : '%s' (key = %s) \n",  (char *)(packet+1), conf->key)
  if ((len = transceive_query(conf, request, buffer, sizeof(buffer) -1)) == -1)
    return (-1);
  packet = (t_packet *) &buffer;
  if (packet->type == OK)
    return (0);
  return (-1);
}

/**
 * @brief try to open a session
 * @param[in] conf configuration
 * @retval 0 on error
 * @retval session id
 **/

uint16_t	create_session(t_conf *conf)
{
  char		domain[MAX_DNS_LEN + 1];
  t_request	request;
  t_packet	*packet;
  uint16_t	session_id;
  char		challenge[MAX_DNS_LEN + 1];  

  if ((strlen(conf->domain) + sizeof(AUTH)) > MAX_DNS_LEN)
    return (0);
  
  strcpy(domain, AUTH);
  strcat(domain, conf->domain);
  request.domain = (char *)&domain;
  request.type = conf->query_functions->type;
  request.request_functions = conf->query_functions;
  request.len = PACKET_LEN;
  packet = &(request.u.packet);
  packet->session_id = 0;
  packet->ack_seq = 0;
  packet->type = 0;
  packet->seq = myrand();
  if (!conf->disable_compression)
    packet->type |= USE_COMPRESS;
  if (!(session_id = request_challenge(conf, &request, (char *)&challenge)))
    return (0);
  packet->session_id = session_id;
  if (send_response(conf, &request, &challenge[PACKET_LEN]))
    {
      fprintf(stderr, "Authentication failed\n");
      return (0);
    }
  return (session_id);
}


