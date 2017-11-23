/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: requests.c,v 1.23.4.10 2010/02/11 15:09:17 dembour Exp $
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
#include <sys/socket.h>
#include <assert.h>

#include "mycrypto.h"
#include "server.h"
#include "dns.h"
#include "dns_decode.h"
#include "list.h"
#include "base64.h"
#include "myerror.h"
#include "queue.h"
#include "mystrnlen.h"
#include "auth.h"
#include "debug.h"
#include "rr.h"
#include "requests.h"
#include "session.h"
#include "log.h"


const t_command dns_commands[]= {
	{AUTH, sizeof(AUTH)-1, 0, &login_user},
	{RESOURCE, sizeof(RESOURCE)-1, 1, &send_resources_reply},
	{CONNECT, sizeof(CONNECT)-1, 1, &bind_user},
	{0,0,0,0}
};


/**
 * @brief get the DNS request type (KEY, TXT ...)
 * @param[in] req request
 **/

static uint16_t		get_type_request(t_request *req)
{
  struct dns_hdr	*hdr;
  char 			*ptr;
  uint16_t		type;

  if (sizeof(struct dns_hdr) > req->len)
    return (0);
  hdr =  (struct dns_hdr *) req->data;
  if (hdr->qdcount > 0)
    {
      ptr = memchr(JUMP_DNS_HDR(hdr), 0, req->len - sizeof(struct dns_hdr));
      if (ptr)
        {
	  type = ((struct req_hdr *) (ptr + 1))->qtype;
	  return GET_16(&type);
	}
    }
  return (0);
}

/**
 * @brief send list of available ressource
 * @param[in] conf configuration
 * @param[in] req request
 * @param[in] packet packet structure
 * @param[in] client client
 * @note need to be authenticated
 **/

int			send_resources_reply(t_conf *conf, t_request *req, t_packet *packet,  t_simple_list *client)
{
  struct dns_hdr	*hdr;
  t_list		*list;
  void			*where = 0;
  char			buffer2[MAX_DNS_LEN + 1];  
  char			buffer[MAX_DNS_LEN + 1];
  int			len, ressource_len;
  uint16_t		answer_len;

  hdr = (struct dns_hdr *)req->data;
  hdr->ra = 1;
  hdr->aa = 1;
  hdr->qr = 1;
  
  DPRINTF(3, "Sending resource\n");
  if (!(where = jump_end_query(req->data, GET_16(&hdr->qdcount), req->len)))
    return (-1);
  packet = (t_packet *)&buffer2;
  packet->type = OK;
  for (list = conf->resources; list; list = list->next)
    {
      answer_len = where ? (uint16_t)((void *)where - (void *)hdr) : req->len;
      len = strchr(list->data, ':') - list->data;
      if ((BASE64_SIZE(len) + (where - (void *)req->data)) < MAX_DNS_LEN )
	{
	  if ((!(ressource_len = req->reply_functions->rr_available_len(hdr, client, answer_len)))
	      || (strlen(list->data) > ressource_len))
	    {
	      LOG("Not enought space to send resources, message will be truncated\n");
	      break;
	    }
	  strcpy(&buffer2[PACKET_LEN], list->data); 
	  base64_encode(buffer2, buffer, len+PACKET_LEN);
	  where = req->reply_functions->rr_add_reply(conf, req, hdr, where, buffer);
	}
    }
  answer_len = (uint16_t)((void *)where - (void *)hdr);
  if ((sendto(conf->sd_udp, req->data, answer_len, 
              0, (struct sockaddr *)&req->sa, sizeof(struct sockaddr))) != answer_len)
    {
      MYERROR("sendto error");
      return (-1);
    }
  return (0);
}

/**
 * @brief decode a request
 * @param[in] conf configuration
 * @param[in] req request
 * @param[out] output where to write the data
 * @retval 0 on success
 * @retval -1 on error
 **/

int			get_request(t_conf *conf, t_request *req, t_data *output)
{
  char			buffer[MAX_HOST_NAME_ENCODED + 1];
  int			len;
  char			*query;
  struct dns_hdr	*hdr;


  query = JUMP_DNS_HDR(req->data);
  hdr = (void *)req->data;
  
  /* just a header -> drop */
  if ((len = mystrnlen(query, (req->len - DNS_HDR_SIZE))) == (req->len - DNS_HDR_SIZE))
    return (-1);
  
  if (len > (sizeof(buffer) -1))
    {
      DPRINTF(2, "Request too long\n");
      return (-1);
    }
  if (dns_decode(conf, req, query, buffer) == -1)
    {
      DPRINTF(2, "DNS decode error\n");
      return (-1);
    }
  DPRINTF(3, "Receive query : %s dns_id = 0x%x for domain %s\n", buffer, ntohs(hdr->id), req->domain);
  return ((output->len = base64_decode((unsigned char *)output->buffer, buffer)));
}

/* 
   send_reply does not check the size of data
 */
/**
 * @brief send immediatly the reply 
 * @param[in] req request to use
 * @param[in] data data to send
 * @retval 0 on success
 * @retval -1 on error
 **/

int			send_reply(t_conf *conf, t_request *req, t_data *data)
{
  char			buffer[MAX_EDNS_LEN];
  void			*where;
  struct dns_hdr	*hdr;
  t_packet		*packet;
  uint16_t		packet_id;


  hdr = (struct dns_hdr *) req->data;
  hdr->ra = 1;
  hdr->aa = 1;
  hdr->qr = 1;

  if (!(where = jump_end_query(req->data, GET_16(&hdr->qdcount), req->len)))
    return (-1);

  packet = (t_packet *)data->buffer;
  packet_id = ntohs(packet->seq);
  base64_encode(data->buffer, buffer, data->len);
  where = req->reply_functions->rr_add_reply(conf, req, hdr, where, buffer);
  /* update request len */
  req->len = where - (void *)req->data;
  DPRINTF(3, "Sending [%d] len = %d dns id = 0x%x %s\n", packet_id, req->len, ntohs(hdr->id), buffer);
  if ((sendto(conf->sd_udp, req->data, req->len, 
	      0, (struct sockaddr *)&req->sa, sizeof(struct sockaddr))) != req->len)
    {
      MYERROR("sendto error");
      return (-1);
    }
  return (0);
}
/**
 * @brief send immediatly an error reply 
 * @param[in] req request to use
 * @param[in] packet packet structure to use
 * @param[in] str string to send
 * @retval 0 on success
 * @retval -1 on error
 **/

int			send_ascii_reply(t_conf *conf, t_request *req, t_packet *packet, char *str)
{
  t_data		data;
  char			buffer[MAX_EDNS_LEN];
  int			len, max_len;

  len = strlen(str) +  sizeof(t_packet);
  max_len =  req->reply_functions->rr_available_len(req->data, NULL, req->len) + PACKET_LEN;
  
  if (len > max_len) 
    {
      LOG("Packet too long, try to add %d bytes on a %d bytes long request\n", len, req->len);
      return (-1);
    }
  memcpy(buffer, packet, sizeof(t_packet));
  strcpy(buffer + sizeof(t_packet), str);
  
  data.buffer = buffer;
  data.len = len;
  return (send_reply(conf, req, &data));
}

/**
 * @brief deal an incoming request
 * @param[in] conf configuration
 **/

int			get_incoming_request(t_conf *conf)
 {
   char			recv_buffer[MAX_EDNS_LEN + 1];
   char			domain[MAX_HOST_NAME_ENCODED];
   char			input[MAX_HOST_NAME_ENCODED + 1];
   t_request		req; /* req.data -> recv_buffer */
   socklen_t		slen; 
   uint16_t		type;
   t_data		decoded_data; /* .data -> input */

   slen = sizeof(req.sa);
   req.data = recv_buffer;
   req.domain = domain;
   req.cmd = 0;
   decoded_data.buffer = input;
   decoded_data.len = sizeof(input) - 1;
   if (((req.len = recvfrom(conf->sd_udp, req.data, 
			     MAX_DNS_LEN, 0, (struct sockaddr *)&req.sa, &slen)) <= 0 ))
     return (-1);
   /* Data buffer is always terminated by 0 */
   ((char *)req.data)[req.len] = 0;
   type = get_type_request(&req);
   if (!type)
     return (-1);
   if ((req.reply_functions = get_rr_function_by_type(type)))
     {
       if (get_request(conf, &req, &decoded_data) <= 0)
	 return (-1);
       if (!req.cmd)
	 return (queue_put_data(conf, &req, &decoded_data));       
       if (!session_request(conf, &req, &decoded_data))
	 return (0);
     }
   return (-1);
 }
