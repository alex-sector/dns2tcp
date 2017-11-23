/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: requests.c,v 1.20.4.7 2010/06/02 14:30:00 collignon Exp $
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
#ifndef _WIN32
#include <strings.h>
#endif

#include "client.h"
#include "base64.h"
#include "dns.h"
#include "myrand.h"
#include "list.h"
#include "myerror.h"
#include "requests.h"
#include "debug.h"
#include "socket.h"
#include "dns.h"
#include "rr.h"

/**
 * @brief create the DNS header
 * @param[in] conf configuration
 * @param[in] hdr DNS header 
 **/


static void		create_req_hdr(t_conf *conf, struct dns_hdr *hdr)
{
  memset(hdr, 0, sizeof(struct dns_hdr));
  hdr->id = myrand();
  hdr->rd = 1;
}

/**
 * @brief Add a request into the DNS packet
 * @param[in] hdr DNS header address
 * @param[out] where memory address to write
 * @param[in] name data to copy
 * @param[in] conf configuration
 * @param[in] type request type
 * @retval 0 on success
 * @retval -1 on error
 **/

static int		add_query(struct dns_hdr *hdr, void *where, char *name, 
				  t_conf *conf, uint16_t type)
{
  struct req_hdr	*req;
  size_t		query_len;
  int			actual_len;

  
  query_len = strlen(name) + 1;
  actual_len = where - (void *)hdr;
  if ((query_len + actual_len + RR_HDR_SIZE) > MAX_DNS_LEN)
    return (-1);
  PUT_16(&hdr->qdcount, GET_16(&hdr->qdcount)+1);
  strcpy(where , name);
  req = (struct req_hdr *) (where + query_len);
  PUT_16(&req->qtype, type);
  PUT_16(&req->qclass, CLASS_IN);
  return ((int) (JUMP_REQ_HDR(req) - (char *)(hdr)));
}

/**
 * @brief encode data in qname format
 * @param[in] req request
 * @param[out] output adress to write 
 **/

static void	data2qname(t_request *req, void *output)
{
  base64_encode((char *)req->req_data, output, req->len);
  strcat(output, ".");
  strcat(output, req->domain);
#ifndef _WIN32
  DPRINTF(3, "Query is %s len %zd\n", (char *)output, strlen(output));
#else
  DPRINTF(3, "Query is %s len %d\n", (char *)output, strlen(output));
#endif
  dns_encode(output);
}

/**
 * @brief check if query is compressed
 * @param[in] DNS request
 * @param[in] len request size
 * @retval if it's compressed
 **/

uint8_t			query_is_compressed(char *buffer, uint16_t len)
{
  char			*name;
  struct dns_hdr	*hdr;

  hdr = (struct dns_hdr *) buffer;
  if (!(name  = jump_end_query(buffer, GET_16(&hdr->qdcount), len)))
    return (0);
  return ((*name & COMPRESS_FLAG_CHAR) == COMPRESS_FLAG_CHAR);
}

/**
 * @brief create a DNS request
 * @param[in] conf configuration
 * @param[out] output address to write
 * @param[in] req DNS request
 * @retval size written
 **/

static int		create_request(t_conf *conf, void *output, t_request *req)
{
  char			name[MAX_HOST_NAME_ENCODED + 1];
  struct dns_hdr	*hdr;
  int			len;

  hdr = (struct dns_hdr *) output; 
  create_req_hdr(conf, hdr);
  if ((ENCODED_LEN(BASE64_SIZE(req->len)) + strlen(req->domain) + 2 ) > (MAX_HOST_NAME_ENCODED))
    {
#ifndef _WIN32
      fprintf(stderr, "send_query : data too long (%d bytes -> %zd bytes)\n", 
#else
      fprintf(stderr, "send_query : data too long (%d bytes -> %d bytes)\n", 
#endif
	      req->len, ENCODED_LEN(BASE64_SIZE(req->len)) + strlen(req->domain) + 2 );
      return (0);
    }
  DPRINTF(3, "Sending dns id = 0x%x\n", ntohs(hdr->id)); 
  data2qname(req, &name);
  if ((len = add_query((struct dns_hdr *)output, JUMP_DNS_HDR(hdr), name, conf, req->type)) == -1)
    return (0);
  return (len);
}


/**
 * @brief send a query
 * @param[in] conf configuration
 * @param[in] req request to send
 **/

uint16_t		send_query(t_conf *conf, t_request *req)
{
  char			buffer[MAX_DNS_LEN + 1];  
  int			len;
  struct dns_hdr	*hdr;

  hdr = (struct dns_hdr*) &buffer;
  len = create_request(conf, buffer, req);
  if ((sendto(conf->sd_udp, buffer, len, 0,  (struct sockaddr *)&(conf->sa), sizeof(struct sockaddr))) == -1)
    {
      perror("");
      MYERROR("Sendto error (len = %d)", len);
      return (0);
    }
  return (hdr->id);
}

/**
 * @brief transmit an receive a request
 * @param[in] conf configuration
 * @param[in] request request to send
 * @param[out] output where to write decoded answer
 * @param[in] max_len maximum answer len
 * @retval size written
 * @retval -1 on error
 **/

int			transceive_query(t_conf *conf, t_request *request, char *output, int max_len)
{
  struct dns_hdr	*hdr;
  uint16_t		id;
  uint32_t		count = 0;
  int			len, total_len = 0;
  
  if ((id = send_query(conf, request)) == 0)
    return (-1);
  if ((request->len = get_simple_reply(conf, (char *)&(request->req_data), id)))
    {
      request->req_data[request->len] = 0;
      hdr = (struct dns_hdr *)&(request->req_data);
      if (hdr->rcode)
	{
	  MYERROR("Auth error = %s\n", dns_error[hdr->rcode % (MAX_DNS_ERROR-1)]);
	  return (-1);
	}
      while ((len = request->request_functions->rr_decode_next_reply(request, &output[total_len], 
								     max_len - total_len, count++)))
	{
	  total_len += len;
	}
      return (total_len);
    }
  return (-1);
}


/**
 * @brief send a simple request
 * @param[in] conf configuration
 * @param[in] request request to send
 * @param[in] subdomain destination subdomain
 * @param[in] domain destination domain
 * @param[in] session_id session to use
 * @retval 0 on success
 * @retval -1 on error
 **/

int		create_simple_req(t_conf *conf, t_request *request, 
				  char *subdomain, char *domain, uint16_t session_id)
{
  t_packet	*packet;
  
  packet = (t_packet *)&request->u.packet;
  memset(packet, 0 , sizeof(t_packet));
  packet->session_id = session_id;
  packet->ack_seq = myrand();
  packet->seq = myrand();
  request->len = PACKET_LEN;
  request->type = conf->query_functions->type;
  request->request_functions = conf->query_functions;
  if ((strlen(conf->domain) + strlen(subdomain)) > MAX_DNS_LEN)
    return (-1);
  request->domain = domain;
  strcpy(request->domain, subdomain);
  strcat(request->domain, conf->domain);
  return (0);
}

/**
 * @brief put a specific data in the request
 * @param[in] conf configuration
 * @param[in] client client queue
 * @param[in] request request to send
 * @retval request len send
 */

int	push_req_data(t_conf *conf, t_simple_list *client, t_list *queue, t_request *req)
{
  t_packet		*query;
  char			*ptr;

  req->domain = conf->domain;
  req->request_functions = conf->query_functions;
  req->type =  conf->query_functions->type;

  query =  (t_packet *)&(req->u.packet);
  if (!req->len)
    query->type = NOP;
  else
    {
      if (req->len > 0)
	query->type = DATA;
      else
	{
	  DPRINTF(1, "send desauth\n");
	  query->type = DESAUTH;
	  req->len = 0;
	}
    }
  req->len += PACKET_LEN;
  query->session_id = client->session_id;
  PUT_16(&query->seq,client->num_seq);
  PUT_16(&query->ack_seq,queue->peer.ack_seq);
  queue->info.num_seq = client->num_seq;
  ptr = ((char *)query) + PACKET_LEN;
  DPRINTF(2, "Client 0x%x : push data [%d] ack [%d] len = %d\n", client->session_id, client->num_seq, 
	  queue->peer.ack_seq, req->len-(int)PACKET_LEN);
  if ((queue->len = create_request(conf, &(queue->data), req)))
    return (queue->len);
  return (0);
}
