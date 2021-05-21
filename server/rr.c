/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: rr.c,v 1.6.4.3 2010/01/20 16:09:07 collignon Exp $
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

#include "list.h"
#include "dns.h"
#include "server.h"
#include "rr.h"
#include "requests.h"
#include "dns.h"
#include "debug.h"

#include <string.h>

static const t_rr_functions rr_function[] = {
  { TYPE_TXT,	TYPE_TXT,	&rr_add_reply_encode,	0,	&rr_get_reply_length_encode},
  { TYPE_KEY,	TYPE_KEY,	&rr_add_reply_raw,	0,	&rr_get_reply_length_raw},
  //  { TYPE_A,	TYPE_CNAME,	&rr_add_reply_cname,	0,	&rr_get_reply_length_cname}, 
  //  { TYPE_NS,	TYPE_NS,	0,			0,	0},
  //  {TYPE_SIG, TYPE_SIG,	&rr_add_reply_raw,	0,	&rr_get_reply_length_raw},
  {0,0,0,0}
};


/**
 * @brief get functions pointer for decoding data
 * @param[in] request type
 * @retval functions pointer
 **/

const t_rr_functions		*get_rr_function_by_type(uint16_t type)
{
  int			i = 0;
  
  while (rr_function[i].type 
	 && (rr_function[i].type != type))
    i++;
  return (rr_function[i].type ? &rr_function[i] : 0);
}

/**
 * @brief add a answer in the DNS request
 * @param[in] hdr DNS header
 * @param[in] where memory to write
 * @param[in] type type of request (TXT, KEY ...)
 * @param[in] encoded_data data to put
 * @param[in] what compress pointer to the subdomain or 0
 * @retval rr header
 **/

void                    *rr_add_data(struct dns_hdr *hdr, void *where, uint16_t type, char *encoded_data, uint16_t what)
{
  struct rr_hdr         *rr;

  PUT_16(&hdr->ancount, GET_16(&hdr->ancount)+1);
  hdr->arcount = 0;
  if (!what) /* std compression */
    PUT_16(where, sizeof(struct dns_hdr) | COMPRESS_FLAG);
  else
    PUT_16(where, what | COMPRESS_FLAG);
  rr = where + sizeof(uint16_t);
  PUT_16(&rr->type, type);
  PUT_16(&rr->klass, CLASS_IN);
  PUT_32(&rr->ttl, 3);
  if (encoded_data)
    {
      JUMP_RR_HDR(rr)[0] = 'A' +  GET_16(&hdr->ancount)-1;
      strcpy(JUMP_RR_HDR(rr)+1, encoded_data);
    }
  else /* fake IP adress */
    {  
      PUT_16(&rr->rdlength,4);
      strcpy(JUMP_RR_HDR(rr), "AAAA");
    }
  return (rr);
}
/**
 * @brief add data as a CNAME no available
 **/

void                    *rr_add_reply_cname(t_conf *conf, t_request *req, struct dns_hdr *hdr, void *where, char *encoded_data)
{
  struct rr_hdr         *rr;
  int                   len;
  char			domain[MAX_EDNS_LEN];
  char			*my_domain;

  /* TODO : should avoid the strcpy each time */
  strncpy(domain, req->domain, sizeof(domain));
  dns_encode(domain);
  
  my_domain = strstr((char *) (hdr+1), domain);
  rr = rr_add_data(hdr, where, req->reply_functions->reply_type , encoded_data, 0);

  where = JUMP_RR_HDR(rr);
  dns_encode(where);
  len = strlen(where);

  ((char *)where)[len] = COMPRESS_FLAG_CHAR; /* add domain name */
  ((char *)where)[len+1] = (uint16_t) (my_domain - (char *)hdr);
  PUT_16(&rr->rdlength,len + 2);
  /* Add fake entry  CNAME is at x.x.x.x */
  rr = rr_add_data(hdr, where+len+2, TYPE_A, 0, JUMP_RR_HDR(rr) - (char *)hdr);
  where = JUMP_RR_HDR(rr);
  //  PUT_16(&rr->type, TYPE_A);
  len = strlen(where);
  return (where + len);
}

/**
 * @brief add data and dns_encode it
 * @param[in] conf configuration
 * @param[in] req request received
 * @param[in] hdr DNS header
 * @param[in] where memory address
 * @param[in] encoded_data data encoded in base64
 **/

void                    *rr_add_reply_encode(t_conf *conf, t_request *req, struct dns_hdr *hdr, void *where, char *encoded_data)
{
  struct rr_hdr         *rr;
  int                   len;

  rr = rr_add_data(hdr, where, req->reply_functions->reply_type, encoded_data, 0);
  where = JUMP_RR_HDR(rr);
  dns_encode(where);
  len = strlen(where);
  PUT_16(&rr->rdlength,len);
  return (where + len);
}

/**
 * @brief add data but don't dns_encode it
 * @param[in] conf configuration
 * @param[in] req request received
 * @param[in] hdr DNS header
 * @param[in] where memory address
 * @param[in] encoded_data data encoded in base64
 **/

void                    *rr_add_reply_raw(t_conf *conf,  t_request *req, struct dns_hdr *hdr, 
					  void *where,  char *encoded_data)
{
  struct rr_hdr         *rr;
  int                   len;
  
  rr = rr_add_data(hdr, where, req->reply_functions->reply_type, encoded_data, 0);
  where =JUMP_RR_HDR(rr);
  len = strlen(where); 
  PUT_16(&rr->rdlength,len);
  return (where + len);
}

int			rr_get_reply_length_cname(struct dns_hdr *hdr, t_simple_list *client, int query_len)
{

  /*
   */
  return (0);
}

/**
 * @brief check available length left before being encoded
 * @param[in] client client
 * @param[in] query_len query len 
 * @retval len available
 **/

int			rr_get_reply_length_encode(struct dns_hdr *hdr, t_simple_list *client, int query_len)
{
  void			*end_query;
  int			len;
  int			total_query_len;

  if (!(end_query = jump_end_answer(hdr, query_len)))
    return (0);
  total_query_len = (int) (end_query - (void *)hdr);
  len = (ENCODE_DATA_AVAILABLE(total_query_len, 
			       strlen(JUMP_DNS_HDR(hdr)), MAX_DNS_LEN));

  if ((len > 0) && (len > PACKET_LEN + 2))
    /* IDX + EOL = 2 bytes  */
    len -=  (PACKET_LEN + 2);
  else
    len = 0;
  if (client && client->control.mtu_size)
    len = MIN(DECODED_LEN(client->control.mtu_size), len);
  DPRINTF(3, "%s return %d\n", __FUNCTION__, len);
  return (len);
}

/**
 * @brief check available length left for raw data
 * @param[in] client client
 * @param[in] query_len query len 
 * @retval len available
 **/

int			rr_get_reply_length_raw(struct dns_hdr *hdr, t_simple_list *client, int query_len)
{
  char			*end_query;
  int			len;
  int			total_query_len;

  if (!(end_query = jump_end_answer(hdr, query_len)))
    return (0);
  total_query_len = (int) (end_query - (char *)hdr);
  len = (RAW_DATA_AVAILABLE(total_query_len, 
			    strlen(JUMP_DNS_HDR(hdr)), MAX_DNS_LEN));

  if ((len > 0) && (len > PACKET_LEN + 2))
    /* IDX + EOL = 2 bytes  */
    len -=  (PACKET_LEN + 2);
  else
    len = 0;
  /* max mtu ? */
  if (client && client->control.mtu_size)
    len = MIN(client->control.mtu_size, len);
  DPRINTF(3, "%s return %d\n", __FUNCTION__, len);
  return (len);
}
