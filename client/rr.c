/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: rr.c,v 1.4.4.4 2010/02/11 16:06:37 dembour Exp $
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

#include "dns.h"
#include "client.h"
#include "requests.h"
#include "rr.h"
#include "debug.h"


t_rr_functions rr_function[] = {
  { "TXT",  TYPE_TXT,	0, &rr_decode_next_reply_encode,	0 /* UNUSED */},
  { "KEY",  TYPE_KEY,	0, &rr_decode_next_reply_raw,		0 /* UNUSED */},
  {0,0,0,0,0}
  /*
  { "A",    TYPE_A,	0, &rr_decode_next_reply_encode,	0 },
  { "SIG",  TYPE_SIG,	0, &rr_decode_next_reply_raw,		0 },
  { "NS",  TYPE_NS,	0, 0, 0},
*/
};


t_rr_functions		*get_rr_function_by_type(uint16_t type)
{
  int			i = 0;
  
  while (rr_function[i].type 
	 && (rr_function[i].type != type))
    i++;
  return (rr_function[i].type ? &rr_function[i] : 0);
}

t_rr_functions		*get_rr_function_by_name(char *name)
{
  int			i = 0;
  
  while (rr_function[i].name
	 && (strcmp(rr_function[i].name, name)))
    i++;
  return (rr_function[i].name ? &rr_function[i] : 0);
}


 struct rr_hdr		*jump_next_reply(t_request *req, char *output, int max_len, int idx, uint8_t is_encode)
{
  void			*ptr;
  uint32_t		count;
  struct rr_hdr		*answer;
  struct dns_hdr	*hdr;

  hdr = (struct dns_hdr *) &(req->req_data);
  if (!(ptr  = jump_end_query(&(req->req_data), GET_16(&hdr->qdcount), req->len)))
    {
      fprintf(stderr, "invalid reply\n");
      return (0);
    }
   for (count = GET_16(&hdr->ancount); count ; count--)
    {
      if (idx + 1 >  GET_16(&hdr->ancount))
	return (0);
      if ((answer = jump_qname(ptr, req->len - (int) ((unsigned long) ptr - (unsigned long) hdr))) == 0)
	return (0);
      if ((GET_16(&answer->rdlength) + (uint16_t)((unsigned long)answer-(unsigned long)hdr)) > req->len)
	return (0);
      if ( (JUMP_RR_HDR(answer)[0 + is_encode] - idx) == 'A')
	return (answer);
      ptr = (void *)(JUMP_RR_HDR(answer) + GET_16(&answer->rdlength));
    }
   return (0);
}

int                     rr_decode_next_reply_encode(t_request *req, char *output, int max_len, int idx)
{
  struct rr_hdr	         *reply;
  char                  buffer[MAX_EDNS_LEN - DNS_HDR_SIZE - RR_HDR_SIZE];
  
  if (!(reply = jump_next_reply(req, output, max_len, idx, 1)))
    return (0);
  
  if (ENCODED_LEN(DECODED_BASE64_SIZE(strlen(JUMP_RR_HDR(reply)))) > max_len)
    {
      DPRINTF(1,"Packet seems too big, this part is drop");
      return (0);
    }
  dns_simple_decode_strip_dot(JUMP_RR_HDR(reply), buffer, GET_16(&(reply->rdlength)));
  DPRINTF(3, "%s base64 data was = %s (reply len = %d)\n", __FUNCTION__, &buffer[1],  GET_16(&(reply->rdlength)));
  /*  jump idx  ->  &buffer[1] */
  return (base64_decode((unsigned char *)output, &buffer[1]));
}

int                     rr_decode_next_reply_raw(t_request *req, char *output, int max_len, int idx)
{
  struct rr_hdr		*reply;
  char                  buffer[MAX_EDNS_LEN - DNS_HDR_SIZE - RR_HDR_SIZE];
  
  if (!(reply = jump_next_reply(req, output, max_len, idx, 0)))
    return (0);
  memset(buffer, 0, sizeof(buffer));
  strncpy(buffer, JUMP_RR_HDR(reply), GET_16(&(reply->rdlength)));
  DPRINTF(3, "%s base64 data was = %s (reply len = %d)\n", __FUNCTION__, buffer,  GET_16(&(reply->rdlength)));
  if (DECODED_BASE64_SIZE(strlen(buffer)) > max_len)
    return (0);
  /*  jump idx  ->  &buffer[1] */
  return (base64_decode((unsigned char *)output, &buffer[1]));
 }
