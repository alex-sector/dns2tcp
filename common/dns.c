/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: dns.c,v 1.16.4.2 2010/02/11 16:06:37 dembour Exp $
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

#include "packet.h"
#include "dns.h"
#include "myerror.h"
#include "mystrnlen.h"
#include "debug.h"


const char	*dns_error[MAX_DNS_ERROR] = {
  "No error",
  "Format error",
  "Server failure",
  "Name error",
  "Not implemented",  
  "Request refused",
};


/**
 * @brief jump at the end of the qname section
 * @param[in] ptr where to search
 * @param[in] maxlen max size
 */

void		*jump_qname(void *ptr, int maxlen)
{
  char		*name;
  
  if (! maxlen)
    return (0);
  name = ptr;
  while ((*name) && (maxlen--))
    {
      if ((*name & COMPRESS_FLAG_CHAR) == COMPRESS_FLAG_CHAR)
	{
	  if (maxlen-1)
	    return (name + 2);
	  return (0);
	}
      name++;
    }
  return ((maxlen-1) ? name + 1 : 0);
}


void			*jump_edns(void *buffer, int max_len)
{
  struct dns_hdr	*hdr;
  void			*where;
  uint16_t		records;
  struct rr_hdr		*aarecord;

  hdr = (struct dns_hdr *) buffer;
  if (!(where = jump_end_answer(buffer, max_len)))
    return (0);
  /* jump additional records */
  for (records =  GET_16(&hdr->nscount); records; records--)
    {
      if (!(where = jump_qname(where, max_len - (where - (void *)hdr))))
	return (0);
    }
  aarecord = where;
  for (records =  GET_16(&hdr->arcount); records; records--)
    {
      if ((max_len - (where - (void *)hdr) -sizeof(struct add_record)) > max_len)
	return (0);
      if (GET_16(&aarecord->type) ==  TYPE_EDNS)
	return (aarecord);
      aarecord++;
    }
  return (0);
}

/**
 * @brief jump at the end of the answer
 * @param[in] ptr where to search
 * @param[in] maxlen max size
 */

void			*jump_end_answer(void *buffer, int max_len)
{
  struct dns_hdr	*hdr;
  void			*where;
  uint16_t		records;
  struct rr_hdr		*rr;
  uint16_t		len;
  uint16_t		available_len;
  
  hdr = buffer;
  if (!GET_16(&hdr->qdcount))
    return (0);
  if (!(rr = where = jump_end_query(hdr, GET_16(&hdr->qdcount), max_len)))
    return (0);
  available_len =  max_len - (uint16_t) ((void *)where - (void *)hdr);
  for (records =  GET_16(&hdr->ancount); records; records--)
    {
      available_len =  max_len - (uint16_t) ((void *)rr - (void*)hdr);
      if (!(rr = jump_qname(where, available_len)))
	return (0);
      len = GET_16(&rr->rdlength);
      if (( ((void *)rr - buffer) + len + RR_HDR_SIZE) > max_len)
	return (0);
      rr =  (struct rr_hdr *) (JUMP_RR_HDR(rr) + len);
      where = rr;
    }
  return (rr);
}

uint16_t		get_edns_size(void *buffer, int max_len)
{
  struct add_record	*edns;
  
  if (!(edns = jump_edns(buffer, max_len)))
    return (0);
  return (GET_16(&edns->payload_size));
}


/**
 * @brief jump at the end of the query
 * @param[in] ptr where to search
 * @param[in] nb max number of requests
 * @param[in] maxlen max size
 */

void			*jump_end_query(void *buffer, int nb, int max_len)
{
  void			*tmp;
  void			*max_ptr;
  int			len;

  max_ptr = ((char *)buffer) + max_len;
  tmp = ((char *)buffer) + DNS_HDR_SIZE;
  while ((nb--) && (tmp <= max_ptr))
    {
      if ((len = mystrnlen(tmp , MAX_HOST_NAME_ENCODED+1)) > MAX_HOST_NAME_ENCODED)
	{
	  MYERROR("Host name too long (%d)\n", len);
	  return (0);
	}
      tmp = jump_qname(tmp, max_ptr-tmp) +  REQ_HDR_SIZE;
    }
  return ((tmp <= max_ptr) ? tmp : 0);
}

static unsigned int	search_dot(char *buffer)
{
  unsigned int		len = 0;
  
  while ((buffer[len] != 0) 
	 &&  (buffer[len] != '.'))
      len++;
  return (len);
}

/**
 * @brief encode a data to the qname format
 * @param[out] data
 **/

void		dns_encode(char *data)
{
  char		buffer2[MAX_EDNS_LEN];
  int		len;
  char		*buffer = buffer2;

  strncpy(buffer, data, MAX_DNS_LEN-1);
  do 
    {
      len = search_dot(buffer);
      if (len < 64)
	{
	  *data = (char) len;
	  if (len)
	    strncpy(data + 1, buffer, len);
	  if (buffer[len])
	    buffer++;
	}
      else
	{
	  len = 63;
	  *data = (char) len;
	  strncpy(data + 1, buffer, len);
	}
      buffer += len;
      data += len + 1;
    } while (len);
}

/**
 * @brief simple qname decoder, do not strip anything
 * @param[in] input data
 * @param[out] output where to write
 * @param[in] max_len maximum len 
 **/


void		dns_simple_decode(char *input, char *output, int max_len)
{
  uint8_t	len;
  char		*ptr;
  int		total_len =0;
  
  ptr = input;
  *output = 0;
  while (*ptr)
    {
      len = (uint8_t) *ptr;
      /* compression not supported */
      if (len > 63)
	len = 0;
      total_len +=len;
      if (++total_len > max_len)
	break;
      output[total_len] = 0;
      if (!len)
	break;
      strncat(output, ptr + 1, len++);
      output[total_len-1] = '.';
      ptr += len;
    }
  if (total_len > 0)
  output[total_len-1] = 0;
}

/**
 * @brief simple qname decoder, but strip 'fake' dot
 * @param[in] input data
 * @param[out] output where to write
 * @param[in] max_len maximum len 
 **/

void		dns_simple_decode_strip_dot(char *input, char *output, int max_len)
{
  uint8_t	len;
  char		*ptr;
  int		total_len =0;
  
  ptr = input;
  *output = 0;
  while (total_len < max_len - 1)
    {
      len = (uint8_t) *ptr;
      /* compression not supported */
      if (len > 63)
	len = 0;
      total_len +=len;
      if (total_len > max_len)
	{
	  MYERROR("Error while decoding reply max_len was %d total len = %d\n", max_len, 
		  total_len);
	  break;
	}
      strncat(output, ptr + 1, len);
      output[total_len] = 0;
      ptr += (len + 1);
    }
}
