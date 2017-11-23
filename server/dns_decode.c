/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: dns_decode.c,v 1.7.4.4 2010/02/11 15:05:49 collignon Exp $
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
#include <arpa/inet.h>

#include "packet.h"
#include "dns.h"
#include "server.h"
#include "myerror.h"
#include "mystrnlen.h"
#include "log.h"
#include "debug.h"
#include "server.h"
#include "requests.h"

extern const t_command dns_commands[];

/* 
   Strip dot and domain name 
   extract the dns command
   request is always ended by NULL
*/

static int	dns_strip_dot_and_domain(t_conf *conf, t_request *req, char *output)
{
  char		*ptr;
  char		*ptr2;
  unsigned int 	i=0, j, len;
  int		req_len, domain_len;

  req_len = strlen(output);
  domain_len = strlen(conf->my_domain);
  ptr = strstr(output + (req_len - domain_len), conf->my_domain);
  if (!ptr)
    {
      // FIXME bug ipv6 support ?
      LOG("Query from %u.%u.%u.%u for unknown domain %s",
#ifndef WORDS_BIGENDIAN
	  (unsigned int) ((req->sa.sin_addr.s_addr) & 0xff),
	  (unsigned int) ((req->sa.sin_addr.s_addr >> 8) & 0xff),
	  (unsigned int) ((req->sa.sin_addr.s_addr >> 16) & 0xff),
	  (unsigned int) ((req->sa.sin_addr.s_addr >> 24) & 0xff),
#else
	  (unsigned int) ((req->sa.sin_addr.s_addr >> 24) & 0xff),
	  (unsigned int) ((req->sa.sin_addr.s_addr >> 16) & 0xff),
	  (unsigned int) ((req->sa.sin_addr.s_addr >> 8) & 0xff),
	  (unsigned int) ((req->sa.sin_addr.s_addr) & 0xff),
#endif
	  output);
      return (-1);
    }
  /* 
     look for :
	resource.<domain> 
	auth.<domain> 
	...
	cf. request.c
  */
  while (dns_commands[i++].str)
    {
      if ( ( dns_commands[i-1].str_len + 1 + domain_len <= req_len )
	   && ((ptr2 = strstr(ptr - dns_commands[i-1].str_len, dns_commands[i-1].str))))
	{
	  ptr = ptr2;
	  req->cmd = &dns_commands[i-1];
	  break;
	}
    }
  strcpy(req->domain, ptr);
  *ptr = 0;

  len = (unsigned int) (ptr - output);
  /* delete dots */
  for (i=0,j=0; i < len; ++i)
    {
      if (output[i] != '.')
	{
          if (i != j)
            output[j] = output[i];
	  ++j;
	}
    }
  output[j] = 0;
  return (0);
}


/* 
   Not a RFC compatible decoder 
   return -1 if domain is incorrect 
   dns_decode check max size of host
   strip the domain name
*/

int		dns_decode(t_conf *conf, t_request *req, char *input, char *output)
{
  int		total_len = 0;
  uint8_t	len;
  char		*ptr;

  ptr = input;
  *output = 0;

  if (strlen(ptr) < (strlen(conf->my_domain) + 1))
    return (-1);
  while (*ptr)
    {
      len = (uint8_t) *ptr;
      total_len += len;
      if ((len > 63) || (total_len > MAX_HOST_NAME_ENCODED))
	{
	  MYERROR("NAME TOO long %d %d", len, total_len + len);
	  return (-1);
	}
      strncat(output, ptr + 1, len);
      output[total_len] = 0;
      if (len)
	{
	  if (++total_len > MAX_HOST_NAME_ENCODED)
	    return (-1);
	  strcat(output , ".");
	  len++;
	}
      ptr += (len);
    }
  if (total_len > 0)
    output[total_len -1 ] = 0;
  return (dns_strip_dot_and_domain(conf, req, output));
}
