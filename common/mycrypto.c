/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: mycrypto.c,v 1.4.4.6 2010/06/16 08:40:10 dembour Exp $
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hmac_sha1.h"
#include "mycrypto.h"

static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

void	alphanum_random(char *buffer, int len)
{
  buffer[len] = 0;

  while (len--)
    buffer[len] = charset[rand() % (sizeof(charset)-1)];
}

/**
 * @brief interface to an HMAC function
 * @param[in] input data to sign
 * @param[in] len input len
 * @param[in] key key for HMAC
 * @param[out] output output
 * @param[in] max_len max output len
 **/

int		sign_challenge(char *input, int len, 
			       char *key, char *output, int max_len)
{
  unsigned char sha1sum[SHA1_SIZE+1];
  unsigned int	output_len = SHA1_SIZE;
  int		i=0;

  sha1_hmac(
	    key ? (unsigned char *)key : (unsigned char *)"", 
	    key ? strlen(key) : 0,
	    (unsigned char *)input, 
	    len,
	    sha1sum
	    );
  if (output_len*2 < max_len)
    {
      for (i = 0; i < output_len; i++) 
	sprintf(output + 2*i, "%.2X", sha1sum[i]&0xff);
      output[2*i] = 0;
    }
  return (2*i);
}


