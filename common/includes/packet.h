/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: packet.h,v 1.9.4.1 2010/01/06 12:50:40 dembour Exp $
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

#ifndef __PACKET_H__
#define __PACKET_H__

#ifndef _WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#else
#include "mywin32.h"
#endif

#include "list.h"
#include "memdump.h"

/* type */




/* end type */

/*
Error MSG
*/
#define MAX_ERROR_SIZE	64

#define ERR_RESOURCE		"Resource Unknown"
#define ERR_CONN_REFUSED	"Connexion refused"
#define ERR_AUTH_FAILED		"Authentication Failed"
#define ERR_BAD_SEQ		"Bad seq number"


#undef MIN
#define MIN(a,b)	((a) > (b) ? (b) : (a))

#define	PACKET_LEN	(sizeof(t_packet))

#define MAX_SEQ 0xffff

typedef struct		s_trace {
  uint16_t		max_packet_size;
  uint16_t		session_reply_size;
  uint16_t		data_reply_size;
  uint8_t		enable_multi_reply;
  uint16_t		len_request;
  uint8_t		request_type;
#define	SEND_ONCE	0
#define	SEND_FRAG	1
} __attribute__((packed)) t_trace;


typedef struct		s_packet {
  uint16_t		session_id;
  uint16_t		ack_seq;
  uint16_t		seq;
  uint8_t		type;
#define OK		0x0
#define DESAUTH		0x1
#define ERR		0x2
#define	NOP		0x4
#define CHECK_MTU	0x6

#define DATA		(1 << 3)
#define ACK		(1 << 4)
#define NACK		(1 << 5)
#define USE_COMPRESS	(1 << 6)
} __attribute__((packed)) t_packet;

/* DATA goes  after */

typedef struct		s_data {
  char			*buffer;
  int			len;
}			t_data;

#endif
