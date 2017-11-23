/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: dns.h,v 1.16.4.2 2010/06/01 16:05:05 collignon Exp $
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

#ifndef __DNS_H__
#define __DNS_H__

#include "config.h"

#ifndef _WIN32
#include <unistd.h>
#include <arpa/inet.h>
#else
#include "mywin32.h"
#endif
#include "base64.h"

#define MAX_DNS_LEN			512
#define MAX_EDNS_LEN			4096

#define EDNS_HEADER			11			

#define MAX_HOST_NAME_ENCODED		200 /* need space for reply */
#define MAX_HOST_NAME_DECODED		DECODED_LEN((MAX_HOST_NAME_ENCODED))

#define ENCODED_LEN(len)		(((len) + (((len) / 63) + 1)))
#define DECODED_LEN(len)		( ((len)>0) ? (((len) - (((len) / 63) + 1))) : 0)

/* USE EDNS or std DNS */
#define MAX_ENCODE_DATA(len, dns_size)	\
	( \
		 (((len)+RR_HDR_SIZE) > (dns_size - AUTHORITATIVE_SIZE)) ? 0 :		\
			DECODED_LEN(DECODED_BASE64_SIZE(\
			( (dns_size - AUTHORITATIVE_SIZE) - (len) - (RR_HDR_SIZE)) ) \
				    ))

#define MAX_RAW_DATA(len, dns_size)	\
	( \
		 (((len)+RR_HDR_SIZE) > (dns_size - AUTHORITATIVE_SIZE)) ? 0 :	\
			DECODED_BASE64_SIZE(\
		    ( (dns_size - AUTHORITATIVE_SIZE) - (len) - (RR_HDR_SIZE) ) ) \
	  )


#define AUTHORITATIVE_SIZE 50 /* should be better defined ... */
/* Additional record + Authoritative nameserver */


#define ENCODE_DATA_AVAILABLE(len, query_len, dns_size)  (client && (client->control.use_compress)) ? \
				((MAX_ENCODE_DATA((len + 2), (dns_size)))) :				\
				((MAX_ENCODE_DATA((len + query_len), (dns_size))))

#define RAW_DATA_AVAILABLE(len, query_len, dns_size)  (client && (client->control.use_compress)) ? \
				((MAX_RAW_DATA((len + 2), (dns_size)))) :				\
				((MAX_RAW_DATA((len + query_len), (dns_size))))

/*
#define ENCODE_DATA_AVAILABLE(len, query_len, dns_size)  (client && (client->control.use_compress)) ? \
				((MAX_ENCODE_DATA((len) + 2, (dns_size + 1)))) : \
				((MAX_ENCODE_DATA((len) + (query_len), (dns_size))))

#define RAW_DATA_AVAILABLE(len, query_len, dns_size)  (client && (client->control.use_compress)) ? \
				((MAX_RAW_DATA((len) + 2, (dns_size + 1)))) : \
				((MAX_RAW_DATA((len) + (query_len), (dns_size))))
*/
#define	MAX_QNAME_DATA(domain)		(DECODED_BASE64_SIZE(MAX_HOST_NAME_DECODED - strlen(domain) - 1))

/* GCC alignement padding workaround */

#define DNS_HDR_SIZE			12
#define	RR_HDR_SIZE			10
#define	REQ_HDR_SIZE			4

#define	JUMP_DNS_HDR(hdr)		((char *)hdr + DNS_HDR_SIZE)
#define	JUMP_RR_HDR(hdr)		((char *)hdr + RR_HDR_SIZE)
#define	JUMP_REQ_HDR(hdr)		((char *)hdr + REQ_HDR_SIZE)

#define COMPRESS_FLAG_CHAR		0xC0
#define COMPRESS_FLAG			0xC000
#define	GET_DECOMPRESS_OFFSET(offset)	((ntohs(offset)) & ~(COMPRESS_FLAG))

/* Why not */
#define	MAX_COMPRESS_DEPTH		10


/* Network order */
#define PUT_16(dst, src) do \
	{\
		((unsigned char *)(dst))[0] = (uint8_t) ((src ) >> 8) ;       \
		((unsigned char *)(dst))[1] = (uint8_t) (src) ;		\
	} while (0)

#define PUT_32(dst, src) do \
	{\
	  ((unsigned char *)(dst))[0] = (uint8_t) ((src ) >> 24) ;      \
	  ((unsigned char *)(dst))[1] = (uint8_t) ((src ) >> 16) ;      \
	  ((unsigned char *)(dst))[2] = (uint8_t) ((src ) >> 8) ;       \
	  ((unsigned char *)(dst))[3] = (uint8_t) (src) ;	       \
	} while (0)

/* Host order */
#define GET_16(src) ((((unsigned char *)(src))[0] << 8) | (((unsigned char *)(src))[1]) )
#define GET_32(src) (\
			  (((unsigned char *)(src))[0] << 24) |		\
			  (((unsigned char *)(src))[1] << 16) |		\
			  (((unsigned char *)(src))[2] << 8) |		\
			  (((unsigned char *)(src))[3] )		\
		     )

/* FIXME hardcoded '=' is bad ! (check base64_padding ...) */
#define RESOURCE	"=resource."
#define AUTH		"=auth."
#define CONNECT		"=connect."



struct				dns_hdr {
  uint16_t			id;
#ifndef WORDS_BIGENDIAN
  uint16_t			rd:1, /* recurse demand */
				tc:1, /* truncated */
				aa:1, /* authorative */
				opcode:4,
				qr:1, 
				rcode:4,
				z:3,
				ra:1; /* recurse available */
#else
  uint16_t			qr:1,
				opcode:4,
				aa:1,
				tc:1,
				rd:1,
				ra:1,
				z:3,
				rcode:4;
#endif
#define RCODE_NO_ERR		0x0
#define RCODE_FORMAT_ERR	0x1
#define RCODE_SRV_FAILURE	0x2
#define RCODE_NAME_ERR		0x3
#define RCODE_NOT_IMPLEMENTED	0x4
#define RCODE_REFUSED		0x3
  uint16_t			qdcount; /* nb queries */
  uint16_t			ancount; /* nb answers */
  uint16_t			nscount; /* authority records */
  uint16_t			arcount; /* additional records */
}  __attribute__((packed));


#define MAX_DNS_ERROR	6
extern const char *dns_error[MAX_DNS_ERROR];

struct		req_hdr {
  uint16_t	qtype; /* TXT */
  uint16_t	qclass; /* IN | CHAOS */
} __attribute__((packed));

struct		rr_hdr {
  uint16_t	type;
#define TYPE_TXT 16
#define TYPE_KEY 25
  uint16_t	klass;
#define CLASS_IN 1
  uint32_t	ttl;
  uint16_t	rdlength;
} __attribute__((packed));

struct		add_record {
  uint8_t	name;
  uint16_t	type;
#define TYPE_EDNS 41
  uint16_t	payload_size;
  uint8_t	rcode;
  uint8_t	version;
  uint16_t	z;
  uint16_t	length;
} __attribute__((packed));

void    dns_simple_decode(char *input, char *output, int max_len);
void	dns_simple_decode_strip_dot(char *input, char *output, int max_len);
void	dns_encode(char *);
void	*jump_end_query(void *, int, int);
void   *jump_qname(void *, int);
void	*jump_end_answer(void *buffer, int max_len);
void	*jump_edns(void *buffer, int max_len);

#endif
