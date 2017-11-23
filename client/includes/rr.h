/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: rr.h,v 1.2 2008/08/26 15:49:59 dembour Exp $
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

#ifndef __RR_H__
#define __RR_H__

#include "dns.h"
#include "requests.h"

typedef struct s_rr_functions {
  char		*name;
  uint16_t	type;
  void		*(*rr_add_reply)(struct dns_hdr *, void *, uint16_t , char *);
  int		(*rr_decode_next_reply)(t_request *, char *, int, int);
  int		(*rr_available_len)();
}		t_rr_functions;

#define TYPE_A            1
#define TYPE_NS           2
#define TYPE_MD           3
#define TYPE_MF           4
#define TYPE_CNAME        5
#define TYPE_SOA          6
#define TYPE_MB           7
#define TYPE_MG           8
#define TYPE_MR           9
#define TYPE_NULL         10
#define TYPE_WKS          11
#define TYPE_PTR          12
#define TYPE_HINFO        13
#define TYPE_MINFO        14
#define TYPE_MX           15
#define TYPE_TXT          16
#define TYPE_RP           17
#define TYPE_AFSDB        18
#define TYPE_X25          19
#define TYPE_ISDN         20
#define TYPE_RT           21
#define TYPE_NSAP         22
#define TYPE_NSAP_PTR     23
#define TYPE_SIG          24
#define TYPE_KEY          25
#define TYPE_PX           26
#define TYPE_GPOS         27
#define TYPE_AAAA         28
#define TYPE_LOC          29
#define TYPE_NXT          30
#define TYPE_EID          31
#define TYPE_NIMLOC       32
#define TYPE_SRV          33
#define TYPE_ATMA         34
#define TYPE_NAPTR        35
#define TYPE_KX           36
#define TYPE_CERT         37
#define TYPE_A6           38
#define TYPE_DNAME        39
#define TYPE_SINK         40
#define TYPE_OPT          41
#define TYPE_APL          42
#define TYPE_DS           43
#define TYPE_SSHFP        44
#define TYPE_IPSECKEY     45
#define TYPE_RRSIG        46
#define TYPE_NSEC         47
#define TYPE_DNSKEY       48
#define TYPE_DHCID        49
#define TYPE_NSEC3        50
#define TYPE_NSEC3PARAM   51
#define TYPE_HIP          55 
#define TYPE_SPF          99 
#define TYPE_UINFO        100
#define TYPE_UID          101
#define TYPE_GID          102
#define TYPE_UNSPEC       103
#define TYPE_TKEY         249
#define TYPE_TSIG         250
#define TYPE_IXFR         251
#define TYPE_AXFR         252
#define TYPE_MAILB        253
#define TYPE_MAILA        254

t_rr_functions	*get_rr_function_by_type(uint16_t );
t_rr_functions	*get_rr_function_by_name(char *);

int rr_decode_next_reply_encode(t_request *, char *, int , int);
int rr_decode_next_reply_raw(t_request *, char *, int , int);

#endif /* __RR_H__ */

