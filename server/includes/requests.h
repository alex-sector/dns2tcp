/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: requests.h,v 1.4.4.2 2010/02/10 15:29:51 dembour Exp $
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

#ifndef __REQUESTS_H__
#define  __REQUESTS_H__

typedef struct s_command {
  const char	*str;
  uint8_t	str_len;
  uint8_t	authenticated;
  int		(*deal_cmd)(t_conf *, t_request *, t_packet *, t_simple_list *);
}		t_command;

int	get_incoming_request(t_conf *);
int	send_reply(t_conf *conf, t_request *req, t_data *data);
int	send_ascii_reply(t_conf *conf, t_request *req, t_packet *packet, char *data);
void    *add_reply(struct dns_hdr *, void *, uint16_t , char *);
int	get_request(t_conf *conf, t_request *req, t_data *output);
int	send_resources_reply(t_conf *conf, t_request *, t_packet *, t_simple_list *);


#endif
