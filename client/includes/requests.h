/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: requests.h,v 1.6.4.2 2010/06/02 14:30:25 collignon Exp $
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

typedef struct		s_request {
  union			 {
    char		data[MAX_EDNS_LEN];
    t_packet		packet;
  }			u;
#define req_data	u.data
  int			len;
  uint16_t		type;
  char			*domain;
  struct s_rr_functions *request_functions;
}			t_request;

int		add_edns(t_conf *conf, void *buffer, int len);
int		push_req_data(t_conf *conf, struct s_simple_list *client, struct s_list *queue, t_request *req);
int		transceive_query(t_conf *, t_request *, char *, int );
uint16_t	send_query(t_conf *conf, struct s_request *);
int		decode_reply(char *query, int in_len, char *output, int max_len);
int		create_simple_req(t_conf *, t_request *, char *, char *, uint16_t);
uint8_t		query_is_compressed(char *buffer, uint16_t len);

#endif
