/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: queue.h,v 1.4 2009/01/09 16:40:14 dembour Exp $
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

#ifndef __QUEUE_H__
#define __QUEUE_H__

int		queue_put_data(t_conf *conf, t_request *req, t_data *data);
t_list		*init_queue();
int		queue_read_tcp(t_conf *conf, t_simple_list *client);
int		queue_delete_zombie(t_conf * conf);
void		client_update_timer(struct s_simple_list *client);
int		delete_queue(struct s_list *queue);
t_simple_list   *find_client_by_session_id(t_conf *conf, uint16_t session_id);
void            queue_dump(t_simple_list *client);
int		queue_flush_expired_data(t_conf *conf);

#endif
