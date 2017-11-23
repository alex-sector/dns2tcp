/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: queue.h,v 1.3 2008/08/26 15:49:59 dembour Exp $
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

t_list	*init_queue();
int	delete_queue(t_list *queue);
int	queue_get_udp_data(t_conf *conf, char *buffer, int len);
int	queue_get_tcp_data(t_conf *conf, struct s_simple_list *client);
int	check_for_resent(t_conf *conf);
int	queue_put_nop(t_conf *conf, struct s_simple_list *client);
void	queue_dump(struct s_simple_list *client);

#endif
