/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: trace.h,v 1.1 2008/08/04 15:31:08 dembour Exp $
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

#ifndef  __TRACE_H__
#define  __TRACE_H__

void	trace_on(t_conf *conf);
uint8_t	trace_wanted(t_conf *conf, char *domain);
int	trace(t_conf *conf, t_request *req, t_data *data);
uint8_t	trace_available(t_conf *conf);


#endif /*  __TRACE_H__ */
