/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: session.h,v 1.3 2008/08/26 15:50:00 dembour Exp $
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

#ifndef  __SESSION_H__
#define  __SESSION_H__

int		session_request(t_conf *, t_request *, t_data *);
t_simple_list	*create_session(t_conf *, t_request *, t_packet *);
     
#endif
