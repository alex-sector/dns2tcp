/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: auth.h,v 1.4 2008/08/26 15:49:59 dembour Exp $
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

#ifndef __AUTH_H__
#define __AUTH_H__

int		list_resources(t_conf *conf);
uint16_t	connect_resource(t_conf *conf, uint16_t);
uint16_t	create_session(t_conf *conf);

#endif

