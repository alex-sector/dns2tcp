/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: select.h,v 1.1.2.1 2009/12/09 15:50:09 dembour Exp $
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

#ifndef __SELECT_H__
#define __SELECT_H__

int	prepare_select(t_conf *, void *, struct timeval *);

#ifdef _WIN32
int	add_event(WSAEVENT event, HANDLE *rfds, int max_fd);
#else
int	add_socket(socket_t socket, fd_set *rfds, socket_t max_fd);
#endif

#endif
