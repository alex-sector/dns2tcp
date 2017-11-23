/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: control.h,v 1.5.4.3 2010/01/20 16:14:26 collignon Exp $
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

#ifndef __CONTROL_H__
#define __CONTROL_H__

#include "mycrypto.h"

/* client related struct : info & parameters */
typedef	struct		s_control {

  uint8_t		req;		/* first req acceptable */
  uint8_t		queue_full;	
  uint8_t		use_compress;
  uint16_t		mtu_size;	/* max encoded data */
  uint16_t		nb_reply;	/* how many reply can we send */
  struct timeval	tv;		/* client timeout */
  uint8_t		authenticated;
  char			challenge[CHALLENGE_SIZE+1];
}			t_control;

/* packet related */
typedef	struct		s_control_peer {
  struct sockaddr_in	sa;
  char			data[MAX_HOST_NAME_ENCODED];
  int			len;
  uint16_t		seq;
  const struct s_rr_functions	*reply_functions;
}			t_control_peer;

#endif
