/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: mycrypto.h,v 1.2.4.1 2010/06/16 08:40:10 dembour Exp $
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


#ifndef __MYCRYPTO_H__
#define __MYCRYPTO_H__

#define CHALLENGE_SIZE	16
#define SHA1_SIZE	20

void	alphanum_random(char *buffer, int len);
int	sign_challenge(char *, int, char *, char *, int);

#endif
