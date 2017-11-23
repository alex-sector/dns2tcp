/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: myerror.h,v 1.2.6.1 2009/09/07 17:11:57 dembour Exp $
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

#ifndef __MY_ERROR_H__
#define __MY_ERROR_H__

#include <stdio.h>

#define MYERROR(fmt, args...) \
{ \
        fprintf(stderr, "Error %s:%d ", __FILE__, __LINE__); \
	fprintf(stderr, fmt, ##args); \
	fprintf(stderr, "\n"); \
 }

#endif
