/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: my_config.h,v 1.1.6.1 2009/09/01 12:16:25 dembour Exp $
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

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "config.h"

#ifndef _WIN32
#include <netdb.h>
#else
#include "mywin32.h"
#endif

#define CONFIG_FILE_LEN	256

int	read_config(char *, void *, int (*f)(void *, char *, char *), char *);
int	get_next_line(char *, int , FILE *);

#endif /* __CONFIG_H__ */
