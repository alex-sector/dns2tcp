/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: debug.h,v 1.5.6.2 2009/09/07 17:11:57 dembour Exp $
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

#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>
#include <time.h>

int debug;

#ifndef _WIN32
#define DPRINTF(level, fmt, args...)  \
{\
	if (debug >= level) \
	{\
	   if (level == 1) \
	     {\
	        time_t t; \
	        struct tm *tmp; \
	        char my_time[64]; \
		\
		t = time(NULL); \
                tmp = localtime(&t); \
	        strftime(my_time, sizeof(my_time), "%R:%S", tmp); \
		fprintf(stderr, "%s : ", my_time); \
		}\
	   fprintf(stderr, "Debug %s:%d\t", __FILE__, __LINE__); \
           fprintf(stderr, fmt, ##args); \
	}\
}
#else
#define DPRINTF(level, fmt, args...)  \
{\
  if (debug >= level)				\
    {								 \
      fprintf(stderr, "Debug %s:%d\t", __FILE__, __LINE__);		\
      fprintf(stderr, fmt, ##args);					\
    }									\
}
#endif

#endif /* __DEBUG_H__ */
