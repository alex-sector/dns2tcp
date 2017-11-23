/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: log.h,v 1.1 2007/01/16 13:09:16 dembour Exp $
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

#ifndef __LOG_H__
#define __LOG_H__

#define LOG_LEVEL (LOG_DAEMON | LOG_INFO)

#include <syslog.h>

#define LOG(fmt, args...) \
do { \
        if (conf->foreground) \
	{ \
            fprintf(stderr, fmt, ##args); \
            fprintf(stderr, "\n"); \
	 } \
         syslog(LOG_LEVEL, fmt, ##args); \
 } while (0);


#endif /* __LOG_H__ */
