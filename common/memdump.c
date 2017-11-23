/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: memdump.c,v 1.4 2008/08/04 15:31:07 dembour Exp $
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

#include <stdio.h>
#include <string.h>

#define LINE_LEN 16	
#define GET_CHAR(c) (((c > 0x1f) && (c < 0x7e)) ? (c) : '.')


int	memdump2(char *memory, int len, int idx)
{
  char	buffer[4*LINE_LEN+2];

  memset(buffer, ' ', 4*LINE_LEN);
  buffer[4*LINE_LEN] = 0;
  buffer[(4*LINE_LEN)+1] = 0;
  if (!(idx % LINE_LEN) && (idx < len))
    fprintf(stderr, "0x%x\t", idx);
  do {
    sprintf(&buffer[3*(idx%LINE_LEN)], "%.2X ", (*(memory+idx)) & 0xff );
    buffer[(3*LINE_LEN) + (idx%LINE_LEN) +1] = GET_CHAR(*(memory+idx));
  }  while ((++idx % LINE_LEN) && (idx < len));
  buffer[3*((idx-1)%LINE_LEN)+3] = ' ';
  fprintf(stderr, "%s\n", buffer);
  return ((idx < len)? memdump2(memory, len, idx): 1);
}

void	memdump(void *memory, int len)
{
  fprintf(stderr, "\n");
  memdump2((char *)memory, len, 0);
  fprintf(stderr, "\n");
}
