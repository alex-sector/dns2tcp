/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: config.c,v 1.13.4.2 2009/09/04 16:25:42 dembour Exp $
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <config.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef _WIN32
#include "mywin32.h"
#endif

#include "my_config.h"
#include "debug.h"

#define MAX_LINE_LEN 512

/**
 * @brief extract comma separated parameters
 * @param[out] stop if we are at EOL
 * @retval 0 parameter
 **/

static char *extract_param(char **line, uint8_t *stop)
{
  char	*param;
  
  if ((!*line) || (! **line))
    return (0);
  param = *line;
  *stop = 1;
  if ((*line = strchr(*line, ',')))
    {
      *(*line)++ = 0;
      *stop = 0;
    }
  return (param);
}

/**
 * @brief remove space for this line, skip if we see a comment
 * @param[in] buffer 
 **/

static void	remove_space(char *buffer)
{
  size_t i, j, len;

  len = strlen(buffer);
  if (!len || !buffer[0] || (buffer[0] == '#'))
    return;
  for (i=0,j=0; i<len; ++i)
    {
      if (buffer[i] > 0x20)
	{
 	  if (i != j)
	    buffer[j] = buffer[i];
	  ++j;
        }
    }
  buffer[j] = 0;
}


int get_next_line(char *buffer, int len, FILE *file)
{
  while (fgets(buffer, len, file))
    {
      remove_space(buffer);
      if (*buffer != '#')
	return (0);
    }
  return (-1);
}

/**
 * @brief extract parameter=value from a line
 * @param[in] file file to read
 * @param[in] conf configuration
 * @param[in] copy_func pointer to the copy function
 **/

static void	config_extract_token(FILE *file, void *conf, 
				     int (*copy_func)(void *, char *, char *))
{
  char		buffer[MAX_LINE_LEN + 1];
  char		token[MAX_LINE_LEN + 1];
  char		*value;
  char		*ptr;
  uint8_t	stop;

  token[0] = 0;
  stop = 1;
  while (get_next_line(buffer, MAX_LINE_LEN, file) != -1)
    {
      value = buffer;
      if ((ptr = strchr(buffer, '=')))
	{
	  *ptr = 0;
	  value = ptr + 1;
	  strncpy(token, buffer, MAX_LINE_LEN);
	}
      ptr = value;
      while (((value = extract_param(&ptr, &stop))) && (*value))
	copy_func(conf, token, value);
      if (stop)
	token[0] = 0;
    }
}

/**
 * @brief read config file
 * @param[in] file file to read
 * @param[in] conf configuration
 * @param[in] copy_func pointer to the copy function
 * @param[in] extension default file name
 **/

int	read_config(char *file, void *conf,
		    int (*copy_func)(void *, char *, char *), 
		    char *extension)
{
  FILE	*my_file;
  char	*home;

  if (!*file)
    {
      if ((!(home = getenv("HOME"))) 
	  || ((strlen(home) > (CONFIG_FILE_LEN - sizeof("/.dns2tcprc") - 10))))
	return (-1);
      snprintf(file, CONFIG_FILE_LEN-1, "%s/%s", home, extension);
    }
  if (!(my_file = fopen(file, "r")))
    {
      DPRINTF(1, "Warn cannot openning config file \'%s\'\n", file);
      return (-1);
    }
  config_extract_token(my_file, conf, copy_func);
  return (fclose(my_file));
}
