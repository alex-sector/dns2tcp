/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: list.c,v 1.3 2009/04/30 14:04:59 dembour Exp $
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

#include <stdlib.h>       
#include <string.h>

#include "dns.h"
#include "list.h"
#include "myerror.h"

/**
 * @brief create an empty list
 * @retval list
 * @retval 0 on error
 * @retval list on success
 **/

t_simple_list	*list_create_simple_cell()
{
  t_simple_list	*list;

  if (!(list = malloc(sizeof(t_simple_list))))
    return (0);
  memset(list, 0, sizeof(t_simple_list));
  return (list);
}

/**
 * @brief create a cell 
 * @retval cell
 * @retval 0 on error
 * @retval list on success
 **/


t_list		*list_create_cell()
{
  t_list	*list;
  
  if (!(list = malloc(sizeof(t_list))))
    return (0);
  list->next = 0;
  list->status = FREE;
  return (list);
}

/**
 * @brief add the simple cell to the list
 * @param[in] list simple list
 * @param[in] cell
 * @retval 0 on error
 * @retval 1 on success
 **/

int		list_add_simple_cell(t_simple_list *list, t_simple_list *cell)
{
  t_simple_list	*ptr;

  if (!list)
    return (-1);
  ptr = list;
  while (ptr->next)
    ptr = ptr->next;
  ptr->next = cell;
  return (1);
}

/**
 * @brief add the cell to the simple list struct
 * @param[in] list list
 * @param[in] cell
 * @retval 0 on error
 * @retval 1 on success
 **/

int		list_add_cell(t_list *list, t_list *cell)
{
  t_list	*ptr;

  if (!list)
    return (-1);
  ptr = list;
  while (ptr->next)
    ptr = ptr->next;
  ptr->next = cell;
  return (1);
}

/**
 * @brief free cell in list
 * @param[in] cell 
 **/

int		list_destroy_cell(t_list *cell)
{
  if (!cell)
    return (-1);
  free(cell);
  cell=0;
  return (0);
}

/**
 * @brief free simple cell in list
 * @param[in] cell 
 **/

int		list_destroy_simple_cell(t_simple_list *cell)
{
  if (!cell)
    return (-1);
  free(cell);
  cell=0;
  return (0);
}
