/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: queue.c,v 1.31.4.8 2010/06/02 13:54:29 collignon Exp $
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

/**
 * @file client/queue.c
 * @brief messages queue management
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "dns.h"
#include "list.h"
#include "client.h"
#include "myerror.h"
#include "requests.h"
#include "myrand.h"
#include "debug.h"
#include "rr.h"
#include "crc16.h"
#include "socket.h"

#ifdef _WIN32
static int gettimeofday(struct timeval *tv, void *bla)
{
  tv->tv_sec  = (long) time(NULL);
  tv->tv_usec = 0;
  return 0;
}
#endif

/**
 * @brief initialize client messages queue
 */
t_list          *init_queue(void)
{
  int           nb;
  t_list        *queue;

  if (!(queue = calloc(QUEUE_SIZE, sizeof(t_list))))
    return (0);
  for (nb=0; nb < QUEUE_SIZE-1; nb++)
    queue[nb].next = &queue[nb+1];
  queue[QUEUE_SIZE-1].next = NULL;

  return (queue);
}

/**
 * @brief delete client messages queue
 * @param[in] queue client queue
 * @retval 0 on success
 * @retval -1 on error
 */

int             delete_queue(t_list *queue)
{
  if (!queue)
    return (-1);
  free(queue);
  return (0);
}


/**
 * @brief send an specific DNS request from the queue
 * @param[in] conf configuration
 * @param[in] client list item
 * @param[in] queue  item to send
 * @retval 0 on success
 * @retval -1 on error
 * @note update the timeout timer
 **/

int			queue_send(t_conf *conf, t_simple_list *client, t_list *queue)
{
  int			out_len;
  struct timeval	tv;
  
#if 0
  if (conf->query_size)
    queue->len = add_edns(conf, queue->data, queue->len);
#endif
  if ((out_len = sendto(conf->sd_udp, queue->data, queue->len,
			0, (struct sockaddr *)&(conf->sa), 
			sizeof(struct sockaddr))) == -1)
     {
       queue->status = FREE;
       MYERROR("send error\n");
       return (-1);
     }
  if (gettimeofday(&tv, NULL))
    {
      MYERROR("Timer error");
      return (-1);
    }
  queue->timeout.tv_sec = tv.tv_sec + REPLY_TIMEOUT;
  queue->timeout.tv_usec = tv.tv_usec;
  return (0);
}



/**
 * @brief resend an specific DNS request from the queue
 * @param[in] conf configuration
 * @param[in] client list item
 * @param[in] queue  item to send
 * @retval 0 on success
 * @retval -1 on error
 * @note update the request ID but keep the previous one for delayed reply
 **/

int			queue_resend(t_conf *conf, t_simple_list *client, t_list *queue)
{
  struct dns_hdr	*hdr;

  hdr = (struct dns_hdr *)queue->data;
  hdr->id = myrand();
  queue->peer.old_id =  queue->peer.id;
  queue->peer.id = hdr->id;
  
  DPRINTF(2, "Queue resend seq %d id = 0x%x \n", queue->info.num_seq, ntohs(queue->peer.id));
  queue_send(conf, client, queue);
  return (0);
}


/**
 * @brief check for unanswered queries, resend them
 * @param[in] conf configuration
 * @retval 0 on success
 * @retval -1 on error
 **/
int			check_for_resent(t_conf *conf)
{
  t_simple_list		*client;
  struct timeval	tv;
  t_list		*queue;
#ifdef _WIN32
  int			need_event = 0;
#endif
  if (gettimeofday(&tv, NULL))
    {
      MYERROR("Timer error");
      return (-1);
    }
  
  for (client = conf->client; client; client = client->next)
    for (queue = client->queue; queue; queue = queue->next)
      {
	if ((queue->status == SENT) && (queue->timeout.tv_sec < tv.tv_sec)) 
	  {
#ifdef _WIN32
	    need_event = 1;
#endif
	    queue_resend(conf, client, queue);
	  }
      }
#ifdef _WIN32
  if (need_event)
    SetEvent(conf->event_udp);
#endif
  return (0);
}

/**
 * @brief dump the queue
 * @param[in] client list item
 * @retval 0 on success
 * @retval -1 on error
 * @note for debug only
 **/

void		queue_dump(t_simple_list *client)
{
  t_list        *queue;
  
  if (debug > 1)
    {
      printf("Client 0x%x :\n", client->session_id);
      printf ("queue dump :");
      printf ("n.pen :%d d.pend %d  {seq:seq_ack:status}\n", 
	      client->control.nop_pending,
	      client->control.data_pending
	      );
      for (queue = client->queue; queue; queue = queue->next)
	{
	  printf("{seq=%d:ack=%d:stat=%s} ", 
		 queue->info.num_seq,
		 queue->peer.ack_seq ,
		 (queue->status == FREE) ? "F" : "U");
	}
      printf("\n");
    }
}

/**
 * @brief rotate the circular buffer
 * @param[in] client list item
 * @param[in] new_root where to rotate
 * @retval 0 on success
 * @retval -1 on error
 **/

int             queue_change_root(t_simple_list *client, t_list *new_root)
{
  t_list        *end;
  t_list	*prev;

  prev = client->queue;
  if (new_root->next)
    {
      for (end = client->queue ; end != new_root; end = end->next)
	{
	  end->peer.ack_seq = 0;	  
	  end->status = FREE;
	  prev = end;
	}
      prev->next = 0;
      for (end = new_root->next; end->next; end = end->next)
        ;
      end->next = client->queue;
      client->queue = new_root;
    }
  else
    for (end = client->queue; end->next ; end = end->next)
      {
	end->status = FREE;
	end->peer.ack_seq = 0;	  
      }
  return (0);
}

int		write_to_client(t_conf *conf, t_simple_list *client, const char *buffer, int total_len)
{
  ssize_t	ret;
#ifdef _WIN32
  DWORD		w;
#endif
  
#ifndef _WIN32
  ret = write(client->fd_wo, &buffer[PACKET_LEN], total_len - PACKET_LEN);
  if (ret != total_len - PACKET_LEN) 
    {
      MYERROR("Fail to send data )\n");
      delete_client(conf, client);
      return (-1);
    }
#else
  if (client->pid == (process_t)-1) 
    {
      ret = write(client->fd_wo, &buffer[PACKET_LEN], total_len - PACKET_LEN);
      if (ret != total_len - PACKET_LEN) 
	{
	  MYERROR("Fail to send data (err=%lu, handle=%x)\n", GetLastError(), client->fd_wo);
	  delete_client(conf, client);
	  return (-1);
	}
    } 
  else 
    {
      w = 0;
      if (!WriteFile((HANDLE)client->fd_wo, &buffer[PACKET_LEN], total_len - PACKET_LEN, &w, NULL)) 
	{
	  DPRINTF(1, "Fail to send data (err=%lu, handle=%x, w=%lu)\n", GetLastError(), client->fd_wo, w);
	  return (-1);
	}
    }
#endif
  return (0);

}
/**
 * @brief extract data from a DNS reply and write it to the correct socket
 * @param[in] conf configuration
 * @param[in] client list item
 * @param[in] queue element to decode
 * @retval 0 on success
 * @retval -1 on error
 **/

int			extract_data(t_conf *conf, t_simple_list *client, t_list *queue)
{
  char			buffer[MAX_DNS_LEN + 1 - DNS_HDR_SIZE - RR_HDR_SIZE];
  t_packet		*packet;
  int			len;
  uint16_t              seq_tmp;
  t_request		req;
  int			count = 0, total_len = 0;

  /*
    TODO put t_request in queue ?
  */
  memcpy(req.req_data, queue->data, queue->len);
  req.len = queue->len;
  req.req_data[req.len]=0;
  req.request_functions = conf->query_functions;
  
  DPRINTF(3, "decoding seq [%d]\n",queue->info.num_seq);
  while ((len = req.request_functions->rr_decode_next_reply(&req, &buffer[total_len], sizeof(buffer) - total_len, count++)))
    total_len += len;
  if (total_len)
    {
      packet = (t_packet *)buffer;
      seq_tmp = ntohs(packet->seq); packet->seq = seq_tmp;
      queue->info.num_seq = packet->seq;
      if (packet->type == DESAUTH)
	{
	  DPRINTF(1, "Received desauth\n");
	  delete_client(conf, client);
	  return (-1);
	}
      if (queue->peer.type == DATA)
	client->control.data_pending--;
      else
	client->control.nop_pending--;
      if ((packet->type & DATA) != DATA)
	return (0);
      if (total_len < PACKET_LEN)
	{
	  MYERROR("bug ! reply len = %d\n", total_len);
	  memdump(queue->data, queue->len);
	  while(1);
	}
      DPRINTF(2, "Client 0x%x : write [%d] %d on fd %d, crc = 0x%x \n", 
	      client->session_id, packet->seq, total_len - (int)PACKET_LEN, client->fd_wo,
	      crc16( (const char *)&buffer[PACKET_LEN], total_len - PACKET_LEN)
	      );
      return (write_to_client(conf, client, (const char *) buffer, total_len));
    }
  return (0);
}

/**
 * @brief find next space in the circular buffer
 * @param[in] client list item
 * @retval element found
 * @retval -1 on error
 **/

t_list		*queue_find_empty_data_cell(t_simple_list *client)
{
  t_list	*queue;

  queue = client->queue;
  DPRINTF(2, "queue = 0x%p\n", queue);
  while ((queue) && (queue->status != FREE))
    queue = queue->next;
  if (!queue)
    {
      MYERROR("QUEUE ERROR should not happen");
      while (1);
      return (0);
    }
  return (queue);
}

/**
 * @brief put ACK flag in a free future request
 * @param[in] queue 
 * @param[in] seq seq number to acknoledge
 * @retval seq number on success
 * @retval -1 on error
 **/

int		queue_prepare_ack(t_list *queue, uint16_t seq)
{
  while (queue)
    {
      if (!(queue->peer.ack_seq))
	return ((queue->peer.ack_seq = seq));
      queue = queue->next;
    } 
  return (0);
}


/**
 * @brief flush incoming reply
 * @param[in] conf configuration
 * @param[in] client list item
 * @retval 0 on success
 * @retval -1 on error
 * @note rotate the circular buffer when done
 **/

int		queue_flush(t_conf *conf, t_simple_list *client)
{
  t_list	*queue;
  t_list	*free_cell;

  queue = client->queue;
  if (!(free_cell = queue_find_empty_data_cell(client)))
    return (-1);
  while ((queue) && (queue->status == RECEIVED))
    {
      if (!free_cell)
	{
	  MYERROR("Queue design is too small\n");
	  queue_dump(client);
	  while (1);
	  return (-1);
	}
      queue_prepare_ack(free_cell,queue->info.num_seq);
      if (extract_data(conf, client, queue) == -1)
	return (-1);
      queue = queue->next;
      free_cell = free_cell->next;
    }
  /* FIXME queue can be null ? */
  if ((!queue) || (queue == client->queue))
    return (-1);
  return (queue_change_root(client, queue));
}

/**
 * @brief put NOP in future requests
 * @param[in] conf configuration
 * @param[in] client list item
 * @retval 0 on success
 * @retval -1 on error
 **/

int			queue_put_nop(t_conf *conf, t_simple_list *client)
{
  t_list		*queue;
  int			len;
  struct dns_hdr	*hdr;
  t_request		req;

  req.len = 0;
  while (client->control.nop_pending < NOP_SIZE)
    {
      if ((queue = queue_find_empty_data_cell(client)))
	{
	  /* num seq must not be null */
	  if (!++client->num_seq)
	    client->num_seq++;
	  len = push_req_data(conf, client, queue, &req);
	  if (queue_send(conf, client, queue) == -1)
	    {
	      client->num_seq--;
	      return (-1);
	    }
	  client->control.nop_pending++;
	  queue->peer.type = NOP;
	  queue->status = SENT;
	  hdr = (struct dns_hdr *)queue->data;
	  queue->peer.id = hdr->id;
	  queue->peer.old_id = 0;
	  return (0);
	}
    }
  return (-1);
}

/* TODO check packet validity */

/**
 * @brief deal a DNS answer
 * @param[in] conf configuration
 * @param[in] buffer DNS request
 * @param[in] len size of the request
 * @retval 0 on success
 * @retval -1 on error
 **/

int			queue_get_udp_data(t_conf *conf, char *buffer, int len)
{
  struct dns_hdr	*hdr;
  t_list		*queue;
  t_simple_list		*client;
  
  client = conf->client;
  hdr = (struct dns_hdr *) buffer;
  
  for (; client; client = client->next)
    {
      for (queue = client->queue; queue; queue = queue->next)
	{
	  if ( (queue->status == SENT) && ( (queue->peer.id == hdr->id) 
					    || (queue->peer.old_id && (queue->peer.old_id == hdr->id))))
	    {
	      if (hdr->rcode)
		{
		  if ((hdr->rcode == RCODE_NAME_ERR) || (hdr->rcode == RCODE_SRV_FAILURE))
		    {
		      /* Reply already sent and acked by server
			 Bug ?
		      */
		      if (client->control.cumul_errors++ > MAX_CLIENT_ERROR)
			{
			  DPRINTF(1, "Too many packets lost. Reseting connection ...\n");
			  return (delete_client(conf, client));
			}
		    }
		  DPRINTF(2, "Connection reject code %d id = 0x%x (%s) trying to continue\n", hdr->rcode, ntohs(hdr->id),
			  (hdr->rcode == RCODE_REFUSED) ? "Connection Lost" :  /* state not found */
			  (hdr->rcode == RCODE_SRV_FAILURE) ? "Server failure" :  /* state not found */
			  (hdr->rcode == RCODE_NAME_ERR) ? "Query not found or already done" : "" /* already replied */
			  );
		  return (0);
		}
	      DPRINTF(2, "Received [%d]%s id=0x%x\n", queue->info.num_seq, (queue->peer.id == hdr->id) ? "" :" old",
		      ntohs(hdr->id));
	      client->control.cumul_errors = 0;
	      memcpy(queue->data, buffer, len);
	      queue->status = RECEIVED;
	      queue->data[len] = 0;
	      queue->len = len;
	      if (queue_flush(conf, client) && conf->local_port)
		/* check TCP socket only if we have bind a port */
		return (!socket_is_valid(conf->sd_tcp));
	      return (0);
	    }
	}
    }
  DPRINTF(2, "received reply for unknow request 0x%x \n",  ntohs(hdr->id));
  return (0);
}

#ifdef _WIN32
static int	windows_read_pipe(t_conf *conf, t_simple_list *client, t_list *queue, t_request *req, size_t max_len)
{
  DWORD		len;

  len = 0;
  if (client->control.io_pending) 
    {
      if (!GetOverlappedResult((HANDLE)client->fd_ro, &client->control.aio, &len, FALSE)) 
	{
	  DPRINTF(1, "failed to complete async read (%lu)\n", GetLastError());
	  req->len = -1;
	  push_req_data(conf, client, queue, req);
	  queue_send(conf, client, queue);
	  return -1;
	}
      // previous read has completed
      client->control.io_pending = 0;
      SetEvent(client->control.aio.hEvent);
    } 
  else 
    {
      ZeroMemory(req, sizeof(t_request));
      if (!ReadFile((HANDLE)client->fd_ro, &req->req_data[PACKET_LEN],
		    max_len, &len, &client->control.aio)) 
	{
	  if (GetLastError() == ERROR_IO_PENDING) {
	    // read would block
	    client->control.io_pending = 1;
	    return 0;
	  }
	  DPRINTF(1, "failed to read pipe data (%lu)\n", GetLastError());
	  //	  req->len = -1;
	  //	  push_req_data(conf, client, queue, req);
	  // queue_send(conf, client, queue);
	  return -1;
	}
      // read has completed right now
      client->control.io_pending = 0;
      SetEvent(client->control.aio.hEvent);
    }
  if (!len) 
    {
      DPRINTF(1, "THIS IS A FUCKING BUG!\n");
      exit (0);
    }
  return (len);
}
#endif

#ifdef _WIN32
static int	windows_client_read(t_conf *conf, t_simple_list *client, t_list *queue, t_request *req, size_t max_len)
{
  int		len;

  if (client->pid != (process_t)-1)
    return (windows_read_pipe(conf, client, queue, req, max_len));

  if ((len = read(client->fd_ro, &req->req_data[PACKET_LEN], max_len)) <= 0)
    {
      if (GetLastError() == WSAEWOULDBLOCK) 
	{
	  ResetEvent(client->control.event);
	  return (0);
	}
      return (-1);
    }
  return (len);
}
#endif

/**
 * @brief convert incoming TCP data to a DNS request
 * @param[in] conf configuration
 * @param[in] client list item
 * @retval 0 on success
 * @retval -1 on error
 **/


int			queue_get_tcp_data(t_conf *conf, t_simple_list *client)
{
  t_list		*queue;
  int			len;
  size_t		max_len;
  struct dns_hdr	*hdr;
#ifndef _WIN32
  t_request		req;
#else
  static t_request	req;
#endif
  
  
  /* 3 octets reserved for alter packet */
  max_len = MAX_QNAME_DATA(conf->domain) - PACKET_LEN - 3;
  /* Should exit if  !queue */
  if ((queue = queue_find_empty_data_cell(client)))
    {
      if ((client->control.data_pending >= MAX_DATA_SIZE)
	  || (client->control.data_pending + client->control.nop_pending >= WINDOW_SIZE))
	{
	  DPRINTF(1, "Warning Window size full waiting to flush ...\n");
	  return (0);
	}
#ifdef _WIN32
      
      if ((req.len = windows_client_read(conf, client, queue, &req, max_len)) == 0)
	return (0);
#else
      req.len = read(client->fd_ro, &req.req_data[PACKET_LEN], max_len);
#endif
      if (req.len <= 0)
	{
	  req.len = -1;
	  push_req_data(conf, client, queue, &req);
	  queue_send(conf, client, queue);
	  return (-1); 
	}
      /* num_seq must not be null */
      if (!++client->num_seq)
	client->num_seq++;
      
      DPRINTF(3, "Read tcp %d bytes on sd %d, crc = 0x%x\n", req.len, client->fd_ro,
	      crc16((const char *)&req.req_data[PACKET_LEN], req.len)
	      );
      len = push_req_data(conf, client, queue, &req);
      if (queue_send(conf, client, queue) == -1)
	return (-1);
      client->control.data_pending++;
      queue->peer.type = DATA;
      hdr = (struct dns_hdr *) queue->data;
      queue->peer.id = hdr->id;
      queue->peer.old_id = 0;
      queue->status = SENT;
    }
  return (0);
}
