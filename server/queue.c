/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: queue.c,v 1.29.4.5 2010/01/19 17:18:00 collignon Exp $
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

#include <sys/time.h>     
#include <sys/socket.h>
#include <time.h>
#include <strings.h>
#include <stdlib.h>
#include <string.h>

#include "mycrypto.h"
#include "base64.h"
#include "server.h"
#include "dns.h"
#include "dns_decode.h"
#include "packet.h"
#include "myerror.h"
#include "requests.h"
#include "rr.h"
#include "control.h"
#include "list.h"
#include "debug.h"
#include "packet.h"
#include "crc16.h"




void		queue_dump(t_simple_list *client);


/**
 * @brief initialize client messages queue
 */
t_list		*init_queue(void)
{
  int		nb;
  t_list	*queue;

  if (!(queue = calloc(QUEUE_SIZE, sizeof(t_list))))
    return (0);
  for (nb=0; nb < QUEUE_SIZE-1; nb++)
    queue[nb].next = &queue[nb+1];
  queue[QUEUE_SIZE-1].next = NULL;

  return (queue);
}

/**
 * @brief delete client messages queue
 */
int		delete_queue(t_list *queue)
{
  if (!queue)
    return (-1);
  free(queue);
  return (0);
}


/**
 * @brief update the client's queue timer
 */
void			queue_update_timer(t_list *queue)
{
  struct timeval	tv;
  struct timezone	tz;
   
  if (!(gettimeofday(&tv, &tz)))
    {    
      queue->timeout.tv_sec = tv.tv_sec + REQUEST_TIMEOUT;;
      queue->timeout.tv_usec = tv.tv_usec + REQUEST_UTIMEOUT;
    }
}


/**
 * @brief acknoledge a reply
 * @param[in] queue client's queue
 * @param[in] seq sequence number
 * @retval 0 on success
 * @retval -1 on error
 **/


static int	queue_mark_received(t_list *queue, uint16_t seq)
{
  if (seq)
    {
      while ((queue) && (queue->info.num_seq != seq))
	queue = queue->next;
      if (!queue)
	return (0);
      queue->status = (queue->status == FREE) ? FREE : RECEIVED;
    }
  return (0);
}

/**
 * @brief extract data from a request in queue
 * @param[in] client clients structure
 * @param[in] queue client client structure
 * @param[in] packet client client structure
 * @param[in] len packet's request len
 * @retval 0 on success
 * @retval -1 on error
 **/

static int		queue_copy_data(t_simple_list *client, t_list *queue, t_packet *packet, int len)
{
  void			*data;

  data = (void *)packet + PACKET_LEN;
  if ((packet->type & DATA) == DATA) 
    {
      memcpy(queue->peer.data, data, len - PACKET_LEN);
      queue->peer.len = len - PACKET_LEN;
    }
  if (packet->type == NOP)
    queue->peer.len = 0;
  if (packet->type == DESAUTH)
    return (-1);
  queue->status = USED;
  queue->peer.seq = packet->seq;
  client->control.queue_full = 0;
  /* WTF could be another queue ? */
  if (queue == client->queue)
    client->num_seq = packet->seq;
  /* Update request timer */
  queue_update_timer(queue);
  return (0);
}


/**
 * @brief send a specifi request from the queue
 * @param[in] conf configuration
 * @param[in] queue request in queue to send
 **/

static int		queue_send_data(t_conf *conf, t_list *queue)
{
  if ((sendto(conf->sd_udp, queue->data, queue->len, 0, 
	      (struct sockaddr *)&(queue->peer.sa), sizeof(struct sockaddr))) != queue->len)
    {
      MYERROR("send error len %d ", queue->len);
      perror("");
      return (-1);
    }
  queue->status = SENT;
  return (0);
}


/**
 * @brief reply for a specifi request
 * @param[in] conf configuration
 * @param[in] client client's queue
 * @param[in] queue element in queue to send
 * @param[in] data data to send
 * @param[in] data_len data len
 **/

static void		queue_reply(t_conf *conf, t_simple_list *client, 
				    t_list *queue, void *data, int data_len)
{
  struct dns_hdr	*hdr;
  t_packet		*packet;
  char			buffer[MAX_EDNS_LEN - DNS_HDR_SIZE - REQ_HDR_SIZE ];
  t_data		output_data;
  t_request		req;

  hdr = (struct dns_hdr *) queue->data;
  req.data = queue->data;
  req.len = queue->len;
  req.reply_functions = queue->peer.reply_functions;
  // FIXME bug ipv6 support
  memcpy(&req.sa, &(queue->peer.sa), sizeof(struct sockaddr_in));

  output_data.buffer = buffer;
  packet = (t_packet *)buffer;
  packet->session_id = client->session_id;
  packet->type = ACK ;
  PUT_16(&packet->seq, queue->peer.seq);
  packet->ack_seq = 0;
  output_data.len = sizeof(t_packet);
  if (data_len > 0)
    {
      packet->type |= DATA;
      memcpy((char *)(output_data.buffer)+PACKET_LEN, data, data_len);
      output_data.len += data_len;
    }
  if (data_len == -1)
    packet->type = DESAUTH ;
  if (!send_reply(conf, &req, &output_data))
    {
      /* update queue len */
      queue->len = req.len;
      queue->status = SENT; 
      queue_update_timer(queue);
    }
}

/**
 * @brief flush incoming request
 * @param[in] client list item
 * @retval 0 on success
 * @retval -1 on error
 **/

static int		queue_flush_incoming_data(t_simple_list *client)
{
  t_list		*queue;

  queue = client->queue;
  while ((queue) && (queue->status != FREE))
    {
      if (queue->peer.len)
	{
	  if (write(client->sd_tcp, queue->peer.data, queue->peer.len) != queue->peer.len)
	    return (-1);
	  DPRINTF(2, "Flush Write %d bytes, crc = 0x%x \n", queue->peer.len, 
		  crc16((const char*) queue->peer.data, queue->peer.len));
	  queue->peer.len = 0;
	}
      queue = queue->next;
    }
  return (0);
}

/**
 * @brief rotate the circular buffer
 * @param[in] client list item
 * @retval 0 
 **/


static int	queue_change_root(t_simple_list *client)
{
	t_list	*end;
	t_list	*new_root;
	t_list	*prev;


	if (client->queue->status != RECEIVED)
		return (0);
	prev = client->queue;
	for (end = client->queue; end ; end = end->next)
	{
		if (end->status != RECEIVED)
			break;
		end->status = FREE;
		end->info.num_seq = 0;
		client->control.req++;
		/* num_seq must not be null */
		if (!++client->num_seq)
			client->num_seq++;
		prev = end;
	}
	if (!end)
		return (0);
	new_root = end;
	prev->next = 0;
	for (end = new_root; end->next; end = end->next)
		;
	end->next = client->queue;
	client->queue = new_root;
	return (0);
}

/**
 * @brief flush outgoing reply
 * @param[in] conf configuration
 * @param[in] client list item
 * @param[in] index numbers of items to flush
 * @retval 0
 **/

int		queue_flush_outgoing_data(t_conf *conf,t_simple_list *client, int index)
{
	t_list	*queue;

	DPRINTF(2, "Flushing outgoing data\n");
	for (queue = client->queue; index-- ; queue = queue->next)
	{
		if (queue->status != USED)
			return (0);
		queue_reply(conf, client, queue, 0, 0);
		queue->status = SENT;
		client->control.req--;  
	}
	return (0);
}


/**
 * @brief flush all expired outgoing replies 
 * @param[in] conf configuration
 **/

int			queue_flush_expired_data(t_conf *conf)
{
	t_list		*queue;
	t_simple_list		*client;
	struct timeval	tv;
	struct timezone	tz;
	struct dns_hdr	*hdr;

	//DPRINTF(3, "Flushing expired request\n");
	if (gettimeofday(&tv, &tz))
		return (-1);
	for (client = conf->client; client; client = client->next)
	{
		for (queue = client->queue; queue ; queue = queue->next)
		{
			if  ((tv.tv_sec >  queue->timeout.tv_sec)  ||
					(((tv.tv_sec ==  queue->timeout.tv_sec) 
					  && (tv.tv_usec >  queue->timeout.tv_usec))))
			{
				/* If req received but no answer sent */
				if  (queue->status == USED )
				{
					hdr = (void *) queue->data;
					DPRINTF(3, "%s, flush expired req id 0x%x\n", __FUNCTION__, ntohs(hdr->id));
					queue_reply(conf, client, queue, 0, 0);
					client->control.req--;
				}
			}
		}
	}
	return (0);
}

/*
  Should copy packet, mark original query cell as 'RECEIVED'
  
  if cell is USED (query received but no data to send now)
  else WTF !

  if CELL is FREE (new data) 
	-> copy data
	-> try to flush incoming data
	-> try to change root

  if diff(first in queue, received) > SIZE -> try to flush SIZE/2 packet

*/

/**
 * @brief 'TCP' engine
 * @param[in] conf configuration
 * @param[in] client client struct 
 * @param[in] queue client's queue
 * @param[in] packet packet request
 * @param[in] len packet len
 * @note : magic do not touch, it came from a space trip
 **/

static int		queue_deal_incoming_data(t_conf *conf, t_simple_list *client, t_list *queue,
					 t_packet *packet, int len)
{
  int			res = 0;
  int			diff = 0;
  struct dns_hdr	*hdr;
    
  if ((packet->ack_seq) && (queue_mark_received(client->queue, packet->ack_seq)))
    return (-1);
  if (queue)
    {
      hdr = (void *)queue->data;
      switch (queue->status) 
	{
	case USED: 
	  DPRINTF(3, "USED, sending reply for id 0x%x\n", ntohs(hdr->id));
	  queue_reply(conf, client, queue, 0, 0);
	  client->control.req--;
	  break;
	case SENT:
	  res = queue_send_data(conf, queue);
	  DPRINTF(3, "SENT received same req again, sending id 0x%x\n", ntohs(hdr->id));
	  break;
	case RECEIVED:
	  DPRINTF(3, "RECEIVED received same req again, sending id 0x%x\n", ntohs(hdr->id));
	  queue_reply(conf, client, queue, 0, 0);
	  /* FIXME req-- ?? */
	  client->control.req--;
	  res = queue_send_data(conf, queue);
	  break;
	case FREE:
	  DPRINTF(3, "Queue : dealing packet %d\n", packet->seq);
	  res = queue_copy_data(client, queue, packet, len);
	  /* Now mark as USED */
	  if (queue_flush_incoming_data(client) < 0)
	    return (-1);
	  if (client->queue->status == RECEIVED)
	    queue_change_root(client);	      
	  break;
	}
      if (client->num_seq > packet->seq) /*  seq must not be 0 */
	diff = ((MAX_SEQ - client->num_seq) + packet->seq ); 
      else
	diff = packet->seq - client->num_seq ;
      if (diff > FLUSH_TRIGGER)
	queue_flush_outgoing_data(conf, client, diff/2);
      return (res);
    }
  return (-1);
}


/**
 * @brief read TCP data and put it in the next reply
 * @param[in] conf configuration
 * @param[int] client 
 * @retval 0 on success
 * @retval -1 on error
 **/

int			queue_read_tcp(t_conf *conf, t_simple_list *client)
{
  char			buffer[ MAX_EDNS_LEN ];
  t_list		*queue;
  struct dns_hdr	*hdr;
  int			len;
  
  for (queue = client->queue; queue; queue = queue->next)
    {
      if (queue->status == FREE)
	break;
      if (queue->status == USED)
	{
	  hdr = (struct dns_hdr *) queue->data;
	  if ((len = queue->peer.reply_functions->rr_available_len(hdr, client, queue->len)) > 0)
	    {
	      if ((len = read(client->sd_tcp, buffer, len)) < 1)
		{
		  /* nothing to read : connection closed */
		  queue_reply(conf, client, queue, 0, -1);
		  return (-1);
		}
	      DPRINTF(3, "Read tcp %d bytes, crc = 0x%x\n", len, crc16((const char *)buffer, len));
	      
	      queue_reply(conf, client, queue, buffer, len);
	      return (0);
	    }
	  DPRINTF(1, "Query too long for a reply\n");
	}
    }
  client->control.queue_full = 1;
  return (0);
}

/**
 * @brief queue_dump for debug
 **/

void		queue_dump(t_simple_list *client)
{
  t_list	*queue;

  while (client)
    {
      queue = client->queue;
      printf("client 0x%x\n", client->session_id);
      while (queue)
	{
	  printf("{seq=%d:stat=%s} ", queue->info.num_seq, 
		 (queue->status == 0) ? "F" : (queue->status == USED )? "U" :"S" );
	  queue = queue->next;
	}
      printf("\n");
      client = client->next;
    }
}

/**
 * @brief get a specifi offset cell in the queue
 * @param[in] queue client queue
 * @param[in] offset offset
 **/

static t_list	*get_cell_in_queue(t_list *queue, int offset)
{
  while ((queue) && (offset--))
    queue = queue->next;
  return (queue);
}

/* Copy query in queue */
/**
 * @brief put request in the client queue
 * @param[in] request client request
 * @param[in] queue
 * @param[in] seq sequence number
 * @note : if the request was already seen, update the DNS transaction ID
 **/

static int		queue_copy_query(t_request *req, t_list *queue, uint16_t seq)
{
  /* Free -> New request */
  if (queue->status == FREE)
    {
      memcpy(queue->data, req->data, req->len);
		// FIXME bug ipv6 support
      memcpy(&(queue->peer.sa), &req->sa, sizeof(struct sockaddr_in)); 
      queue->len = req->len;	
      queue->info.num_seq = seq;
      queue->peer.reply_functions = req->reply_functions;
      return (0);
    }
  /* 
     Request already received
     Update DNS transaction ID 
     
     Maybe we can compare the two request size ...
  */
  if (!strncmp(&(queue->data[DNS_HDR_SIZE]), 
	       ((char *)req->data) + DNS_HDR_SIZE, 
	       strlen(((char *)req->data) + DNS_HDR_SIZE)))
    {
      memcpy(queue->data, req->data, sizeof(uint16_t)); 
      queue->peer.reply_functions = req->reply_functions;
		// FIXME bug ipv6 support
      memcpy(&(queue->peer.sa), &req->sa, sizeof(struct sockaddr_in)); 
      return (0);
    }
  return (0);
}


/**
 * @brief send an error message
 * @param[in] conf configuration
 * @param[in] request to send
 * @param[in] code DNS error code
 * @retval 0 on success
 * @retval -1 on error
 **/

static int		send_error(t_conf *conf, t_request *req, int code)
{
  struct dns_hdr	*hdr;  
  
  hdr = (struct dns_hdr *) req->data;

  hdr->ra = 1;
  hdr->qr = 1;
  hdr->rcode = code;
  if ((sendto(conf->sd_udp, req->data, req->len, 0, 
	      (struct sockaddr *)&req->sa, sizeof(struct sockaddr))) == -1)
    MYERROR("sendto error");
  return (-1);
}

/**
 * @brief tell that the client is still alive
 * @param[in] client
 **/

void			client_update_timer(t_simple_list *client)
{
  struct timeval	tv;
  struct timezone	tz;
   
  if (!(gettimeofday(&tv, &tz)))
    {    
      client->control.tv.tv_sec = tv.tv_sec + CLIENT_TIMEOUT;
      client->control.tv.tv_usec = tv.tv_usec;
    }
}

/**
 * @brief find a client based on his session id
 * @param[in] conf configuration
 * @param[in] session_id 
 **/

t_simple_list	*find_client_by_session_id(t_conf *conf, uint16_t session_id)
{
  t_simple_list	*client;

  for (client = conf->client; client; client = client->next)
    {
      if (client->session_id == session_id)
	return (client);
    }
  return (0);
}

/*
 queue_put_data
 
     -> decode request
     -> Look for client
        update the client timer
     -> put data in queue
     -> deal incoming data (queue_deal_incoming_data)
     and return
*/
/**
 * @brief decode a request and put it in the client's queue
 * @param[in] conf configuration
 * @param[in] req request
 * @param[in] decoded_data decoded data
 * @retval 0 on success
 * @retval -1 on error
 * @note if it's no a client, send a RCODE_REFUSED code
 **/

int		queue_put_data(t_conf *conf, t_request *req, t_data *decoded_data)
{
  t_packet	*packet;
  t_simple_list	*client;
  t_list	*queue;
  int		diff = 0;
  uint16_t      seq_tmp;

  if (PACKET_LEN > decoded_data->len)
    return (-1);
  packet = (t_packet *)decoded_data->buffer;
  /* convert ntohs */
  seq_tmp = GET_16(&(packet->seq)) ; packet->seq = seq_tmp;
  seq_tmp = GET_16(&(packet->ack_seq)) ; packet->ack_seq = seq_tmp;

  DPRINTF(2, "Packet [%d] decoded, data_len %d\n", packet->seq, decoded_data->len - (int)PACKET_LEN);
  if ((client = find_client_by_session_id(conf, packet->session_id)))
    { 
      if (client->sd_tcp < 0)
	return (0); /* slient drop */
      client_update_timer(client);
      queue = client->queue;
      if (client->num_seq > packet->seq) /*  seq must not be 0 */
	diff = ((MAX_SEQ - client->num_seq) + packet->seq ); 
      else
	diff = packet->seq - client->num_seq ;
      DPRINTF(2, "diff = %d\n", diff);
      if ((diff > QUEUE_SIZE) || (!packet->seq))
	{
	  DPRINTF(3, "seq %d not good diff %d\n", packet->seq, diff);
	  return (-1); /* not in seq */
	}
      if ((queue = get_cell_in_queue(queue, diff)))
	{
	  queue_copy_query(req, queue, packet->seq);
	  if (queue_deal_incoming_data(conf, client, queue, packet, decoded_data->len))
	    {
	      close(client->sd_tcp);
	      return (delete_client(conf, client));
	    }
	}
      else 
	/* Cell not found (reply already received or cell lost ? ) */
	return (send_error(conf, req, RCODE_NAME_ERR));
    }
  
  if (!client)
    {
      DPRINTF(3, "Not a client 0x%x\n", packet->session_id);
      return (send_error(conf, req, RCODE_REFUSED));
    }
  return (0); // Silent DROP 
}
