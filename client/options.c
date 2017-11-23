/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: options.c,v 1.26.4.8 2010/06/02 13:30:32 collignon Exp $
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
 * @file options.c
 * @brief deal command line options
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef _WIN32
#include <strings.h>
#include <unistd.h>
#else
#include "mywin32.h"
#include <iphlpapi.h>
extern int	optind;
extern char	*optarg;
int		getopt(int, char * const *, const char *);
#endif


#include "client.h"
#include "my_config.h"
#include "debug.h"
#include "rr.h"

#define MAX_LINE_LEN 512

/**
 * @brief Usage
 * @param[in] program name
 **/

static void	usage(char *name)
{
  fprintf(stderr,
    "dns2tcp v%s ( http://www.hsc.fr/ )\n"
    "Usage : %s [options] [server] \n"
    "\t-c         \t: enable compression\n"
    "\t-z <domain>\t: domain to use (mandatory)\n"
    "\t-d <1|2|3>\t: debug_level (1, 2 or 3)\n"
    "\t-r <resource>\t: resource to access\n"
    "\t-k <key>\t: pre-shared key\n"
    "\t-f <filename>\t: configuration file\n"
#ifdef _WIN32
    "\t-l <port|->\t: local port to bind (mandatory if resource defined without program )\n"
#else
    "\t-l <port|->\t: local port to bind, '-' is for stdin (mandatory if resource defined without program )\n"
#endif
    "\t-e <program>\t: program to execute\n"
    "\t-t <delay>\t: max DNS server's answer delay in seconds (default is 3)\n"
    "\t-T <TXT|KEY>\t: DNS request type (default is TXT)\n"
    "\tserver\t: DNS server to use\n"
    "\tIf no resources are specified, available resources will be printed\n",
    VERSION, name);
}

/**
 * @brief check for missing parameters
 * @param[in] conf configuration
 * @retval 0 on success
 * @retval -1 on error
 **/

static int	check_mandatory_param(t_conf *conf)
{
  if (!conf->dns_server)
    {
      fprintf(stderr, "Missing parameter : need a dns server \n");
      return (-1);
    }
  if (!conf->domain)
    {
      fprintf(stderr, "Missing parameter : need a dns zone \n");
      return (-1);
    }
  if (conf->resource)
    if (! (conf->local_port || conf->cmdline || conf->output_file || conf->use_stdin))
      {
	fprintf(stderr, "Missing parameter : need a local port or a program to execute\n");
	return (-1);
      }
  return (0);
}

/**
 * @brief copy a parameter into conf structure
 * @param[in] conf configuration
 * @param[in] token parameter
 * @param[in] value value
 * @retval 0 on success
 * @retval -1 on error
 **/

static int	client_copy_param(void *my_conf, char *token, char *value)
{
  char		*buffer = 0;
  t_conf	*conf;

  conf = (t_conf *)my_conf;
  if (token)
    {
      if (!strcmp(token, "local_port"))
	{
	  if (*value != '-')
	    return ((conf->local_port)? 0 : (conf->local_port = atoi(value)));
	  return ((conf->local_port)? 0 : (conf->use_stdin = 1));
	}
      if (!strcmp(token, "enable_compression"))
	return ((conf->disable_compression) ? 0 : (conf->disable_compression = !atoi(value)));
      if (!strcmp(token, "debug_level"))
	return (debug ? 0 : (debug = atoi(value)));
      if (!strcmp(token, "query_size"))
	return (conf->query_size ? 0 : (debug = atoi(value)));
      if (!(buffer = strdup(value)))
	{
	  fprintf(stderr, "Memory error\n");
	  exit (-1);
	}
      if (!strcmp(token, "server"))
	return ((int) (conf->dns_server ? 0 : !!(conf->dns_server = buffer)));
      if (!strcmp(token, "domain"))
	return ((int) (conf->domain ? 0 :  !!(conf->domain = buffer)));
      if (!strcmp(token, "key"))
	return ((int) (conf->key ? 0 : !!(conf->key = buffer)));
      if (!strcmp(token, "resource"))
	return ((int) (conf->resource ? 0 : !!(conf->resource = buffer)));
      if (!strcmp(token, "ressource"))
	{
	  fprintf(stderr, "Warning : Incorrect ressource syntax in config file (should be resource)\n");
	  return ((int) (conf->resource ? 0 : !!(conf->resource = buffer)));
	}
    }
  if (buffer)
    free(buffer);
  return (-1);
}

/**
 * @brief get DNS from resolv.conf
 * @param[in] conf configuration
 * @retval 0 on success
 * @retval -1 on error (actually not used)
 **/

#ifndef _WIN32
static int	read_resolv(t_conf *conf)
{
  FILE		*resolv;
  char		buffer[MAX_LINE_LEN+1];
  
  if (!(resolv = fopen(RESOLV_CONF, "r")))
    return (-1);
  while (get_next_line(buffer, MAX_LINE_LEN, resolv) != -1)
    {
      if (!strncmp("nameserver", buffer, 10))
	{
	  conf->dns_server = strdup(buffer + 10);
	  fprintf(stderr, "No DNS given, using %s (first entry found in resolv.conf)\n", conf->dns_server);
	  return (fclose(resolv));
	}
    }  
  fclose(resolv);
  return (-1);
}
#else
static int      read_resolv(t_conf *conf)
{
  ULONG         size;
  FIXED_INFO    fi, *pfi;
  
  size = sizeof(fi);
  if (GetNetworkParams(&fi, &size) != ERROR_BUFFER_OVERFLOW)
    {
      pfi = &fi;
    }
  else
    {
      pfi = malloc(size);
      if (!pfi)
        return -1;
    }
  
  if (GetNetworkParams(pfi, &size) != NO_ERROR)
    {
      fprintf(stderr, "error: failed to get network parameters (%lu)\n",
              GetLastError());
      if (pfi != &fi)
        free(pfi);
      return -1;
    }
  if (strlen(pfi->DnsServerList.IpAddress.String) > 0)
    {
      conf->dns_server = strdup(pfi->DnsServerList.IpAddress.String);
      fprintf(stderr, "No DNS given, using %s (first system preferred DNS server)\n", conf->dns_server);
    }
  else
    fprintf(stderr, "No DNS configured in the system\n");
  if (pfi != &fi)
    free(pfi);
  return 0;
}
#endif

/**
 * @brief get options for command line and file configuration
 * @param[in] argc number command line arguments
 * @param[in] argv command line arguments
 * @param[in] conf configuration
 * @retval 0 on success
 * @retval -1 on error
 **/

int			get_option(int argc, char **argv, t_conf *conf)
{
  int			c;
  char			config_file[CONFIG_FILE_LEN];
  
  memset(conf, 0, sizeof(t_conf));
  memset(config_file, 0, sizeof(config_file));
  debug = 0;
  conf->conn_timeout = 3;
  conf->sd_tcp = -1;
  conf->disable_compression = 1;
  conf->query_functions = get_rr_function_by_name("TXT");
  while (1)
    {
      c = getopt (argc, argv, "ch:z:T:t:s:d:l:r:f:e:o:k:");
      if (c == -1)
	  break;
      switch (c) {
      case 'f':
	if (strlen(optarg) > (CONFIG_FILE_LEN - 10))
	  return (-1);
	strncpy(config_file, optarg, CONFIG_FILE_LEN-1);
	break;
      case 'z':
	conf->domain = optarg;
	break;
      case 'd':
	debug = atoi(optarg);
	break;
      case 'e':
	conf->cmdline = optarg;
	break;
      case 'o':
	conf->output_file = optarg;
	break;
      case 'k':
	conf->key = optarg;
	break;
      case 's':
	conf->query_size = atoi(optarg);
	break;
      case 'r':
	conf->resource = optarg;
	break;
      case 'l':
#ifndef _WIN32
	if (*optarg == '-')
	  conf->use_stdin = 1;
	else
#endif
	  conf->local_port = atoi(optarg);
	break;
      case 'c':
	conf->disable_compression = 0;
	break;
      case 'T':
	if (!(conf->query_functions = get_rr_function_by_name(optarg)))
	  {
	    fprintf(stderr, "Invalid query type %s\n", optarg);
	    return (-1);
	  }
	break;
      case 't':
	c = atoi(optarg);
	if ((c <= 0) || (c > 4*60))
	  {
	    fprintf(stderr,
	    	"connection timeout must be within [1..240] seconds\n");
	    return (-1);
	  }
	conf->conn_timeout = (uint8_t) c;
	break;
      case 'h':
      default:
	usage(argv[0]);
	return (-1);
      }
    }
  if (optind < argc)
      conf->dns_server = argv[optind];
  if ((*config_file) || (!conf->domain))
    /* we don't care if it read_config fails, config file may not
       exist */
    read_config(config_file, conf, client_copy_param, ".dns2tcprc");
  if (!conf->dns_server)
    read_resolv(conf);
  if (check_mandatory_param(conf) == -1)
    {
      usage(argv[0]);
      return (-1);
    }
  if (debug)
    fprintf(stderr, "debug level %d\n", debug);
  return (0);
}

	  
	  
