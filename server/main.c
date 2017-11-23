/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: main.c,v 1.28.4.2 2009/12/07 08:46:29 dembour Exp $
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

#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <grp.h>

#include "config.h"
#include "server.h"
#include "dns.h"
#include "list.h"
#include "socket.h"
#include "options.h"
#include "debug.h"
#include "myerror.h"
#include "log.h"

int			detach_process(t_conf *conf)
{
  int			fd;
  pid_t                 pid;
  FILE                  *pidfile;

  if (!(pid = fork()))
    { /* child */
      if (setsid() < 0)
	{
	  perror("");
	  return (-1); 
	}
      if ((fd = open("/dev/null", O_RDWR)) == -1)
	return (-1);
      fclose(stdin);  fclose(stdout); fclose(stderr);
      dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
      close(fd);
      return (0);
      
    }
  if (! (pidfile = fopen((conf->pidfile == 0)? DEFAULT_PIDFILE: conf->pidfile,  "w")))
    {
      LOG("Could not open pidfile %s\n", conf->pidfile? conf->pidfile : DEFAULT_PIDFILE);
      exit (0);
    }
  fprintf(pidfile, "%ld\n", (long) pid);
  fclose(pidfile);
  exit (0);
}

/*
  Just do a real DNS request to load libresolv
  before the chroot
*/

void			load_resolv(t_conf *conf)
{
  struct addrinfo	*res;
  struct addrinfo	hints;
  char			*domain;

  memset(&hints, 0, sizeof(hints));

  hints.ai_flags    = AI_CANONNAME;
  hints.ai_family   = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  /* 
     jump the subdomain, do not try to resolv ourself 
     because we are not a real DNS server
  */
  if (!(domain = strchr(conf->my_domain, '.'))
      || (!*++domain))
    domain = conf->my_domain;
  if (!getaddrinfo(domain, NULL, &hints, &res))
    freeaddrinfo(res);
}

int			jail(t_conf *conf)
{
  struct passwd		*pwd = 0;
  FILE			*pid_file;

  if (!conf->foreground)
    detach_process(conf);
  if ((conf->user) && (!(pwd = getpwnam(conf->user))))
    {
      LOG("User unknown %s", conf->user);
      return (-1);
    }
  if (conf->pid_file)
    {
      pid_file = fopen(conf->pid_file, "w");
      if (pid_file)
        {
          fprintf(pid_file, "%d\n", getpid());
          fclose(pid_file);
        }
      else
        {
	  LOG("Failed to write pidfile");
	  return (-1);
        }
    }
  if (conf->chroot)
    {
      DPRINTF(1, "Chroot to %s\n", conf->chroot);
      load_resolv(conf);
      if ((chroot(conf->chroot) == -1) || chdir("/"))
	{
	  LOG("Failed to chroot in %s\n", conf->chroot);
	  return (-1);
	}
    }
  if (pwd) 
    {
      DPRINTF(1, "Change to user %s\n", conf->user);
      if (setgroups(0, NULL) || setgid(pwd->pw_gid) || setuid(pwd->pw_uid))
	{
	  LOG("Failed to change to user %s\n", conf->user);
	  return (-1);
	}
    }
#ifdef RLIMIT_NPROC
   struct rlimit		rlim;
 
   /* fork() is not need anymore, disable it */
   rlim.rlim_max = rlim.rlim_cur = 0;
   if (setrlimit(RLIMIT_NPROC, &rlim))
     return (-1);
#endif
  return (0);
}

int			main(int argc, char **argv)
{
  t_conf		my_conf;
  t_conf		*conf;

  conf = &my_conf;
  if (get_option(argc, argv, conf))
    return (-1);
  openlog("dns2tcp", LOG_PID , LOG_SYSLOG);
  signal(SIGPIPE, SIG_IGN);
  if (!bind_socket(conf))
    {
      LOG("Starting Server v%s...", VERSION);
      if (jail(conf))
	return (-1);
      srand(getpid()^time(0));
      do_server(conf);
    }
  closelog();
  return (0);
}

