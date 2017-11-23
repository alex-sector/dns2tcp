/*
** Copyright (C) 2006 Olivier DEMBOUR
** $Id: command.c,v 1.4.4.4 2010/06/01 15:25:29 collignon Exp $
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

#ifndef _WIN32
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#else
#include "mywin32.h"
#endif

#include <signal.h>
#include <stdlib.h>
#include <errno.h>

#include "myerror.h"
#include "list.h"
#include "client.h"
#include "debug.h"

#define IS_SEPARATOR(c) ((c == ' ') || (c == '\t') || (c == '\n'))
#define MAX_ARG_SIZE 64

#ifndef _WIN32

/**
 * @brief find numbers of arguments
 * @param[in] cmdline command to execute
 * @retval numbers of arguments
 **/

int	count_arg(char *cmdline)
{
  int	i = 0;
  
  while (*cmdline)
    if (IS_SEPARATOR(*cmdline++))
      i++;
  return (i);
}

/**
 * @brief convert command line into argv
 * @param[in] line command line
 * @param[in] argv table
 **/

void	line_to_argv(char *line, char **argv)
{
  int	i = 0;

  if  (!IS_SEPARATOR(*line))
    argv[i++] = line;  
  while (*line)
    {
      while ((*line) && (!IS_SEPARATOR(*line)))
	line++;
      while ((*line) && (IS_SEPARATOR(*line)))
	*line++ = 0;
      argv[i++] = *line? line: 0;  
    }
}

/**
 * @brief create a process, add it into client list
 * @param[in] conf configuration
 * @retval 0 on success
 * @retval -1 on error
 **/

int			create_process(t_conf *conf)
{
  int		        from_child[2];
  int			to_child[2];
  int			status;
  pid_t			pid;

  if ((pipe(from_child) == -1) || (pipe(to_child) == -1))
    {
      perror("pipe");
      exit(-1);
    }
  pid = fork();
  if (!pid)
    {
      char *argv[MAX_ARG_SIZE];

      line_to_argv(conf->cmdline, argv);      
      if (count_arg(conf->cmdline) > MAX_ARG_SIZE)
	{
	  fprintf(stderr, "Arg size > MAX_ARG_SIZE\n");
	  exit (-1);
	}
      if (dup2(to_child[0], STDIN_FILENO) == -1)
	return (-1);
      if (dup2(from_child[1], STDOUT_FILENO) == -1)
	return (-1);
      if (dup2(from_child[1], STDERR_FILENO) == -1)
      	return (-1);
      close(from_child[0]);
      close(to_child[0]);
      execv(argv[0],argv);
      fprintf(stderr, "execv error (%d) for '%s'\n", errno, conf->cmdline);
      exit(1);
    }
  DPRINTF(1, "Executing %s (Pid %d)\n",  conf->cmdline, (int)pid);
  close(from_child[1]);
  close(to_child[0]);
  if (add_client(conf, from_child[0], to_child[1] , pid))
    {
      /* BUGFIX: child process not killed if auth has failed (with -e) */
		kill(pid, SIGKILL);
		waitpid(-1, &status, WNOHANG);
      close(from_child[0]); close(to_child[1]);
      return (-1);
    }
  return (0);
}

#else
/*
 * Windows pipe handling simply *SUX*
 * It doesn't seem possible to perform asynchronous I/O on anonymous pipes.
 * ReadFile() will block if there is no pending data. We don't want to use
 * any additional thread.
 * So we have to use named pipe... nasty ugly trick ...
 */
static int create_pipe(HANDLE *rfd, HANDLE *wfd, int async_read, SECURITY_ATTRIBUTES *attr)
{
  char name[128];
  
  sprintf(name, "\\\\.\\pipe\\win-sux-no-async-anon-pipe-%lu-%i",
	  GetCurrentProcessId(), rand());
  DPRINTF(2, "using pipe %s\n", name);
  
  *rfd = CreateNamedPipe(name,
			 PIPE_ACCESS_INBOUND|(async_read ? FILE_FLAG_OVERLAPPED : 0),
			 PIPE_TYPE_BYTE|PIPE_WAIT, 2, 4096, 4096,
			 5000 /*msec*/, attr);
  if (*rfd == INVALID_HANDLE_VALUE) 
    {
      MYERROR("error: failed to create pipe\n");
      return -1;
    }
  
  *wfd = CreateFile(name, GENERIC_WRITE, 0, attr, 
		    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (*wfd == INVALID_HANDLE_VALUE) {
    MYERROR("error: failed to create pipe\n");
    CloseHandle(*rfd);
    return -1;
  }  
  return 0;
}

int                     create_process(t_conf *conf)
{
  
  BOOL			res;
  HANDLE		stdin_child, stdin_parent, stdout_parent, stdout_child, stderr_child;
  DWORD			pid;
  SECURITY_ATTRIBUTES	sattr;
  PROCESS_INFORMATION	pi;
  STARTUPINFO		si;
  
  ZeroMemory(&sattr, sizeof(sattr));
  ZeroMemory(&pi, sizeof(pi));
  ZeroMemory(&si, sizeof(si));
  
  sattr.nLength = sizeof(sattr);
  sattr.bInheritHandle = TRUE;
  
  // stdin pipe
  if (create_pipe(&stdin_child, &stdin_parent, 0, &sattr))
    return -1;
  
  // stdout pipe
  if (create_pipe(&stdout_parent, &stdout_child, 1, &sattr))
    {
      CloseHandle(stdin_child);
      CloseHandle(stdin_parent);
      return -1;
    }
  
  // stderr pipe
  if (!DuplicateHandle(GetCurrentProcess(), stdout_child,
		       GetCurrentProcess(), &stderr_child,
		       0, TRUE, DUPLICATE_SAME_ACCESS))
    {
      MYERROR("error: failed to duplicate pipe handle\n");
      CloseHandle(stdin_child);
      CloseHandle(stdin_parent);
      CloseHandle(stdout_child);
      CloseHandle(stdout_parent);
      return -1;
    }
  
  SetHandleInformation(stdin_parent, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(stdout_parent, HANDLE_FLAG_INHERIT, 0);
  
  si.cb         = sizeof(si);
  si.dwFlags    = STARTF_USESTDHANDLES;
  si.hStdInput  = stdin_child;
  si.hStdOutput = stdout_child;
  si.hStdError  = stderr_child;
  
  //FIXME print error
  res = CreateProcess(NULL, conf->cmdline, NULL, NULL, TRUE, 0,
		      NULL, NULL, &si, &pi);
  
  CloseHandle(stdin_child);
  CloseHandle(stdout_child);
  CloseHandle(stderr_child);
  
  if (!res)
    {
      MYERROR("error: failed to create process (%lu)\n", GetLastError());
      CloseHandle(stdin_parent);
      CloseHandle(stdout_parent);
      return -1;
    }
  
  pid = GetProcessId(pi.hProcess);
  CloseHandle(pi.hThread);

  DPRINTF(3, "===============================\n");
  DPRINTF(3, "pipes: %lx/%lx\n", (long)stdin_parent, (long)stdout_parent);
  DPRINTF(3, "proc:  %lx\n", (long)pi.hProcess);
  DPRINTF(3, "===============================\n");

  if (add_client(conf, (socket_t)stdout_parent,
		 (socket_t)stdin_parent, pi.hProcess))
    {
      CloseHandle(stdin_parent);
      CloseHandle(stdout_parent);
      TerminateProcess(pi.hProcess, 0);
      CloseHandle(pi.hProcess);
      return -1;
    }
  return 0;
}
#endif
