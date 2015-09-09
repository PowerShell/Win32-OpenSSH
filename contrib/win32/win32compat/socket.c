/*
 * Author: NoMachine <developers@nomachine.com>
 *
 * Copyright (c) 2009, 2012 NoMachine
 * All rights reserved
 *
 * Support functions and system calls' replacements needed to let the
 * software run on Win32 based operating systems.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <winsock2.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sfds.h"

#define FAIL(X) if (X) goto fail

#undef  DEBUG

#ifdef DEBUG
  #define DBG_MSG(FMT, ARGS...) debug3(FMT, ## ARGS)
#else
  #define DBG_MSG(FMT, ARGS...)
#endif

extern void debug(const char *fmt,...);
extern void debug2(const char *fmt,...);
extern void debug3(const char *fmt,...);
extern void error(const char *fmt,...);
extern void fatal(const char *fmt,...);

static int winsock_initialized = 0;

extern int logfd;

static FD_SET debug_sfds;
static FD_SET crlf_sfds;

static fd_set read_sfd_set;
static fd_set write_sfd_set;

#define MAX_THREADS 256
#define TEST_READ   1
#define TEST_WRITE  0

#define MSG_WAITALL 0x8

int PassInputFd  = STDIN_FILENO;
int PassOutputFd = STDOUT_FILENO;

/*
 * We store cookies for authorize 
 * connections on AF_UNIX sockets here.
 */
 
struct _SocketCookie
{ 
  FILE *f;
  int socket;
  char *cookie;
} SocketCookieMap[SFD_MAP_SIZE] = {0};

DWORD WINAPI selectThread(LPVOID lpParam);

typedef struct 
{
  HANDLE thread;
  
  DWORD thread_id;
  
  HANDLE semaphore1;
  HANDLE semaphore2;

  int sfd;
  int thread_no;
  int test_type;
  int signaled;
  int exit;
  int exited;
} thread_data_t, *thread_data_p;

static thread_data_p thread_data_set[MAX_THREADS];

#define IS_WINSOCK_INITIALIZED() (winsock_initialized != 0)

void WSHELPinitialize();

/*
 * FIXME. This function forces stopping all socket threads 
 * at next select. This workaround nivelates problem with
 * infinite hangs up in below scenario:
 * 
 * a) read select start.
 * b) write select start.
 * c) read select ends: SSH2_MSG_CHANNEL_CLOSE received.
 * d) close input channel.
 * e) now write select may never ends.
 *
 * We call this function after (d).
 */

void StopSocketThreads()
{
  DBG_MSG("-> StopSocketThreads()...");

  FD_ZERO(&write_sfd_set);
  FD_ZERO(&read_sfd_set);
  
  DBG_MSG("<- StopSocketThreads()...");
}


void read_sfd_set_add(int sfd)
{
  static int do_init = 1;

  if (do_init)
  {
    FD_ZERO(&read_sfd_set);
    
    do_init = 0;
  }

  FD_SET((SOCKET) sfd, &read_sfd_set);
}


void write_sfd_set_add(int sfd)
{
  static int do_init = 1;

  if (do_init)
  {
    FD_ZERO(&write_sfd_set);

    do_init = 0;
  }

  FD_SET((SOCKET) sfd, &write_sfd_set);
}


void debug_sfd(int sfd)
{
  static int do_init = 1;

  if (do_init)
  {
    FD_ZERO(&debug_sfds);
    
    do_init = 0;
  }

  FD_SET((SOCKET) sfd, &debug_sfds);
}


void crlf_sfd(int sfd)
{
  static int do_init = 1;

  if (do_init)
  {
    FD_ZERO(&crlf_sfds);
  
    do_init = 0;
  }

  FD_SET((SOCKET) sfd, &crlf_sfds);
}


static int getWSAErrno()
{
  int wsaerrno = WSAGetLastError();

  if (wsaerrno == WSAEWOULDBLOCK)
  {
    return EAGAIN;
  }  
  
  if (wsaerrno == WSAEFAULT)
  {
    return EFAULT;
  }
  
  if (wsaerrno == WSAEINVAL)
  {
    return EINVAL;
  }  
  
  return wsaerrno;
}


int WSHELPisatty(int sfd)
{
  int ret;
  
  /*
   * We can only do this for console fds.
   */
  
  if (sfd_is_console(sfd) && sfd > 0)
  {
    ret = _isatty(sfd_to_fd(sfd));

    return ret;
  }

  /*
   * Not a tty.
   */
  
  return 0;
}


int WSHELPfstat(int sfd, struct stat *buf)
{
  int ret;

  struct _stat tmp;
  
  DBG_MSG("WSHELPfstat(sfd = %d, buf = %p)", sfd, buf);

  ret = _fstat(sfd_to_fd(sfd), &tmp);

  /*
   * Handle errors.
   */
  
  if (ret == -1)
  {
    errno = getWSAErrno();
    
    debug("fstat() returned error, errno [%d]", errno);
  
    return -1;
  }

  buf -> st_gid   = tmp.st_gid;
  buf -> st_atime = tmp.st_atime;
  buf -> st_ctime = tmp.st_ctime;
  buf -> st_dev   = tmp.st_dev;
  buf -> st_ino   = tmp.st_ino;
  buf -> st_mode  = tmp.st_mode;
  buf -> st_mtime = tmp.st_mtime;
  buf -> st_nlink = tmp.st_nlink;
  buf -> st_rdev  = tmp.st_rdev;
  buf -> st_size  = tmp.st_size;
  buf -> st_uid   = tmp.st_uid;

  return ret;
}


FILE* WSHELPfdopen(int sfd, const char *mode)
{
  FILE* ret;

  ret = fdopen(sfd_to_fd(sfd), mode);

  /*
   * Handle errors.
   */
  
  if (ret == NULL)
  {
    errno = getWSAErrno();

    debug("fdopen() returned error, errno [%d]", errno);
  
    return NULL;
  }
  
  return ret;
}


int WSHELPpipe(int pfds[2])
{
  int ret;

  ret = _pipe(pfds, 1024, _O_BINARY);

  /*
   * Handle errors.
   */
  
  if (ret == -1)
  {
    errno = getWSAErrno();

    debug("_pipe() returned error, errno [%d]", errno);
    
    return -1;
  }

  pfds[0] = allocate_sfd((int)pfds[0]);

  pfds[1] = allocate_sfd((int)pfds[1]);

  return ret;
}


int WSHELPdup(int oldsfd)
{
  int oldfd;

  int newfd;
  
  int newsfd;

  oldfd = sfd_to_fd(oldsfd);

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Pass through to base layer.
   */
  
  newfd = _dup(oldfd);

  /*
   * Handle errors.
   */
  
  if (newfd == -1)
  {
    errno = getWSAErrno();

    debug("_dup() returned error, errno [%d]", errno);
    
    return -1;
  }

  /*
   * Map the socket.
   */
  
  newsfd = allocate_sfd(newfd);

  return newsfd;
}


int WSHELPdup2(int oldsfd, int newsfd)
{
  int oldfd;
  int newfd;

  oldfd = sfd_to_fd(oldsfd);
  newfd = sfd_to_fd(newsfd);

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Pass through to base layer.
   */
  
  newfd = _dup2(oldfd, newfd);

  /*
   * Handle errors.
   */
  
  if (newfd == -1)
  {
    errno = getWSAErrno();
    
    debug("_dup2() returned error, errno [%d]", errno);
  
    return -1;
  }

  /*
   * Map the socket.
   */
  
  newsfd = allocate_sfd(newfd);

  return newsfd;
}


int WSHELPopen(const char *pathname, int flags, ...)
{
  DBG_MSG("WSHELPopen(path = [%s], flags = [%d])", pathname, flags);
  
  va_list arguments;
  int newfd;
  int newsfd;

  va_start(arguments, flags);

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Pass through to base layer.
   */
  
  newfd = _open(pathname, flags, arguments);

  va_end(arguments);

  /*
   * Handle errors.
   */
  
  if (newfd == -1)
  {
    errno = getWSAErrno();

    debug("_open() returned error, errno [%d]", errno);
    
    return -1;
  }

  /*
   * Map the socket.
   */
  
  newsfd = allocate_sfd(newfd);

  return newsfd;
}


int WSHELPwopen(const wchar_t *pathname, int flags, ...)
{
  va_list arguments;
  int newfd;
  int newsfd;

  va_start(arguments, flags);

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Pass through to base layer.
   */
  
  newfd = _wopen(pathname, flags, arguments);

  va_end(arguments);

  /*
   * Handle errors.
   */
  
  if (newfd == -1)
  {
    errno = getWSAErrno();

    debug("_wopen() returned error, errno [%d]", errno);
    
    return -1;
  }

  /*
   * Map the socket.
   */
  
  newsfd = allocate_sfd(newfd);

  return newsfd;
}


int WSHELPcreat(const char *pathname, int mode)
{
  int newfd;
  int newsfd;

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Pass through to base layer.
   */
  
  newfd = _creat(pathname, mode);

  /*
   * Handle errors.
   */
  
  if (newfd == -1)
  {
    errno = getWSAErrno();

    debug("_creat() returned error, errno [%d]", errno);
    
    return -1;
  }

  /*
   * Map the socket.
   */
  
  newsfd = allocate_sfd(newfd);

  return newsfd;
}


int WSHELPsocket(int af, int type, int protocol)
{
  SOCKET sock = -1;
  
  int sfd;
  
  /*
   * Verify that winsock has been initialized.
   */
  
  if (!IS_WINSOCK_INITIALIZED())
  {
    WSHELPinitialize();
  }

  /*
   * Clear errno.
   */
  
  errno = 0;

  switch(af)
  {
    /*
     * AF_UNIX. We emulate unix socket by localhost tcp here.
     */
    
    case AF_UNIX:
    {
      DBG_MSG("Creating AF_UNIX socket...");
      
      sock = socket(AF_INET, type, 0);
      
      break;
    }
    
    /*
     * We pass through to base layer as default.
     */
    
    default:
    {
      DBG_MSG("Creating AF_INET socket...");
      
      sock = socket(af, type, protocol);
    }
  }

  /*
   * Handle errors.
   */
  
  if (sock == INVALID_SOCKET)
  {
    errno = getWSAErrno();
    
    debug("socket() returned error, errno [%d]", errno);
    
    DBG_MSG("Cannot create socket : errno = %u", errno);
    
    return -1;
  }

  DBG_MSG("Socket %u created.", sock);
  
  /*
   * Map the socket to our fd.
   */
  
  sfd = allocate_sfd((int) sock);

  return sfd;
}


int WSHELPsetsockopt(int sfd, int level, int optname, const char* optval, int optlen)
{
  SOCKET sock;
  
  int ret;

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Get the SOCKET.
   */
  
  sock = (SOCKET) sfd_to_handle(sfd);

  /*
   * Call the underlying function.
   */
  
  ret = setsockopt(sock, level, optname, optval, optlen);

  /*
   * Check for errors.
   */
  
  if (ret == SOCKET_ERROR)
  {
    errno = getWSAErrno();
    
    debug("setsockopt() returned error, errno [%d]", errno);
    
    return -1;
  }

  return 0;
}


int WSHELPgetsockopt(int sfd, int level, int optname, char* optval, int* optlen)
{
  SOCKET sock;
  
  int ret;

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Get the SOCKET.
   */
  
  sock = (SOCKET) sfd_to_handle(sfd);

  /* 
   * Call the underlying function.
   */
  
  ret = getsockopt(sock, level, optname, optval, optlen);

  /*
   * Check for errors.
   */
  
  if (ret == SOCKET_ERROR)
  {
    errno = getWSAErrno();
   
    debug("getsockopt() returned error, errno [%d]", errno);
    
    return -1;
  }

  return 0;
}


int WSHELPgetsockname(int sfd, struct sockaddr* name, int* namelen)
{
  SOCKET sock;
  
  int ret;

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Get the SOCKET.
   */
  
  sock = (SOCKET) sfd_to_handle(sfd);

  /*
   * Call the underlying function.
   */
  
  ret = getsockname(sock, name, namelen);

  /*
   * Check for errors.
   */
  
  if (ret == SOCKET_ERROR)
  {
    errno = getWSAErrno();
   
    debug("getsockname() returned error, errno [%d]", errno);
    
    return -1;
  }

  return 0;
}


int WSHELPgetpeername(int sfd, struct sockaddr* name, int* namelen)
{
  SOCKET sock;
  
  int ret;

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Get the SOCKET.
   */
  
  sock = (SOCKET) sfd_to_handle(sfd);

  /*
   * Call the underlying function.
   */

  ret = getpeername(sock, name, namelen);

  /*
   * Check for errors.
   */
  
  if (ret == SOCKET_ERROR)
  {
    errno = getWSAErrno();
    
    debug("getpeername() returned error, errno [%d]", errno);
    
    return -1;
  }

  return 0;
}


int WSHELPioctlsocket(int sfd, long cmd, u_long* argp)
{
  SOCKET sock;
  
  int ret;

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Get the SOCKET.
   */
  
  sock = (SOCKET) sfd_to_handle(sfd);

  /*
   * Call the underlying function.
   */
  
  ret = ioctlsocket(sock, cmd, argp);

  /*
   * Check for errors.
   */
  
  if (ret == SOCKET_ERROR)
  {
    errno = getWSAErrno();
    
    debug("ioctlsocket() returned error, errno [%d]", errno);
    
    return -1;
  }

  return 0;
}


int WSHELPlisten(int sfd, int backlog)
{
  SOCKET sock;
  
  int ret;

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Get the SOCKET.
   */
  
  sock = (SOCKET) sfd_to_handle(sfd);

  /*
   * Call the underlying function.
   */
 
  ret = listen(sock, backlog);

  /*
   * Check for errors.
   */
  
  if (ret == SOCKET_ERROR)
  {
    errno = getWSAErrno();
   
    debug("listen() returned error, errno [%d]", errno);
    
    return -1;
  }

  return 0;
}


int WSHELPbind(int sfd, const struct sockaddr *name, int namelen)
{
  SOCKET sock = -1;
  
  int ret = SOCKET_ERROR;

  /*
   * Clear errno.
   */
 
  errno = 0;

  /*
   * Get the SOCKET.
   */
  
  sock = (SOCKET) sfd_to_handle(sfd);

  switch(name -> sa_family)
  {
    /*
     * We emulate unix socket here, by tcp socket binded to localhost.
     */
    
    case AF_UNIX:
    {
      int len = 0;

      unsigned int i = 0;
  
      FILE *f = NULL;
      
      char cookie[64 + 1] = {0};
  
      struct sockaddr_in sin = {0};
  
      struct sockaddr_un *unixName = (struct sockaddr_un *) name;

      /*
       * Bind socket to localhost:0.
       */
  
      DBG_MSG("Binding socket %u to localhost:0...", (unsigned int) sock);
  
      sin.sin_family = AF_INET;
      sin.sin_port = 0;
      sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

      FAIL(bind(sock, (struct sockaddr *) &sin, sizeof(sin)));
  
      /*
       * Retreave local name for socket.
       */
  
      DBG_MSG("Retreaving socket's local name...");
  
      len = sizeof(sin);
  
      FAIL(getsockname(sock, (struct sockaddr *) &sin, &len));

      sin.sin_port = ntohs(sin.sin_port);
  
      DBG_MSG("family = %u", sin.sin_family);
      DBG_MSG("port   = %u", sin.sin_port);

      /*
       * Check is socket file already exists.
       */
  
      DBG_MSG("Checking is socket file free...");
  
      WSASetLastError(WSAEADDRINUSE);
      
      f = fopen(unixName -> sun_path, "rt");
  
      FAIL(f);
  
      /*
       * Create file with retrieved port and cookie.
       * This file emulates unix socket itself.
       */
  
      DBG_MSG("Creating socket file [%s]...", unixName -> sun_path);
  
      f = fopen(unixName -> sun_path, "wt+");
 
      FAIL(f == NULL);
  
      /*
       * Write tcp port to soket file.
       */
      
      fprintf(f, "%d ", sin.sin_port);
   
      /*
       * Write 64-byte cookie to socket file.
       * We add port number to rand() to avoid generating the same
       * cookie until next second reached.
       *
       */
      
      for (i = 0; i < 64; i++)
      {
        cookie[i] = 33 + (rand() + sin.sin_port) % (128 - 33);
      }
      
      cookie[64] = 0;
      
      fputs(cookie, f);
      
      fflush(f);
      
      /*
       * Cache cookie and file handle in SocketCookieMap var.
       */
      
      for (i = 0; i < SFD_MAP_SIZE; i++)
      {
        /*
         * Find first empty row.
         */
        
        if (SocketCookieMap[i].socket == 0)
        {
          SocketCookieMap[i].socket = sock;
          SocketCookieMap[i].cookie = strdup(cookie);
          SocketCookieMap[i].f      = f;

          /*
          for (int i = 0; i < 64; j++)
          {
            printf("%02x ", SocketCookieMap[i].cookie[j]);
          }
          */

          break;
        }
      }
 
      /*
       * Clear error.
       */
      
      ret = 0;
      
      WSASetLastError(0);
      
      break;
    }
    
    /*
     * As default, we call underlying function.
     */
  
    default:
    {
      ret = bind(sock, name, namelen);
    }
  }

fail:
  
  /*
   * Check for errors.
   */
  
  if (ret == SOCKET_ERROR)
  {
    errno = getWSAErrno();
   
    debug("bind() returned error, errno [%d]", errno);
    
    return -1;
  }

  return 0;
}


int WSHELPconnect(int sfd, const struct sockaddr* name, int namelen)
{
  SOCKET sock = -1;

  int ret = SOCKET_ERROR;

  /*
   * Clear errno.
   */
  
  errno = 0;
  
  /*
   * Get the SOCKET.
   */
  
  sock = (SOCKET) sfd_to_handle(sfd);

  switch(name -> sa_family)
  {
    /*
     * We emulate unix socket here, by tcp socket binded to localhost.
     */
    
    case AF_UNIX:
    {
      int len  = 0;
      int port = -1;

      char cookie[64 + 1] = {0};

      unsigned int i = 0;
  
      FILE *f = NULL;
  
      struct sockaddr_in sin = {0};
  
      struct sockaddr_un *unixName = (struct sockaddr_un *) name;

      /*
       * Open socket file.
       */
      
      DBG_MSG("Opening socket file [%s] for socket %u...",
                  unixName -> sun_path, (unsigned int) sock);
      
      f = fopen(unixName -> sun_path, "rt");
      
      FAIL(f == NULL);
      
      /*
       * Read tcp port and cokie from socket file.
       */
      
      fscanf(f, "%d ", &port);
      fgets(cookie, 64 + 1, f);
      
      fclose(f);

      /*
       * Connect to localhost on given port.
       */
  
      DBG_MSG("Connecting to localhost:%u on socket %u...", 
                  port, (unsigned int) sock);
  
      sin.sin_family = AF_INET;
      sin.sin_port = htons(port);
      sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

      FAIL(connect(sock, (struct sockaddr *) &sin, sizeof(sin)));
      
      /*
       * Send authorization cookie.
       * If cookie doesn't match to cookie stored on server side
       * server shutdown connection.
       */

      DBG_MSG("Sending authorization cookie...\n");
      
      for (i = 0; i < 64; i++)
      {
        DBG_MSG("%02x ", cookie[i]);
      }
      
      DBG_MSG("\n");
      
      
      ret = send(sock, cookie, 64, MSG_DONTROUTE);
    
      FAIL(ret != 64);

      /*
       * Clear error.
       */
      
      ret = 0;
      
      break;
    }
    
    /*
     * As default, we call underlying function.
     */

    default:
    {
      /*
       * Call the underlying function as default.
       */
  
      ret = connect(sock, name, namelen);
    }
  }
  
  /*
   * Check for errors.
   */
  
fail:

  if (ret == SOCKET_ERROR)
  {
    errno = getWSAErrno();
   
    debug("connect() returned error, errno [%d]", errno);

    DBG_MSG("connect() returned error, errno [%d]\n", errno);
  
    /*
     * Re-map EAGAIN for connect() semantics.
     */
    
    if (errno == EAGAIN)
    {
      errno = WSAEINPROGRESS;
    }  
    
    return -1;
  }

  return 0;
}


int WSHELPshutdown(int sfd, int how)
{
  SOCKET sock;
  
  int ret;

  /*
   * Clear errno.
   */
  
  errno = 0;

  /*
   * Get the SOCKET.
   */
  
  sock = (SOCKET) sfd_to_handle(sfd);

  /*
   * Call the underlying function.
   */
  
  ret = shutdown(sock, how);

  /*
   * Check for errors.
   */
  
  if (ret == SOCKET_ERROR)
  {
    errno = getWSAErrno();
   
    debug("shutdown() returned error, errno [%d]", errno);
    
    return -1;
  }

  return 0;
}


int WSHELPaccept(int sfd, struct sockaddr* addr, int* addrlen)
{
  SOCKET sock;
  
  SOCKET new_sock;
  
  int new_sfd;
  
  int i = 0;
  int j = 0;
  int ret = -1;

  int expectedFamily = addr -> sa_family;
  
  /*
   * Clear errno
   */

  errno = 0;

  /*
   * Get the SOCKET
   */

  sock = (SOCKET) sfd_to_handle(sfd);

  /*
   * Call the underlying function
   */

  new_sock = accept(sock, addr, addrlen);

  switch(expectedFamily)  
  {
    /*
     * Cookie authorization for AF_UNIX.
     */
    
    case AF_UNIX:
    {
      fd_set readsocks;

      struct timeval timeout = {10, 0};

      char remoteCookie[64 + 1] = {0};

      int authorized = 0;
      
      /*
       * Retrieave 64-byte authorization cookie from client.
       */

      DBG_MSG("Waiting for 64-byte cookie...\n");

      FD_ZERO(&readsocks);
      FD_SET((SOCKET) new_sock, &readsocks);

      select(0, &readsocks, NULL, NULL, &timeout);

      ret = recv(new_sock, remoteCookie, 64, 0);


      #ifdef DEBUG

      DBG_MSG("\nRemoteCookie = [");

      for (i = 0; remoteCookie[i]; i++)
      {
        DBG_MSG("%02x ", remoteCookie[i]);
      }

      DBG_MSG("]\n\n");

      #endif

      /*
       * Find correct cookie in SocketCookieMap.
       */

      for (i = 0; i < SFD_MAP_SIZE; i++)
      {
        /*
         * Find socket.
         */

        if (SocketCookieMap[i].socket == sock)
        {
          #ifdef DEBUG

          DBG_MSG("\nServerCookie = [");

          for (j = 0; SocketCookieMap[i].cookie[j]; j++)
          {
            DBG_MSG("%02x ", SocketCookieMap[i].cookie[j]);
          }

          DBG_MSG("]\n\n");

          #endif

          /*
           * Compare cookies.
           */

          if (strncmp(SocketCookieMap[i].cookie, remoteCookie, 64) == 0)
          {
            authorized = 1;
          }

          break;
        }
      }
      
      /*
       * Cookies doesn't match. Shutdown connection.
       */

      if (authorized == 0)
      {
        DBG_MSG("ERROR. Accept from unathorized client."
                    " I'm going to shutdown connection.\n");

        shutdown(new_sock, SD_BOTH);

        new_sock = INVALID_SOCKET;
      }  

      break;
    }
    
    default:
    {
    }
  }
  
  /*
   * Handle errors
   */

  if (new_sock == INVALID_SOCKET)
  {
    errno = getWSAErrno();
    
    debug("accept() returned error, errno [%d]", errno);
    
    return -1;
  }

  /*
   * Map the socket
   */
  
  new_sfd = allocate_sfd((int)new_sock);

  return new_sfd;
}


int socketpair(int socks[2])
{
  struct sockaddr_in addr;

  SOCKET listener;

  int e;

  int addrlen = sizeof(addr);

  /*
   * Clear out last error.
   */

  errno = 0;

  if (socks == 0)
  {
    WSASetLastError(WSAEINVAL);

    errno = getWSAErrno();
    
    return SOCKET_ERROR;
  }

  /*
   * Initialize to invalid sockets.
   */
  
  socks[0] = socks[1] = INVALID_SOCKET;
  
  if ((listener = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
  {
    errno = getWSAErrno();
    
    return SOCKET_ERROR;
  }

  /*
   * Zero out the structure and set params.
   */
  
  memset(&addr, 0, sizeof(addr));

  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = htonl(0x7f000001);
  addr.sin_port        = 0;

  /*
   * Call base function.
   */

  e = bind(listener, (const struct sockaddr*) &addr, sizeof(addr));
  
  if (e == SOCKET_ERROR)
  {
    e = WSAGetLastError();
    
    closesocket(listener);
    
    WSASetLastError(e);
    
    errno = getWSAErrno();
    
    return SOCKET_ERROR;
  }

  /*
   * Find out what ephermeral port got assigned.
   */
  
  e = getsockname(listener, (struct sockaddr*) &addr, &addrlen);
  
  if (e == SOCKET_ERROR)
  {
    e = WSAGetLastError();
    
    closesocket(listener);
   
    WSASetLastError(e);
    
    errno = getWSAErrno();
    
    return SOCKET_ERROR;
  }

  do
  {
    if (listen(listener, 1) == SOCKET_ERROR)
    {
      break;
    }

    if ((socks[0] = (int) WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)) == (int) INVALID_SOCKET)
    {
      break;
    }

    if (connect(socks[0], (const struct sockaddr*) &addr, sizeof(addr)) == SOCKET_ERROR)
    {
      break;
    }

    if ((socks[1] = (int) accept(listener, NULL, NULL)) == (int) INVALID_SOCKET)
    {
      break;
    }

    /*
     * Don't need to listen anymore.
     */
    
    closesocket(listener);

    /*
     * Maps the sockets.
     */
    
    socks[0] = allocate_sfd((int)socks[0]);
    socks[1] = allocate_sfd((int)socks[1]);

    /*
     * All set, return the socket pair.
     */
    
    return 0;
  } while (0);

  /*
   * Cleanup and return if we bailed out of creation above.
   */
  
  e = WSAGetLastError();
  
  closesocket(listener);
  
  closesocket(socks[0]);
  
  closesocket(socks[1]);
  
  WSASetLastError(e);
  
  errno = getWSAErrno();

  socks[0] = INVALID_SOCKET;
  socks[1] = INVALID_SOCKET;

  return SOCKET_ERROR;
}


int peekConsoleRead(int sfd)
{
  DWORD sleep_time = 0;

  HANDLE h = sfd_to_handle(sfd);

  if (h == INVALID_HANDLE_VALUE)
  {
    error("can't get a handle for sfd [%d]", sfd);

    return 0;
  }
  
  FlushConsoleInputBuffer(h);
  
  for (;;)
  {
    INPUT_RECORD irec = {0};

    DWORD events_read = 0;

    int ret = PeekConsoleInput (h, &irec, 1, &events_read);

    if (!ret)
    {
      debug("PeekConsoleInput on sfd [%d] failed with error code [%d]",
                 sfd, GetLastError());
      return 0;
    }

    if (events_read && irec.EventType == KEY_EVENT)
    {
      break;
    }
    else if (events_read)
    {
      ReadConsoleInput (h, &irec, 1, &events_read);
    }

    Sleep (sleep_time >> 3);
    
    if (sleep_time < 80)
    {
      sleep_time++;
    }  
  }

  return 1;
}


int peekConsoleWrite(int sfd)
{
  return 1;
}


int peekPipeRead(int sfd)
{
  HANDLE h;

  DWORD n = 0;
  
  DWORD pFlags = 0;
  
  DWORD sleep_time = 0;
  
  int ret = 0;

  h = sfd_to_handle(sfd);

  if (h == INVALID_HANDLE_VALUE)
  {
    error("can't get a handle for sfd [%d]", sfd);
    
    return 0;
  } 

  ret = GetNamedPipeInfo(h, &pFlags, NULL, NULL, NULL);

  if (!ret)
  {
    error("GetNamedPipeInfo on sfd [%d] failed with error code [%d]",
              sfd, GetLastError());
    return 0;
  }

  for (;;)
  {
    ret = PeekNamedPipe (h, NULL, 0, NULL, &n, NULL);

    if (!ret)
    {
      error("PeekNamedPipe on sfd [%d] failed with error code [%d]",
                sfd, GetLastError());
      return 0;
    }

    if (n > 0)
    {
      break;
    }

    Sleep (sleep_time >> 3);
    
    if (sleep_time < 80)
    {
      sleep_time++;
    }  
  }

  return 1;
}


int peekPipeWrite(int sfd)
{
  return 1;
}


int selectSocketRead(int sfd)
{
  DBG_MSG("-> selectSocketRead(sfd = %d)...\n", sfd);
  
  int ret = 0;

  fd_set readsocks;
  
  struct timeval timeout = {1, 0};

  FD_ZERO(&readsocks);

  FD_SET((SOCKET) sfd_to_handle(sfd), &readsocks);

  
  DBG_MSG("selectSocketRead(sfd = %d) : readsocks.fd_count = %d\n", sfd, readsocks.fd_count);
  
  DBG_MSG("selectSocketRead(sfd = %d, socket = %d) : select...\n", 
              (int) sfd, (int) sfd_to_handle(sfd));
  
  while(ret == 0)
  {
    FD_ZERO(&readsocks);

    FD_SET((SOCKET) sfd_to_handle(sfd), &readsocks);

    ret = select(0, &readsocks, NULL, NULL, &timeout);
  }
  
  DBG_MSG("selectSocketRead(sfd = %d, socket = %d) : end select...\n", 
              (int) sfd, (int) sfd_to_handle(sfd));

  /*
   * Bail if select failed for some reason.
   */
  
  if (ret == SOCKET_ERROR)
  {
    error("select on sfd [%d] failed with error code [%d]",
              sfd, GetLastError());

    DBG_MSG("<- selectSocketRead(sfd = %d)...\n", sfd);

    return 0;
  }

  DBG_MSG("<- selectSocketRead(sfd = %d)...\n", sfd);
  
  return 1;
}


int selectSocketWrite(int sfd)
{
  DBG_MSG("-> selectSocketWrite(sfd = %d)...\n", sfd);
  
  int ret = 0;

  fd_set writesocks;
  
  struct timeval timeout = {1, 0};

  FD_ZERO(&writesocks);

  FD_SET((SOCKET) sfd_to_handle(sfd), &writesocks);

  DBG_MSG("selectSocketWrite(sfd = %d) : writesocks.fd_count = %d...\n", sfd, writesocks.fd_count);

  DBG_MSG("selectSocketWrite(sfd = %d, socket = %d) : select...\n", 
              (int) sfd, (int) sfd_to_handle(sfd));

  while (ret == 0)
  {
    FD_ZERO(&writesocks);

    FD_SET((SOCKET) sfd_to_handle(sfd), &writesocks);

    ret = select(0, NULL, &writesocks, NULL, &timeout);
  }
  
  DBG_MSG("selectSocketWrite(sfd = %d, socket = %d) : end select...\n", 
              (int) sfd, (int) sfd_to_handle(sfd));

  /*
   * Fail if select failed for some reason.
   */

  if (ret == SOCKET_ERROR)
  {
    error("select on sfd [%d] failed with error code [%d]",
              sfd, GetLastError());
          
    DBG_MSG("<- selectSocketWrite(sfd = %d)...\n", sfd);
          
    return 0;
  }

  DBG_MSG("<- selectSocketWrite(sfd = %d)...\n", sfd);
 
  return 1;
}


DWORD WINAPI selectThread( LPVOID lpParam )
{
  DBG_MSG("-> selectThread()...\n");
  
  DWORD dwWaitResult;

  thread_data_p thread_data;

  thread_data = (thread_data_p)lpParam;

  int sfd = thread_data -> sfd;
  int thread_no = thread_data -> thread_no;
  int test_type = thread_data -> test_type;

  debug2("starting thread [%i] for sfd [%i] with test type[%i]",
                  thread_no, sfd, test_type);

  while(1)
  {

    dwWaitResult = WaitForSingleObject(thread_data -> semaphore1, INFINITE);

    if (thread_data -> exit)
    {
      goto out;
    }  

    switch (dwWaitResult)
    {
      case WAIT_OBJECT_0:
      {
        switch(get_sfd_type(sfd))
        {
          case SFD_TYPE_FD:
          {
            break;
          }  
        
          case SFD_TYPE_SOCKET:
          {
            if (test_type == TEST_READ)
            {
              selectSocketRead(sfd);
            }  
            else
            {
              selectSocketWrite(sfd);
            }  
            
            break;
          }  
          
          case SFD_TYPE_PIPE:
          {  
            if (test_type == TEST_READ)
            {
              peekPipeRead(sfd);
            }  
            else
            {
              peekPipeWrite(sfd);
            }
            
            break;
          }  
         
          case SFD_TYPE_CONSOLE:
          {
            if (test_type == TEST_READ)
            {
              peekConsoleRead(sfd);
            }  
            else
            {
              peekConsoleWrite(sfd);
            }  
            
            break;
          }  
        }
      
        if (thread_data -> exit)
        {
          goto out;
        }  

        if (!ReleaseSemaphore(thread_data -> semaphore2, 1, NULL))
        {
          error("WaitForSingleObject in thread [%d] failed with error code [%d]",
                    thread_no, GetLastError());

          return 0;
        } 
          
        break;
      }  

      default:
      {
        error("ReleaseSemaphore in thread [%d] failed with error code [%d]",
                   thread_no, GetLastError());

        return 0;
      }
    }  
  }

  out:

  debug2("stopping thread [%i] for sfd [%i] with test type[%i]",
                  thread_no, sfd, test_type);

  thread_data -> exited = 1;

  DBG_MSG("<- selectThread()...\n");
  
  ExitThread(1);

  return 1;
}


int startSelectThread(int sfd, int test_type)
{
  DBG_MSG("-> startSelectThread(sfd = %d, test_type = %d)...\n", sfd, test_type);
  
  int thread_no = 0;
  
  int i;
  
  DWORD ID;

  for (i = 0; i < MAX_THREADS; i++)
  {
    if (thread_data_set[i] == NULL)
    {
      thread_no = i;
      
      break;
    }
  }

  if (thread_data_set[thread_no] != NULL)
  {
      fatal("MAX_THREADS exceed");
  }

  thread_data_set[thread_no] = (thread_data_p) HeapAlloc(GetProcessHeap(), 
                                                             HEAP_ZERO_MEMORY, 
                                                                 sizeof(thread_data_t));

  if (thread_data_set[thread_no] == NULL)
  {
    fatal("heap allocation failed with error code [%d]", GetLastError());
  }

  thread_data_set[thread_no] -> sfd       = sfd;
  thread_data_set[thread_no] -> thread_no = thread_no;
  thread_data_set[thread_no] -> test_type = test_type;
  thread_data_set[thread_no] -> signaled  = 0;
  thread_data_set[thread_no] -> exit      = 0;
  thread_data_set[thread_no] -> exited    = 0;

  thread_data_set[thread_no] -> semaphore1 = CreateSemaphore(NULL, 1, 1, NULL);

  if (thread_data_set[thread_no] -> semaphore1 == NULL)
  {
    fatal("CreateSemaphore failed with error code [%d]",
              GetLastError());
  }

  thread_data_set[thread_no] -> semaphore2 = CreateSemaphore(NULL, 0, 1, NULL);

  if (thread_data_set[thread_no] -> semaphore2 == NULL)
  {
    fatal("CreateSemaphore failed with error code [%d]", GetLastError());
  }

  thread_data_set[thread_no] -> thread = CreateThread(NULL, 0, selectThread, 
                                                        thread_data_set[thread_no],
                                                            0, &ID);

  thread_data_set[thread_no] -> thread_id = ID;


  if (thread_data_set[thread_no] -> thread == NULL)
  {
      fatal("CreateThread failed with error code [%d]", GetLastError());
  }

  DBG_MSG("<- startSelectThread(thread_no = %d)...\n", thread_no);

  return thread_no;
}


int cleanSelectThread(int thread_no)
{
  DBG_MSG("-> cleanSelectThread(thread_no = %d)...\n", thread_no);
  
  CloseHandle(thread_data_set[thread_no] -> semaphore1);
  CloseHandle(thread_data_set[thread_no] -> semaphore2);
  CloseHandle(thread_data_set[thread_no] -> thread);

  if(thread_data_set[thread_no] != NULL)
  {
    HeapFree(GetProcessHeap(), 0, thread_data_set[thread_no]);
   
    thread_data_set[thread_no] = NULL;
  }
  
  DBG_MSG("<- cleanSelectThread()...\n");
          
  return 1;
}


int WSHELPselect(int fds, fd_set* readsfds, fd_set* writesfds,
                     fd_set* exceptsfds, const struct timeval* timeout)
{
  DBG_MSG("-> WSHELPselect(fds = %d)...\n", fds);
  
  DWORD dwWaitResult;

  DWORD ms;

  unsigned int i;
  
  int count = 0;

  static int sfd_read_to_thread_map[MAX_THREADS] = {0};

  static int sfd_write_to_thread_map[MAX_THREADS] = {0};

  HANDLE semaphores[MAX_THREADS] = {NULL};

  int i_sem = 0;
  
  int semaphores_to_thread_map[MAX_THREADS] = {0};

  static unsigned int threads_count = 0;

  /*
   * 'except' should be implemented.
   */
   
  if (exceptsfds)
  {
    fatal("exceptsfds not implemented");
  }

  /*
   * convert timeout to ms or to INFINITE if null.
   */

  ms = timeout ? (DWORD) (timeout -> tv_sec * 1000) + (timeout -> tv_usec / 1000) : INFINITE;

  if (ms == 0 && timeout -> tv_usec)
  {
    ms = 1;
  }  

  /*
   * just wait if all set's are empty.
   */
   
  if (!readsfds && !writesfds && !exceptsfds)
  {
    HANDLE empty = NULL;

    dwWaitResult = WaitForSingleObject(empty, ms);

    switch (dwWaitResult)
    {
      case WAIT_OBJECT_0:
      { 
        errno = EINTR;

        DBG_MSG("<- WSHELPselect(fds = %d, ret = -1)...\n", fds);
            
        return -1;
      }  
            
      case WAIT_FAILED:
      {
        fatal("WaitForSingleObject failed with error code [%d]", GetLastError());
      }
      
      case WAIT_TIMEOUT:
      {      
        DBG_MSG("<- WSHELPselect(fds = %d, ret = 0)...\n", fds);
            
        return 0;
      }  
    }
  }

  /*
   * threads for read fds removed from set should be stopped.
   */
  
  DBG_MSG("WSHELPselect(fds = %d) : stopping threads for read fds "
            "removed from set...\n", fds);
  
  if (read_sfd_set.fd_count != 0)
  {
    for (i = 0; i < read_sfd_set.fd_count; ++i)
    {
      int sfd = (int) read_sfd_set.fd_array[i];
      
      if (!FD_ISSET(sfd, readsfds))
      {
        //int thread_no = thread_data_set[sfd_read_to_thread_map[sfd]] -> thread_no;

        //debug("WSHELPselect(fds = %d) :   stoping thread_no = %d for sfd = %d...\n", fds, thread_no, sfd);

        thread_data_set[sfd_read_to_thread_map[sfd]] -> exit = 1;

        FD_CLR((SOCKET) sfd, &read_sfd_set);

        sfd_read_to_thread_map[sfd] = -1;
      }
      //else
      //{
      //  debug("WSHELPselect(fds = %d) : i = %d : sfd = %d, FD_ISSET != 0...\n", fds, sfd);
      //}
    }
  }

  /*
   * threads for write fds removed from set should be stopped.
   */

  DBG_MSG("WSHELPselect(fds = %d) : stopping threads for write fds removed from set...\n", fds);
        
  if (write_sfd_set.fd_count != 0)
  {
    for (i = 0; i < write_sfd_set.fd_count; ++i)
    {
      int sfd = (int) write_sfd_set.fd_array[i];
      
      if (!FD_ISSET(sfd, writesfds))
      {
        //int thread_no = thread_data_set[sfd_read_to_thread_map[sfd]] -> thread_no;
        
        //debug("WSHELPselect(fds = %d) :   stopping thread_no = %d for sfd = %d...\n", fds, thread_no, sfd);

        thread_data_set[sfd_write_to_thread_map[sfd]] -> exit = 1;
        
        FD_CLR((SOCKET) sfd, &write_sfd_set);
        
        sfd_write_to_thread_map[sfd] = -1;
      }
      //else
      //{
      //  debug("WSHELPselect(fds = %d) : i = %d : sfd = %d, FD_ISSET != 0...\n", fds, sfd);
      //}
    }
  }

  DBG_MSG("WSHELPselect(fds = %d) : Weaking up threads signaled in previous run...\n", fds);

  for (i = 0; i < MAX_THREADS; i++)
  {
    /*
     * threads signaled in previous run should be waken up.
     */
  
    if (thread_data_set[i] != NULL && thread_data_set[i] -> signaled == 1)
    {
      if (!ReleaseSemaphore(thread_data_set[i] -> semaphore1, 1, NULL))
      {
        fatal("ReleaseSemaphore failed with error code [%d]", GetLastError());
      }
    
      thread_data_set[i] -> signaled = 0;
    }
     
    /*
     * Cleaning after exited threads.
     */
    
    if (thread_data_set[i] != NULL && thread_data_set[i] -> exited == 1)
    {
      cleanSelectThread(i);

      threads_count--;
    }
  }

  /*
   * new thread should be started for each new read fd.
   */

  DBG_MSG("WSHELPselect(fds = %d) : Starting new thread for each new read fd...\n", fds);
  
  if (readsfds != NULL && readsfds -> fd_count != 0)
  {
    for (i = 0; i < readsfds -> fd_count; ++i)
    {
      int sfd = (int) readsfds -> fd_array[i];
      
      if (!FD_ISSET(sfd, &read_sfd_set))
      {
        int thread_no = startSelectThread(sfd, TEST_READ);
        
        //debug("WSHELPselect(fds = %d) :   Starting read thread (thread_no = %d) for sfd = %d...\n",
        //          fds, thread_no, sfd);
        
        read_sfd_set_add(sfd);
        
        sfd_read_to_thread_map[sfd] = thread_no;
        
        threads_count++;
      }
    }
  }

  /*
   * New thread should be started for each new write fd.
   */

  DBG_MSG("WSHELPselect(fds = %d) : Starting new thread for each new write fd...\n", fds);
  
  if (writesfds != NULL && writesfds -> fd_count != 0)
  {
    for (i = 0; i < writesfds -> fd_count; ++i)
    {
      int sfd = (int) writesfds -> fd_array[i];
   
      if (!FD_ISSET(sfd, &write_sfd_set))
      {
        int thread_no = startSelectThread(sfd, TEST_WRITE);
        
        //debug("WSHELPselect(fds = %d) :   Starting write thread (thread_no = %d) for sfd = %d...\n",
        //          fds, thread_no, sfd);

        
        write_sfd_set_add(sfd);
        
        sfd_write_to_thread_map[sfd] = thread_no;
        
        threads_count++;
      }
    }
  }

  /*
   * constructing array of semaphores for working threads
   * new array is needed because in threads map we can have
   * threads which should exit right now.
   */

  DBG_MSG("WSHELPselect(fds = %d) : constructing array of semaphores for working threads...\n", fds);

  for (i = 0; i < MAX_THREADS; i++)
  {
    if (thread_data_set[i] != NULL && !thread_data_set[i] -> exit )
    {
      semaphores[i_sem] = thread_data_set[i] -> semaphore2;

      semaphores_to_thread_map[i_sem] = i;
      
      i_sem++;
    }

  }

  /*
   * wait for signal from threads.
   */
   
  #ifdef DEBUG
  
  {
    char str[256] = "{";
    char tmp[32]  = "";
    
    for (i = 0; i < read_sfd_set.fd_count; ++i)
    {
      int sfd = (int) read_sfd_set.fd_array[i];
      
      sprintf(tmp, " %d", sfd);
      
      strcat(str, tmp);
    }
    
    strcat(str, " }");
    
    debug("read_sfd_set = %s", str);
  
    /*
     *
     */
  
    str[0] = '{';
    str[1] = '\0';
    
    for (i = 0; i < write_sfd_set.fd_count; ++i)
    {
      int sfd = (int) write_sfd_set.fd_array[i];
      
      sprintf(tmp, " %d", sfd);
      
      strcat(str, tmp);
    }
    
    strcat(str, " }");
    
    debug("write_sfd_set = %s", str);
  }
  
  #endif
  
  
  DBG_MSG("WSHELPselect(fds = %d) : Waiting for signal from threads...\n", fds);

  DBG_MSG("i_sem = %d\n", i_sem);
  
  dwWaitResult = WaitForMultipleObjects(i_sem, semaphores, FALSE, ms);

  //debug("WSHELPselect(fds = %d) :   FD_ZERO(readsfds)...\n", fds);
  
  if (readsfds) FD_ZERO(readsfds);
  
  //debug("WSHELPselect(fds = %d) :   FD_ZERO(writesfds)...\n", fds);
  
  if (writesfds) FD_ZERO(writesfds);
  
  //debug("WSHELPselect(fds = %d) :   FD_ZERO(exceptsfds)...\n", fds);
  
  if (exceptsfds) FD_ZERO(exceptsfds);

  switch (dwWaitResult)
  {
    case WAIT_FAILED:
    {
      fatal("WaitForMultipleObjects failed with error code [%d]", GetLastError());
    }
      
    case WAIT_TIMEOUT:
    {
      DBG_MSG("<- WSHELPselect(fds = %d, ret = 0)...\n", fds);
     
      return 0;
    }   
  }

  /*
   * Prepare return fd sets with signaled fd's.
   */

  //debug("WSHELPselect(fds = %d) : preparing return fd sets with signaled fd's...\n", fds);
  
  for (i = 0; i<MAX_THREADS; i++)
  {
    if (dwWaitResult == WAIT_OBJECT_0 + i)
    {
      int thread_no = semaphores_to_thread_map[i];
      
      if (thread_data_set[thread_no] -> test_type == TEST_READ)
      {
        FD_SET((SOCKET) thread_data_set[thread_no] -> sfd, readsfds);
        
        DBG_MSG("WSHELPselect(fds = %d) :   "
                       "thread_no = %d, sfd = %d, readsfds = %d...\n", 
                           fds, thread_no,
                               thread_data_set[thread_no] -> sfd, (int) readsfds);
      }
      else
      {
        FD_SET((SOCKET) thread_data_set[thread_no] -> sfd, writesfds);
        
        DBG_MSG("WSHELPselect(fds = %d) :   "
                       "thread_no = %d, sfd = %d, readsfds = %d...\n", 
                           fds, thread_no, 
                               thread_data_set[thread_no] -> sfd, (int) writesfds);
      }  

      count ++;

      thread_data_set[thread_no] -> signaled = 1;
    }
  }

  DBG_MSG("<- WSHELPselect(fds = %d, ret = %d)...\n", fds, count);
  
  return count;
}

/*
 * IO functions.
 */

int WSHELPread(int sfd, char *dst, unsigned int max)
{
  DBG_MSG("-> WSHELPread(sfd = %d)...\n", sfd);

  SOCKET sock;

  int ret = -1;

  switch(get_sfd_type(sfd))
  {
    case SFD_TYPE_SOCKET:
    {
      /*
       * Clear errno.
       */
      
      errno = 0;

      /*
       * Get the SOCKET.
       */
      
      sock = (SOCKET) sfd_to_handle(sfd);

      /*
       * Call the underlying function.
       */
      
      ret = recv(sock, dst, max, 0);

      if (FD_ISSET(sfd, &debug_sfds))
      {
        if (ret > 0)
        {
          dst[ret] = '\0';

          debug("read[%d]: %s", sfd, dst);
        }
      }

      if (ret < 0)
      {
        debug("read from socket sfd [%d] failed with error code [%d]",
                  sfd, GetLastError());
      }

      /*
       * Check for errors.
       */
      
      if (ret == SOCKET_ERROR)
      {
        errno = getWSAErrno();
        
        DBG_MSG("WSHELPread(sfd = %d) : SOCKET_ERROR...\n", sfd);

        DBG_MSG("<- WSHELPread(sfd = %d, ret = -1)...\n", sfd);
        
        return -1;
      }

      break;
    }
    
    case SFD_TYPE_FD:
    case SFD_TYPE_PIPE:
    case SFD_TYPE_CONSOLE:
    {
      ret = _read(sfd_to_fd(sfd), dst, max);
      
      if (FD_ISSET(sfd_to_fd(sfd), &debug_sfds))
      {
        if (ret > 0)
        {
          dst[ret] = '\0';

          debug("read[%d] len %d: %s", sfd_to_fd(sfd), ret, dst);
        }
      }

      if (ret < 0)
      {
        error("read from pipe/console sfd [%d] failed with error code [%d]",
                  sfd, GetLastError());
      }

      break;
    }  
  }

  DBG_MSG("<- WSHELPread(sfd = %d, ret = %d)...\n", sfd, ret);
  
  return ret;
}

int WSHELPwrite(int sfd, const char *buf, unsigned int max)
{
  DBG_MSG("-> WSHELPwrite(sfd = %d)...\n", sfd);
  
  SOCKET sock;
  
  int ret = -1;

  switch(get_sfd_type(sfd))
  {
    case SFD_TYPE_SOCKET:
    {
      /*
       * Clear errno.
       */
      
      errno = 0;

      /*
       * Get the SOCKET.
       */
      
      sock = (SOCKET) sfd_to_handle(sfd);

      if (FD_ISSET(sfd, &crlf_sfds) && max == 1 && buf[0] == 13)
      {
        /*
         * FIXME: We're getting CR's (13) instead of CR + LF or just LF, 
         * either of which would work.
         */
        
        char locbuf[1] = {10};

        ret = send(sock, locbuf, 1, 0);
      }
      else
      {
        /*
         * Call the underlying function.
         */
        
        ret = send(sock, buf, max, 0);
      }

      if (FD_ISSET(sfd, &debug_sfds))
      {
        if (ret > 0)
        {
          static int writecount = 0;
          
          char *locbuf = malloc(max + 1);
          
          memcpy(locbuf, buf, max);

          locbuf[max] = '\0';

          writecount += max;

          debug("write[%d] len %d: %s", sfd, max, locbuf);
          
          if (max == 1)
          {
            debug("write[%d] one char: %08x", sfd, locbuf[0]);
          }
          
          free(locbuf);
        }
      }

      if (ret < 0)
      {
        /*
         * write error only if failed sfd is not a stderr (2).
         */

        if (sfd != 2)
        {
          error("write to socket sfd [%d] failed with error code [%d]",
                    sfd, GetLastError());

          DBG_MSG("<- WSHELPwrite(sfd = %d, ret = -1)...\n", sfd);
        }

        exit(-1);
      }

      /*
       * Check for errors.
       */
      
      if (ret == SOCKET_ERROR)
      {
        errno = getWSAErrno();

        DBG_MSG("WSHELPwrite(sfd = %d) : SOCKET_ERROR...\n", sfd);

        DBG_MSG("<- WSHELPwrite(sfd = %d, ret = -1)...\n", sfd);

        return -1;
      }
      break;
    }  

    case SFD_TYPE_FD:
    case SFD_TYPE_PIPE:
    case SFD_TYPE_CONSOLE:
    {
      ret = _write(sfd_to_fd(sfd), buf, max);
      
      if (FD_ISSET(sfd_to_fd(sfd), &debug_sfds))
      {
        if (ret > 0)
        {
          char *locbuf = malloc(max + 1);
         
          memcpy(locbuf, buf, max);

          locbuf[max] = '\0';
          
          debug("write[%d]: %s", sfd_to_fd(sfd), locbuf);
          
          free(locbuf);
        }
      }

      if (ret < 0)
      {
        /*
         * write error only if failed sfd is not a stderr (2).
         */
  
        if (sfd != 2)
        {
          error("write to pipe/console sfd [%d] failed with error code [%d]",
                    sfd, GetLastError());
        }
      }
      
      break;
    }  
  }

  DBG_MSG("<- WSHELPwrite(sfd = %d, ret = %d)...\n", sfd, ret);
  
  return ret;
}


int WSHELPclose(int sfd)
{
  DBG_MSG("-> WSHELPclose(sfd = %d)...\n", sfd);
  
  int i;
  
  int socketInUse = 0;
  
  SOCKET sock;
  
  int ret = -1;

  switch(get_sfd_type(sfd))
  {
    case SFD_TYPE_SOCKET:
    {
      /*
       * Clear errno.
       */
      
      errno = 0;

      /*
       * Get the SOCKET.
       */
      
      sock = (SOCKET) sfd_to_handle(sfd);
     
      if (sock == INVALID_SOCKET)
      {
        errno = EBADF;
               
        DBG_MSG("WSHELPclose(sfd = %d) : INVALID_SOCKET...\n", sfd);

        DBG_MSG("<- WSHELPclose(sfd = %d, ret = -1)...\n", sfd);
               
        return -1;
      }

      /*
       * Remove cookie in SocketCookieMap var (for AF_UNIX only).
       */
      
      for (i = 0; i < SFD_MAP_SIZE; i++)
      {
        /*
         * Find socket in table.
         */
        
        if (SocketCookieMap[i].socket == sock)
        {
          /*
           * Remove cookie.
           */
          
          SocketCookieMap[i].socket = 0;

          if (SocketCookieMap[i].cookie)
          {
            free(SocketCookieMap[i].cookie);
          }
          
          if (SocketCookieMap[i].f)
          {
            fclose(SocketCookieMap[i].f);
          }
          
          break;
        }
      }

      /*
       * Test is socket in use by another sfd?
       */

      socketInUse = 0;

      i = 0;
      
      while(!socketInUse && i < SFD_MAP_SIZE)
      {
        //DBG_MSG("%d |-> %d ? %d\n", i, sfd_to_handle(i), sock);
        
        if (((int) sfd_to_handle(i) == (int) sock) && (i != (int) sfd))
        {
          socketInUse = 1;
        }

        i++;
      }
      
      /*
       * Call the underlying function.
       */

      if (!socketInUse)
      {
        DBG_MSG("Closing socket %d\n", sock);
      
        ret = closesocket(sock);
      }
      else
      {
        DBG_MSG("Socket %d in use.\n", sock);
        
        ret = 0;
      }

      /*
       * Remove mapping table entry.
       */
      
      free_sfd(sfd);

      /*
       * Check for errors.
       */
      
      if (ret == SOCKET_ERROR)
      {
        errno = getWSAErrno();
              
        DBG_MSG("WSHELPclose(sfd = %d) : SOCKET_ERROR...\n", sfd);

        DBG_MSG("<- WSHELPclose(sfd = %d, ret = -1)...\n", sfd);
              
        return -1;
      }
      
      break;
    }  
    
    case SFD_TYPE_FD:
    case SFD_TYPE_PIPE:
    case SFD_TYPE_CONSOLE:
    {
      ret = _close(sfd_to_fd(sfd));

      free_sfd(sfd);

      break;
    }  
  }

  DBG_MSG("<- WSHELPclose(sfd = %d, ret = %d)...\n", sfd, ret);
  
  return ret;
}


/*
 * Internal functions.
 */

void WSHELPinitialize()
{
  DBG_MSG("-> WSHELPinitialize()...\n");
  
  WORD wVersionRequested;
  
  WSADATA wsaData;
  
  int err;

  wVersionRequested = MAKEWORD(2, 2);

  if (WSAStartup(wVersionRequested, &wsaData))
  {  
    fatal("ERROR: Cannot initialize WinSock DLL.");
  }  

  /*
   * Confirm that the WinSock DLL supports 2.2. 
   * Note that if the DLL supports versions greater   
   * than 2.2 in addition to 2.2, it will still return
   * 2.2 in wVersion since that is the version we     
   * requested.
   */
  
  if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
  {
    fatal("ERROR: WinSock 2.2 needed.");
  }

  /*
   * The WinSock DLL is acceptable. Proceed.
   */
  
  winsock_initialized = 1;

  DBG_MSG("<- WSHELPinitialize()...\n");
}


void allocate_standard_descriptor(int fd)
{
  DBG_MSG("-> allocate_standard_descriptor(fd = %d)...\n", fd);
  
  allocate_sfd(fd);
  
  DBG_MSG("<- allocate_standard_descriptor()...");
}
