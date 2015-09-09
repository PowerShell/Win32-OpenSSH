#ifndef _SFDS_H_
#define _SFDS_H_ 1

/* Types */

typedef int sfd_type;

#define SFD_TYPE_NONE       0
#define SFD_TYPE_FD         1
#define SFD_TYPE_SOCKET     2
#define SFD_TYPE_PIPE       3
#define SFD_TYPE_CONSOLE    4

#define SFD_MAP_SIZE        256
#define SFD_FD_INVALID     -1
#define SFD_HANDLE_INVALID -1

/*
 * Struct for compatibility with AF_UNIX socket.
 * Bind() and connect() should receive pointer to this struct.
 */
 
#define UNIX_PATH_LEN 108

typedef unsigned short uint16_t;
typedef uint16_t sa_family_t;

struct sockaddr_un
{
  sa_family_t sun_family;         /* address family AF_LOCAL/AF_UNIX */
  char sun_path[UNIX_PATH_LEN];   /* 108 bytes of socket address     */
};

/* For a real fd or SOCKET, allocate an sfd */
int allocate_sfd(int fd_or_handle);

/* Free an sfd from the map */
void free_sfd(int sfd);

/* For a real fd or SOCKET, get our sfd */
int fd_to_sfd(int fd_or_socket);

/* For an sfd, get the real fd behind it */
int sfd_to_fd(int sfd);

/* For an sfd, get the real handle behind it */
HANDLE sfd_to_handle(int sfd);

/* For an sfd, get the type */
int get_sfd_type(int sfd);

/*  Check if sfd is file */
int sfd_is_fd(int sfd);

/* Check if sfd is socket */
int sfd_is_socket(int sfd);

/* Check if sfd is pipe */
int sfd_is_pipe(int sfd);

/* Check if sfd is console */
int sfd_is_console(int sfd);

/* Check if sfd is file or console */
int sfd_is_fd_or_console(int sfd);

/* Check if sfd is socket or pipe */
int sfd_is_socket_or_pipe(int sfd);

void sfd_replace_handle(int sfd, HANDLE handle);

#endif
