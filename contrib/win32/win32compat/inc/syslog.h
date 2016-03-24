#pragma once


/* Compatibility header to give us some syslog-like functionality on Win32 */

#define LOG_CRIT	(2)				/* critical */
#define LOG_ERR		(3)				/* errors */
#define LOG_WARNING	(4)				/* warnings */
#define	LOG_INFO	(6)				/* informational */
#define LOG_DEBUG	(7)				/* debug messages */
#define LOG_USER	(1 << 3)		/* user level messages */
#define LOG_DAEMON	(3 << 3)		/* daemons/servers */
#define LOG_AUTH	(4 << 3)		/* security messages */
#define LOG_LOCAL0	(16 << 3)		/* reserved for local use */
#define LOG_LOCAL1	(17 << 3)		/* reserved for local use */
#define LOG_LOCAL2	(18 << 3)		/* reserved for local use */
#define LOG_LOCAL3	(19 << 3)		/* reserved for local use */
#define LOG_LOCAL4	(20 << 3)		/* reserved for local use */
#define LOG_LOCAL5	(21 << 3)		/* reserved for local use */
#define LOG_LOCAL6	(22 << 3)		/* reserved for local use */
#define LOG_LOCAL7	(23 << 3)		/* reserved for local use */

#define LOG_PID		0x01			/* log the pid */

void openlog	(char *, unsigned int, int);
void closelog	(void);
void syslog		(int, const char *, const char *);

