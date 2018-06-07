/**@brief Embeddable and Non-Blocking TFTP server client
 * @author Richard James Howe
 * @license MIT
 * @copyright Richard James Howe (2018)
 * @email howe.r.j.89@gmail.com
 * @repository <https://github.com/howerj/tftp> */
#ifndef TFTP_H
#define TFTP_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

/* See: <https://en.wikipedia.org/wiki/X_Macro> */
#define TFTP_FUNCTIONS_XMACRO\
	X(fopen) X(fread) X(fwrite) X(fclose)\
	X(nopen) X(nread) X(nwrite) X(nclose) X(nconnect)\
        X(nport) X(nhost) \
        X(chdir) \
	X(logger)\
	X(time_ms)\
	X(wait_ms)

typedef int socket_t; /**< Most socket libraries use an integer as a socket file descriptor */
typedef FILE *file_t;   /**< file object, on a hosted platform this will not have to change */
typedef FILE *logger_t; /**< logging object, on a hosted platform this can be a FILE handle */

struct tftp_addr_t;
typedef struct tftp_addr_t tftp_addr_t;

typedef struct {
	const char *name;  /**< host name socket is communicating with */
	uint16_t port;     /**< host port we are communicating with */
	socket_t fd;       /**< file descriptor for socket */
	tftp_addr_t *info; /**< for address information returned in tftp_nread_t functions */
} tftp_socket_t;

typedef enum {
	TFTP_ERR_OK       =  0, /**< zero or a *positive number will be returned */
	TFTP_ERR_NO_BLOCK = -1, /**< a non-blocking call did not block, try again later */
	TFTP_ERR_FAILED   = -2, /**< the call failed */
} tftp_function_error_e;

typedef file_t (*tftp_fopen_t)(char *file, bool read);
typedef long   (*tftp_fread_t)(file_t file, uint8_t *data, size_t length);
typedef long   (*tftp_fwrite_t)(file_t file, uint8_t *data, size_t length);
typedef int    (*tftp_fclose_t)(file_t file);

/**@todo Add validate function for server? And get logging object? */


typedef tftp_socket_t (*tftp_nopen_t)(const char *host, uint16_t port, bool bind);
typedef long     (*tftp_nread_t)(tftp_socket_t *socket, uint8_t *data, size_t length);
typedef long     (*tftp_nwrite_t)(tftp_socket_t *socket, const uint8_t *data, size_t length);
typedef int      (*tftp_nclose_t)(tftp_socket_t *socket);
typedef int      (*tftp_nconnect_t)(tftp_socket_t *socket, tftp_addr_t *addr);
typedef uint16_t (*tftp_nport_t)(tftp_socket_t *socket);                     /**< port of latest received message */
typedef void     (*tftp_nhost_t)(tftp_socket_t *socket, char ip[static 64]); /**< host name of latest received message */

typedef int      (*tftp_logger_t)(void *logger, char *fmt, va_list arg);

typedef uint64_t (*tftp_time_ms_t)(void);           /**< return monotonically increasing time in milliseconds */
typedef void     (*tftp_wait_ms_t)(uint64_t ms);    /**< sleep for 'ms' milliseconds */
typedef int      (*tftp_chdir_t)(const char *path); /**< change current working directory to 'path' */

typedef struct {
#define X(FUNCTION) tftp_ ## FUNCTION ## _t FUNCTION ;
TFTP_FUNCTIONS_XMACRO
#undef X
} tftp_functions_t; /**< A structure containing all of the function pointers needed for the TFTP server/client */

struct tftp_t;                /**< Opaque object containing a TFTP client connection object */
typedef struct tftp_t tftp_t; /**< Opaque object typedef for a TFTP client connection object */

/* Currently the only supported operating systems are ones with either a POSIX 
 * socket library or Windows, although it should be easy to port to a new
 * platform, only a handful of functions have to be supported. */
#if !defined(__unix__) && !defined(_WIN32)
#error Unsupported Operating System
#else
/* NB. These operating system specific functions are selected by the build system */
extern const tftp_functions_t tftp_os_specific_functions;
#endif


#endif
