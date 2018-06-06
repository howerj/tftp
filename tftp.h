#ifndef TFTP_H
#define TFTP_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

#define TFTP_DEFAULT_PORT  (69u)
#define TFTP_DEFAULT_RETRY (5u)
#define TFTP_SLEEP_MS      (10u)
#define TFTP_TIME_OUT_MS   (1000u * 3u)

/* See: <https://en.wikipedia.org/wiki/X_Macro> */
#define TFTP_FUNCTIONS_XMACRO\
	X(fopen) X(fread) X(fwrite) X(fclose)\
	X(nopen) X(nread) X(nwrite) X(nclose) X(nconnect) X(nbind)\
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
	const char *name;        /**< host name socket is communicating with */
	uint16_t port;     /**< host port we are communicating with */
	socket_t fd;       /**< file descriptor for socket */
	tftp_addr_t *info; /**< for address information returned in tftp_nread_t functions */
} tftp_socket_t;

typedef enum {
	TFTP_ERR_OK       =  0, /**< zero or a *positive number will be returned */
	TFTP_ERR_NO_BLOCK = -1, /**< a non-blocking call did not block, try again later */
	TFTP_ERR_FAILED   = -2, /**< the call failed */
} tftp_callback_status_e;

typedef file_t (*tftp_fopen_t)(char *file, bool read);
typedef long   (*tftp_fread_t)(file_t file, uint8_t *data, size_t length);
typedef long   (*tftp_fwrite_t)(file_t file, uint8_t *data, size_t length);
typedef int    (*tftp_fclose_t)(file_t file);

/**@todo Add validate function for server? */

typedef tftp_socket_t (*tftp_nopen_t)(const char *host, uint16_t port, bool bind);
/**@todo Read should accept host field as well as port? */
typedef long     (*tftp_nread_t)(tftp_socket_t *socket, uint8_t *data, size_t length);
typedef long     (*tftp_nwrite_t)(tftp_socket_t *socket, const uint8_t *data, size_t length);
typedef int      (*tftp_nclose_t)(tftp_socket_t *socket);
typedef int      (*tftp_nconnect_t)(tftp_socket_t *socket, tftp_addr_t *addr);
typedef int      (*tftp_nbind_t)(tftp_socket_t *socket, const char *device, uint16_t port);
typedef uint16_t (*tftp_nport_t)(tftp_socket_t *socket); /**< port of latest received message */
typedef void     (*tftp_nhost_t)(tftp_socket_t *socket, char ip[static 64]); /**< host name of latest received message */

typedef int      (*tftp_logger_t)(void *logger, char *fmt, va_list arg);

typedef uint64_t (*tftp_time_ms_t)(void);
typedef void     (*tftp_wait_ms_t)(uint64_t ms);
typedef int      (*tftp_chdir_t)(const char *path);

typedef struct {
#define X(FUNCTION) tftp_ ## FUNCTION ## _t FUNCTION ;
TFTP_FUNCTIONS_XMACRO
#undef X
} tftp_functions_t;

struct tftp_t;
typedef struct tftp_t tftp_t;

/**@todo string lookup functions for tftp_opcode_e */

typedef enum {
	tftp_op_rrq   = 1, /**< Read request */
	tftp_op_wrq   = 2, /**< Write request */
	tftp_op_data  = 3, /**< Data packet */
	tftp_op_ack   = 4, /**< Acknowledge data packet */
	tftp_op_error = 5, /**< Error packet */
} tftp_opcode_e;

typedef enum {
	tftp_error_unknown             = 0, /**< Not defined, see error message (if any). */
	tftp_error_file_not_found      = 1, /**< File not found. */
	tftp_error_access_violation    = 2, /**< Access violation. */
	tftp_error_disk_full           = 3, /**< Disk full or allocation exceeded. */
	tftp_error_illegal_operation   = 4, /**< Illegal TFTP operation. */
	tftp_error_unknown_id          = 5, /**< Unknown transfer ID. */
	tftp_error_file_already_exists = 6, /**< File already exists. */
	tftp_error_no_such_user        = 7, /**< No such user. */
	tftp_LAST_ERROR, /**< NOT AN ERROR CODE, MUST BE LAST ENUM VALUE*/
} tftp_error_e;

tftp_t *tftp_new(logger_t log);
void    tftp_free(tftp_t *t);
const char *tftp_error_lookup(uint16_t e);
int tftp(char *file, char *host, uint16_t port, bool read);
int tftp_reader(tftp_t *t);

#if !defined(__unix__) && !defined(_WIN32)
#error Unsupported Operating System
#else
/* NB. These operating system specific functions are selected by the build system */
extern const tftp_functions_t tftp_os_specific_functions;
#endif


#endif
