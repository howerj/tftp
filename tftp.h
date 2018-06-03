#ifndef TFTP_H
#define TFTP_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>

#define TFTP_DEFAULT_PORT  (69u)
#define TFTP_BUFFER_LENGTH (520u)
#define TFTP_DEFAULT_RETRY (5u)
#define TFTP_SLEEP_MS      (10u)
#define TFTP_TIME_OUT_MS   (1000u * 3u)

/**@todo replace 'void*' with typedefs, perhaps with opaque pointers */

typedef int socket_t;

typedef struct {
	char *name;
	uint16_t port;
	socket_t fd;
	void *info;
} tftp_socket_t;

typedef struct {
	void *addr;
	size_t length;
} tftp_addr_t;

typedef void * (*tftp_fopen_t)(void *file, bool read);
typedef size_t (*tftp_fread_t)(void *file, uint8_t *data, size_t length);
typedef size_t (*tftp_fwrite_t)(void *file, uint8_t *data, size_t length);
typedef int    (*tftp_fclose_t)(void *file);

typedef tftp_socket_t (*tftp_nopen_t)(char *host, uint16_t port);
/**@todo Read should accept IP field as well as port? */
typedef long     (*tftp_nread_t)(tftp_socket_t *socket, uint8_t *data, size_t length, uint16_t *port);
typedef long     (*tftp_nwrite_t)(tftp_socket_t *socket, uint8_t *data, size_t length);
typedef int      (*tftp_nclose_t)(tftp_socket_t *socket);
typedef int      (*tftp_nconnect_t)(tftp_socket_t *socket, tftp_addr_t *addr);

typedef int      (*tftp_logger_t)(void *logger, char *fmt, va_list arg);

typedef uint64_t (*tftp_time_ms_t)(void);
typedef void     (*tftp_wait_ms_t)(uint64_t ms);

typedef struct {
	char *file_name;
	tftp_socket_t server;

	void *file;
	void *log;
	bool read;
	bool log_on;
	uint8_t buffer[TFTP_BUFFER_LENGTH];
	unsigned retry;

	tftp_fopen_t  fopen;
	tftp_fread_t  fread;
	tftp_fwrite_t fwrite;
	tftp_fclose_t fclose;

	tftp_nopen_t  nopen;
	tftp_nread_t  nread;
	tftp_nwrite_t nwrite;
	tftp_nclose_t nclose;
	tftp_nconnect_t nconnect;

	tftp_logger_t  logger;
	tftp_time_ms_t time_ms;
	tftp_wait_ms_t wait_ms;
} tftp_t;

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
} tftp_error_e;



#endif
