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

typedef enum {
	tftp_op_rrq   = 1, /**< Read request */
	tftp_op_wrq   = 2, /**< Write request */
	tftp_op_data  = 3, /**< Data packet */
	tftp_op_ack   = 4, /**< Acknowledge data packet */
	tftp_op_error = 5, /**< Error packet */
} tftp_opcode_e; /**< TFTP packets all have an Op Code field that decides what the packet is */

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
} tftp_error_e; /**< An enumeration for all potential TFTP errors */

typedef enum {
	/* All messages contain an Opcode field */
	HD_OP_HI = 0, /**< Opcode High Byte, always present, always zero */
	HD_OP_LO = 1, /**< Opcode Low  Byte, always present */

	/* For ACK and DATA messages */
	HD_BLOCK_NUMBER_HI = 2, /**< Block Number High Byte */
	HD_BLOCK_NUMBER_LO = 3, /**< Block Number Low  Byte */

	/* For Error messages */
	HD_ERROR_CODE_HI   = 2, /**< Error Code High Byte */
	HD_ERROR_CODE_LO   = 3, /**< Error Code Low  Byte */
	HD_ERROR_MSG_START = 4, /**< Start of NUL terminated ASCIIZ string, if any, for an error message */

	/* For RRQ and WRQ op codes */
	HD_FILE_NAME_START = 2, /**< Start of NUL terminated ASCIIZ string for file-name RRQ/WWQ operations */

	/* For DATA messages only */
	HD_DATA_START      = 4, /**< Start of data packet (0-512 bytes) in DATA message */
} tftp_header_e; /**< TFTP header field offsets (opcode dependent) */

/**@brief This X-Macro is used to define a list of functionality that a
 * given platform needs to support in order for the generic TFTP code
 * defined in 'tftp.c' to work.
 *
 * See: <https://en.wikipedia.org/wiki/X_Macro> */
#define TFTP_FUNCTIONS_XMACRO\
	X(fopen) X(fread) X(fwrite) X(fclose)\
	X(nopen) X(nread) X(nwrite) X(nclose) X(nconnect)\
        X(nport) X(nhost) \
        X(chdir) \
	X(logger)\
	X(time_ms)\
	X(quit)\
	X(wait_ms)

/**@brief an X-Macro for the logging levels */
#define TFTP_LOG_LEVELS_XMACRO\
	X(ALL_OFF)\
	X(FATAL)\
	X(ERROR)\
	X(WARNING)\
	X(INFO)\
	X(DEBUG)\
	X(ALL_ON)

typedef enum {
#define X(LEVEL) TFTP_LOG_LEVEL_ ## LEVEL,
	TFTP_LOG_LEVELS_XMACRO
	TFTP_LOG_LEVEL_LAST_LOG_LEVEL /**< Not a valid log level, marker for last log level! */
#undef X
} tftp_log_levels_e; /**< enumeration of all logging levels */

typedef int socket_t; /**< Most socket libraries use an integer as a socket file descriptor */
typedef FILE *file_t;   /**< file object, on a hosted platform this will not have to change */
typedef FILE *logger_t; /**< logging object, on a hosted platform this can be a FILE handle */

struct tftp_addr_t; /**< For containing information for where messages came from/go to */
typedef struct tftp_addr_t tftp_addr_t; /**< Typedef for the opaque struct tftp_addr_t */

typedef struct {
	const char *name;  /**< host name socket is communicating with */
	uint16_t port;     /**< host port we are communicating with */
	socket_t fd;       /**< file descriptor for socket */
	tftp_addr_t *info; /**< for address information returned in tftp_nread_t functions */
} tftp_socket_t; /**< Object used to abstract out network connections */

typedef enum {
	TFTP_ERR_OK       =  0, /**< zero or a *positive number will be returned */
	TFTP_ERR_NO_BLOCK = -1, /**< a non-blocking call did not block, try again later */
	TFTP_ERR_FAILED   = -2, /**< the call failed */
} tftp_function_error_e;

typedef file_t   (*tftp_fopen_t)(char *file, bool read);
typedef long     (*tftp_fread_t)(file_t file, uint8_t *data, size_t length);
typedef long     (*tftp_fwrite_t)(file_t file, uint8_t *data, size_t length);
typedef int      (*tftp_fclose_t)(file_t file);
typedef tftp_socket_t (*tftp_nopen_t)(const char *host, uint16_t port, bool bind);
typedef long     (*tftp_nread_t)(tftp_socket_t *socket, uint8_t *data, size_t length);
typedef long     (*tftp_nwrite_t)(tftp_socket_t *socket, const uint8_t *data, size_t length);
typedef int      (*tftp_nclose_t)(tftp_socket_t *socket);
typedef int      (*tftp_nconnect_t)(tftp_socket_t *socket, tftp_addr_t *addr);
typedef uint16_t (*tftp_nport_t)(tftp_socket_t *socket);                     /**< port of latest received message */
typedef void     (*tftp_nhost_t)(tftp_socket_t *socket, char ip[static 64]); /**< host name of latest received message */
typedef int      (*tftp_logger_t)(logger_t logger, char *fmt, va_list arg);
typedef uint64_t (*tftp_time_ms_t)(void);           /**< return monotonically increasing time in milliseconds */
typedef void     (*tftp_wait_ms_t)(uint64_t ms);    /**< sleep for 'ms' milliseconds */
typedef int      (*tftp_chdir_t)(const char *path); /**< change current working directory to 'path' */
typedef bool     (*tftp_quit_t)(void);              /**< quit? */

/**@brief 'tftp_functions_t' contains an example use of an X-Macro, it is used
 * for limited code generation and to ensure tables of things are kept in sync,
 * in this case it is tables of functions. 'tftp_functions_t' is a structure
 * which contains a list of function pointers to all Operating System (OS) dependent
 * functionality, the OS code will export its list of functions in a
 * 'tftp_functions_t' functions struct. */
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

/**@brief This function can be used to process packets that are sent or
 * received by the TFTP client/server in an arbitrary way, for example it
 * could be used to introduce errors for testing purposes, or it could be
 * used as a detailed logger in which every packet sent/received is logged
 * to a file. The object in which this function resides should be selected
 * by the build system.
 * @param send,   packet being sent = true, received = false
 * @param buffer, buffer being sent or received
 * @param length, length of buffer
 * @return 0 or greater = no error, less than zero = error */
int tftp_packet_process(bool send, uint8_t *buffer, size_t length);

/**@brief set the logging level of the TFTP system
 * @param l, new logging level
 * @return 0 on success, -1 on failure (invalid logging level) */
int tftp_set_logging_level(tftp_log_levels_e l);

/**@brief tftp logging function
 * @warning TFTP_LOG_LEVEL_FATAL also calls exit(EXIT_FAILURE)!
 * @param l,     logging object to use
 * @param level, log level
 * @param file,  current file, should be __FILE__
 * @param func,  current function, should be __func__
 * @param line,  current line, should be __line__
 * @param fmt,   printf format string
 * @param ...,   parameters for printf format string
 * @return number of bytes written, or negative on error */
int tftp_log(logger_t l, tftp_log_levels_e level, const char *file, const char *func, unsigned line, char *fmt, ...);

#ifndef NDEBUG
#define tftp_fatal(L, ...)   tftp_log((L), TFTP_LOG_LEVEL_FATAL,   __FILE__, __func__, __LINE__, __VA_ARGS__)
#define tftp_error(L, ...)   tftp_log((L), TFTP_LOG_LEVEL_ERROR,   __FILE__, __func__, __LINE__, __VA_ARGS__)
#define tftp_warning(L, ...) tftp_log((L), TFTP_LOG_LEVEL_WARNING, __FILE__, __func__, __LINE__, __VA_ARGS__)
#define tftp_info(L, ...)    tftp_log((L), TFTP_LOG_LEVEL_INFO,    __FILE__, __func__, __LINE__, __VA_ARGS__)
#define tftp_debug(L, ...)   tftp_log((L), TFTP_LOG_LEVEL_DEBUG,   __FILE__, __func__, __LINE__, __VA_ARGS__)
#else
#define tftp_fatal(L, ...)   exit(EXIT_FAILURE)
#define tftp_error(L, ...)   do { } while(0)
#define tftp_warning(L, ...) do { } while(0)
#define tftp_info(L, ...)    do { } while(0)
#define tftp_debug(L, ...)   do { } while(0)
#endif

#ifndef UNUSED
#define UNUSED(X) ((void)(X)) /**< used to suppress unused variable warnings if variable is meant to be unused */
#endif

#endif
