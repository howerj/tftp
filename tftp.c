/**@brief Embeddable and Non-Blocking TFTP server client
 * @author Richard James Howe
 * @license MIT
 * @copyright Richard James Howe (2018)
 * @email howe.r.j.89@gmail.com
 * @repository <https://github.com/howerj/tftp> */

/* TODO:
 * - Reduce number of states in state machine by sharing more code
 * - Test more packet sizes, and make a test suite.
 * - Ensure block numbers are checked correctly.
 * - When implementing the server, implement a single port version that only
 * uses port 69 for ease of use.
 * - Implement a configuration file
 * - The API needs thinking about more and cleaning up */

#include "tftp.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define TFTP_DEFAULT_PORT    (69u)
#define TFTP_DEFAULT_RETRY   (5u)         /**< Default Number of times to retry an operating before giving up */
#define TFTP_TIME_OUT_MS     (1000u * 3u) /**< Time out value in Milli Seconds */
#define TFTP_HEADER_SIZE     (4u)         /**< size of the header field */
#define TFTP_MAX_DATA_SIZE   (512u)       /**< size of the data field */
#define TFTP_MAX_PACKET_SIZE (TFTP_MAX_DATA_SIZE + TFTP_HEADER_SIZE) /**< Maximum length of TFTP packet */
#define TFTP_BUFFER_LENGTH   (TFTP_MAX_DATA_SIZE + 8u) /**< TFTP_MAX_PACKET_SIZE + plus some padding */
#define TFTP_WAIT_TIME_MS    (10)         /**< Time to wait when we have nothing to do */
#define TFTP_LOG_STREAM      (stdout)     /**< Logging stream used throughout */

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

#ifndef MAX
#define MAX(X, Y) ((X) > (X) ? (X) : (Y))
#endif

#define TFTP_STATE_MACRO\
	X(SM_INIT,                "r/w: initialize")\
	X(SM_RS_SEND_RRQ,         "read: send read request")\
	X(SM_RS_RECV_FIRST_DONE,  "read: reopen port")\
	X(SM_RS_RECV,             "read: receive data")\
	X(SM_RS_WRITE_OUT,        "read: write data to disk")\
	X(SM_RS_ACK,              "read: acknowledge")\
	X(SM_WS_SEND_WWQ,         "write: send write request")\
	X(SM_WS_ACK_FIRST,        "write: reopen port")\
	X(SM_WS_READ_IN,          "write: read in data")\
	X(SM_WS_SEND,             "write: send data out")\
	X(SM_WS_ACK,              "write: acknowledge")\
	X(SM_ERROR_PACKET,        "r/w: process error/invalid packet")\
	X(SM_LAST_PACKET,         "r/w: wait for any last packets")\
	X(SM_FINALIZE,            "r/w: close ports/file handles")\
	X(SM_DONE,                "r/w: everything is done")

typedef enum {
#define X(STATE, DESCRIPTION) STATE,
	TFTP_STATE_MACRO

	TFTP_LAST_STATE /**< NOT A VALID STATE */
#undef X
} tftp_state_e;

typedef enum {
	CS_DONE,      /**< Finished all operations */
	CS_WAIT,      /**< Wait state, wait for a period of time and do something else */
	CS_CONTINUE,  /**< Continue on to next state */
	CS_ERROR = -2 /**< Error! Halt operations */
} completion_state_e;

struct tftp_t {
	bool initialized;      /**< has this structure been initialized with host/ip/file data? */
	char *file_name;       /**< file to read/write */
	tftp_socket_t socket;  /**< socket to connect to */
	completion_state_e cs; /**< last completion state */

	file_t file;           /**< file to write to */
	logger_t log;          /**< logging object to use logger with */
	bool read;             /**< true == read file from server, false == write file to server */
	uint8_t buffer[TFTP_BUFFER_LENGTH]; /**< Packet buffer for TX/RX network messages */

	uint8_t tx[TFTP_MAX_DATA_SIZE]; /**< file buffer for reading from file then networking transmit */
	size_t tx_length;      /**< Length of data, if any, in tx */
	bool connected;        /**< Connection initialization done? */

	unsigned retry,        /**< number of tries */
		 tries;        /**< current try count */

	uint64_t now_ms,       /**< current time */
		 last_ms;      /**< time of last successful operation */
	long r;                /**< latest network read return value */
	uint16_t local_block,  /**< what block *we* think we are on */
		 remote_block; /**< block number the remote target thinks it is on */
	uint16_t new_port;     /**< new port the server gives a client for all new traffic */
	tftp_state_e sm;       /**< current TFTP client state */
};

#define TFTP_MAX_SERVER_CONNECTIONS (3)

typedef struct {
	char *file;    /**< file to read or write to */
	char *host;    /**< host to talk to */
	uint16_t port; /**< port to talk to */
	bool read;     /**< read from server/write to file == true, write to server/read from file == false */
	bool server;   /**< operating in server mode? */
} tftp_options_t;

typedef struct {
	tftp_t t;               /**< state machine information for connection */
	tftp_options_t ops;     /**< connection specific options */
	completion_state_e cs;  /**< completion state of connection */
	char remote_host[64];   /**< space for formatting a host address */
	tftp_state_e previous;  /**< previous state in connection state machine */
	size_t number;          /**< connection number */
} tftp_connection_t;

typedef struct {
	tftp_connection_t cons[TFTP_MAX_SERVER_CONNECTIONS]; /**< Concurrent connections allowed */
	uint8_t buffer[TFTP_BUFFER_LENGTH];                  /**< Server request buffer */
	tftp_socket_t server;                                /**< Server socket */
	logger_t log;                                        /**< place to log to */
} tftp_server_t;

static const char *tftp_state_lookup(tftp_state_e state)
{
	static const char *descriptions[] = {
#define X(STATE, DESCRIPTION) DESCRIPTION,
	TFTP_STATE_MACRO
#undef X
	};
	if(state >= TFTP_LAST_STATE)
		return "INVALID";
	return descriptions[state];
}

/* 'f' contains a list of function pointers to operating system dependent
 * functionality.
 *
 * Whilst it is considered bad form to have a variable called 'f' at this scope
 * level, even if it is contained to this module, the functions from this
 * structure are used everywhere, so for convenience 'f' is given a short name. */
static const tftp_functions_t *f = &tftp_os_specific_functions;

static const char *tftp_lookup_log_level(tftp_log_levels_e level)
{
	static const char *s[] = {
#define X(LEVEL) [ TFTP_LOG_LEVEL_ ## LEVEL ] = # LEVEL ,
		TFTP_LOG_LEVELS_XMACRO
#undef X
	};
	if(level >= TFTP_LOG_LEVEL_LAST_LOG_LEVEL)
		level = TFTP_LOG_LEVEL_ALL_ON;
	return s[level];
}

static tftp_log_levels_e tftp_log_level = TFTP_LOG_LEVEL_DEBUG; /**< Global log level settings */

int tftp_set_logging_level(tftp_log_levels_e l)
{
	if(l >= TFTP_LOG_LEVEL_LAST_LOG_LEVEL)
		return -1;
	tftp_log_level = l;
	return 0;
}

static int _logger(logger_t l, char *fmt, ...)
{
	if(!l && !(f->logger))
		return 0;
	va_list arg;
	va_start(arg, fmt);
	int r = f->logger(l, fmt, arg);
	va_end(arg);
	return r;
}

int tftp_log(logger_t l, tftp_log_levels_e level, const char *file, const char *func, unsigned line, char *fmt, ...)
{
	assert(file);
	assert(func);
	assert(fmt);
	assert(level < TFTP_LOG_LEVEL_LAST_LOG_LEVEL);
	if(level == TFTP_LOG_LEVEL_FATAL)
		exit(EXIT_FAILURE);
	if(tftp_log_level < level)
		return 0;
	if(!l || !(f->logger))
		return 0;
	va_list arg;
	int r1 = _logger(l, "%s:%s:%s:%d\t", tftp_lookup_log_level(level), file, func, line);
	va_start(arg, fmt);
	int r2 = f->logger(l, fmt, arg);
	va_end(arg);
	int r3 = _logger(l, "\n");
	return r1 >= 0 && r2 >= 0 && r3 >= 0 ? r1+r2+r3 : -1;
}

static int tftp_init(tftp_t *t, tftp_options_t *ops)
{
	assert(t);
	assert(ops);
	assert(ops->file);
	assert(ops->host);
	assert(!(t->initialized));

	t->file_name  =  ops->file;
	t->retry      =  TFTP_DEFAULT_RETRY;
	t->sm         =  SM_INIT;
	t->read       =  ops->read;
	t->log        =  TFTP_LOG_STREAM;
	t->cs         =  CS_CONTINUE;

	t->file       =  f->fopen(ops->file, !(ops->read));

	if(!(t->file)) {
		tftp_error(t->log, "file open ('%s'/%s) failed", ops->file, !(ops->read) ? "read" : "write");
		goto fail;
	}
	t->socket = f->nopen(ops->host, ops->port, false);
	if(t->socket.fd < 0) {
		tftp_error(t->log, "socket open failed: %s:%u", ops->host, (unsigned)ops->port);
		goto fail;
	}

	t->initialized = true;
	return 0;
fail:
	if(t->file)
		f->fclose(t->file);
	if(t->socket.fd >= 0)
		f->nclose(&t->socket);
	return -1;
}

/**@brief This closes resources associated with 't' structure, but does
 * not free the 't' structure (so it can be reinitialized if needs be). This
 * operating may fail.
 * @param t, structure to clean up
 * @return Code indicating error */
static tftp_function_error_e tftp_finalize(tftp_t *t)
{
	assert(t);
	int r = TFTP_ERR_OK;
	if(t->file && (f->fclose(t->file) < 0)) {
		tftp_error(t->log, "closing file failed");
		r = TFTP_ERR_FAILED;
	}
	if(t->socket.fd > 0 && (f->nclose(&t->socket) < 0)) {
		tftp_error(t->log, "closing server socket failed");
		r = TFTP_ERR_FAILED;
	}
	t->file        = NULL;
	t->socket.fd   = -1;
	t->initialized = false;
	return r;
}

static long nwrite(tftp_socket_t *socket, uint8_t *buffer, size_t length)
{
	assert(socket);
	assert(f->nwrite);
	assert(buffer);
	tftp_packet_process(true, buffer, length);
	return f->nwrite(socket, buffer, length);
}

static long nread(tftp_socket_t *socket, uint8_t *buffer, size_t length)
{
	assert(socket);
	assert(f->nread);
	assert(buffer);
	long r = f->nread(socket, buffer, length);
	if(r >= 0)
		tftp_packet_process(false, buffer, r);
	return r;
}

/** @return -2 == error, -1 == try again, 0 == ok */
static long tftp_ack_send(tftp_socket_t *socket, uint16_t block)
{
	uint8_t header[TFTP_HEADER_SIZE] = { 0, tftp_op_ack, block >> 8, block & 0xff };
	return nwrite(socket, header, sizeof header);
}

/** @return -2 == error, -1 == try again, 0 == ok */
static long tftp_data_send(tftp_t *t, tftp_socket_t *socket, uint16_t block)
{
	uint8_t header[TFTP_HEADER_SIZE] = { 0, tftp_op_data, block >> 8, block & 0xff };
	memcpy(t->buffer, header, sizeof header);
	assert(t->tx_length <= TFTP_MAX_DATA_SIZE);
	memcpy(&t->buffer[HD_DATA_START], t->tx, t->tx_length);
	long r = nwrite(socket, t->buffer, TFTP_HEADER_SIZE + t->tx_length);
	if(r < 0) {
		assert(r == TFTP_ERR_FAILED || r == TFTP_ERR_NO_BLOCK);
		return r;
	}
	return TFTP_ERR_OK;
}

/** @return -2 = failure, -1 = no-data, 512 = done, 0-511 = more data */
static long tftp_read_packet(tftp_t *t, tftp_socket_t *socket, uint16_t *port, uint16_t *block, tftp_opcode_e op)
{
	memset(t->buffer, 0, sizeof(t->buffer));
	long r = nread(socket, t->buffer, TFTP_MAX_PACKET_SIZE);
	if(r < 0) {
		assert(r == TFTP_ERR_FAILED || r == TFTP_ERR_NO_BLOCK);
		return r;
	}
	*port = f->nport(socket);

	if(r < (long)TFTP_HEADER_SIZE || r > (long)TFTP_MAX_PACKET_SIZE)
		return TFTP_ERR_FAILED;
	if(t->buffer[HD_OP_HI] != 0 || t->buffer[HD_OP_LO] != op)
		return TFTP_ERR_FAILED;
	*block = (t->buffer[HD_BLOCK_NUMBER_HI] << 8) | t->buffer[HD_BLOCK_NUMBER_LO];
	r -= TFTP_HEADER_SIZE;
	return r;
}

/**@brief This sends a TFTP Read Request (RRQ) if 'read' is true, or a Write Request
 * (WRQ) if 'read' is false */
static int tftp_wrrq(tftp_t *t, bool read)
{
	assert(t);
	assert(t->file_name);

	static const char *mode    = "octet";
	const size_t mode_length   = strlen(mode);
	const size_t file_length   = strlen(t->file_name);
	const size_t packet_length = file_length + mode_length + TFTP_HEADER_SIZE;

	if(packet_length >= TFTP_MAX_DATA_SIZE)
		return TFTP_ERR_FAILED;

	memset(t->buffer, 0, sizeof(t->buffer));

	t->buffer[HD_OP_HI] = 0;
	t->buffer[HD_OP_LO] = read ? tftp_op_rrq : tftp_op_wrq;

	memcpy(&t->buffer[HD_FILE_NAME_START],               t->file_name, file_length);
	memcpy(&t->buffer[HD_FILE_NAME_START+file_length+1], mode,         mode_length);

	return nwrite(&t->socket, t->buffer, packet_length);
}

static uint64_t time_diff(uint64_t now, uint64_t past)
{
	return now - past;
}

static int tftp_fwrite_helper(tftp_t *t, long r)
{
	assert(t);
	assert(r >= 0 && r <= (long)TFTP_MAX_DATA_SIZE);
	if(!r)
		return TFTP_ERR_OK;
	if(f->fwrite(t->file, &t->buffer[HD_DATA_START], r) != r) {
		tftp_error(t->log, "fwrite failed of size: %lu", r);
		return TFTP_ERR_FAILED;
	}
	return TFTP_ERR_OK;
}

static long tftp_fread_helper(tftp_t *t)
{
	assert(t);
	long r = f->fread(t->file, t->tx, TFTP_MAX_DATA_SIZE);
	if(r < 0) {
		tftp_error(t->log, "fread failed of size: %lu", TFTP_MAX_DATA_SIZE);
		return TFTP_ERR_FAILED;
	}
	return r;
}

static const char *tftp_error_lookup(uint16_t e)
{
	static const char *em[] = {
		[tftp_error_unknown              ] = "Not defined, see error message (if any).",
		[tftp_error_file_not_found       ] = "File not found.",
		[tftp_error_access_violation     ] = "Access violation.",
		[tftp_error_disk_full            ] = "Disk full or allocation exceeded.",
		[tftp_error_illegal_operation    ] = "Illegal TFTP operation.",
		[tftp_error_unknown_id           ] = "Unknown transfer ID.",
		[tftp_error_file_already_exists  ] = "File already exists.",
		[tftp_error_no_such_user         ] = "No such user.",

		[tftp_LAST_ERROR                 ] = "Invalid TFTP Error Code",
	};
	if(e >= tftp_LAST_ERROR)
		return em[tftp_LAST_ERROR];
	return em[e];
}

/**@todo more detailed errors */
static int tftp_error_send(tftp_socket_t *socket, tftp_error_e error, char *msg)
{
	assert(socket);
	assert(error < tftp_LAST_ERROR);
	uint8_t d[TFTP_MAX_PACKET_SIZE] = { 0, tftp_op_error, 0, error };
	const size_t l = strlen(msg);
	const size_t ml = MIN(l, TFTP_MAX_PACKET_SIZE - 1);
	memcpy(d+HD_ERROR_MSG_START, msg, ml);

	if(socket->fd < 0)
		return TFTP_ERR_FAILED;
	return nwrite(socket, d, TFTP_HEADER_SIZE + ml);
}

static tftp_function_error_e tftp_error_print(logger_t l, uint8_t buffer[static TFTP_BUFFER_LENGTH])
{
	assert(l);
	assert(buffer);
	uint16_t op = (buffer[HD_OP_HI] << 8) | buffer[HD_OP_LO];
	if(op != tftp_op_error) {
		tftp_error(l, "invalid packet");
		return TFTP_ERR_FAILED;
	}
	uint16_t e  = (buffer[HD_ERROR_CODE_HI] << 8) | buffer[HD_ERROR_CODE_LO];
	const char *em = tftp_error_lookup(e);
	if(!e)
		tftp_error(l,"%s -> %s", em, &(buffer[HD_ERROR_MSG_START]));
	else
		tftp_error(l,"%s", em);
	return TFTP_ERR_OK;
}

static int tftp_port_new(tftp_t *t)
{
	tftp_socket_t data = f->nopen(t->socket.name, t->new_port, false); /** @note being lazy here...*/
	if(data.fd < 0) {
		tftp_error(t->log, "connect RECV-1 failed");
		return TFTP_ERR_FAILED;
	}
	void *inf = t->socket.info;
	t->socket.info = data.info;
	data.info = inf;
	if(f->nclose(&data) < 0) {
		tftp_error(t->log, "close failed");
		return TFTP_ERR_FAILED;
	}
	if(f->nconnect(&t->socket, t->socket.info) < 0) {
		tftp_error(t->log, "connect failed");
		return TFTP_ERR_FAILED;
	}
	tftp_info(t->log, "connect @ %u", (unsigned)t->new_port);
	return 0;
}

/**@warning changes the state of t->sm to SM_FINALIZE */
static void tftp_goto_finalize(tftp_t *t, completion_state_e cs)
{
	assert(t);
	t->sm = SM_FINALIZE;
	t->cs = cs;
}

typedef enum {
	TIME_OUT_FAILED, /**< Time out limit exceeded, fail */
	TIME_OUT_RETRY,  /**< Retry timed out operation */
	TIME_OUT_WAIT,   /**< Wait for current operation, not timed out */
} tftp_time_out_e; /**< Return status of 'timed_out' function */

static tftp_time_out_e timed_out(tftp_t *t)
{
	assert(t);
	if(time_diff(t->now_ms, t->last_ms) > TFTP_TIME_OUT_MS) {
		if(t->tries-- == 0) {
			t->tries   = t->retry;
			t->last_ms = f->time_ms();
			tftp_error(t->log, "retry count exceeded");
			tftp_goto_finalize(t, CS_ERROR); /* NB. On error this affects the state machine! */
			return TIME_OUT_FAILED;
		}
		return TIME_OUT_RETRY;
	}
	return TIME_OUT_WAIT;
}

static completion_state_e tftp_state_machine(tftp_t *t, tftp_options_t *ops)
{
	assert(t);
	assert(ops);
	switch(t->sm) {
	case SM_INIT:
	{
		long r = tftp_init(t, ops);
		tftp_info(t->log, "file '%s' (%s) -> %s:%u", ops->file, ops->read ? "read" : "write", ops->host, (unsigned)(ops->port));
		if(r < 0) {
			tftp_error(t->log, "initialization failed");
			tftp_goto_finalize(t, CS_ERROR);
			break;
		}

		t->now_ms        = 0;
		t->last_ms       = 0;
		t->tries         = t->retry;
		t->local_block   = t->read ? 1 : 0;

		t->remote_block  = 0;
		t->new_port      = 0;
		t->r             = 0;
		t->connected     = false;
		t->last_ms       = f->time_ms();
		t->cs            = CS_CONTINUE;
		t->sm            = t->read ? SM_RS_SEND_RRQ : SM_WS_SEND_WWQ;
		if(ops->server) {
			tftp_debug(t->log, "server connection mode");
			t->sm = t->read ? SM_RS_ACK : SM_WS_READ_IN;
			t->local_block = t->read ? 0 : 1;
			t->remote_block = 0;
		}
		break;
	}
	case SM_RS_SEND_RRQ:
	{
		long r = 0;
		if((r = tftp_wrrq(t, true)) < 0) { /** @todo add retry counter */
			if(r == TFTP_ERR_FAILED) {
				tftp_goto_finalize(t, CS_ERROR);
				break;
			}
			assert(r == TFTP_ERR_NO_BLOCK);
			t->sm = SM_RS_SEND_RRQ;
			break;
		}
		t->sm = SM_RS_RECV;
		t->last_ms = f->time_ms();
		break;
	}
	case SM_RS_RECV:
		t->now_ms = f->time_ms();
		t->r = tftp_read_packet(t, &t->socket, &t->new_port, &t->remote_block, tftp_op_data);
		if(t->r == TFTP_ERR_FAILED) {
			t->sm = SM_ERROR_PACKET;
		} else if(t->r == TFTP_ERR_NO_BLOCK) {
			switch(timed_out(t)) {
			case TIME_OUT_FAILED: return CS_CONTINUE; /* timed_out sets t->sm to fail */
			case TIME_OUT_RETRY:  t->sm = !(t->connected) && !(ops->server) ? SM_RS_SEND_RRQ : SM_RS_RECV; break;
			case TIME_OUT_WAIT:   return CS_WAIT;
			}
		} else {
			assert(t->r >= 0);
			t->tries = t->retry;
			t->last_ms = f->time_ms();
			t->sm = !(t->connected) && !(ops->server) ? SM_RS_RECV_FIRST_DONE : SM_RS_ACK;
		}
		break;
	case SM_RS_RECV_FIRST_DONE: /* The first received packet contains the port info we need */
		if(tftp_port_new(t) < 0) {
			tftp_error(t->log, "failed to acquire port information");
			tftp_goto_finalize(t, CS_ERROR);
			break;
		}
		t->connected = true;
		t->sm = SM_RS_ACK;
		break;
	case SM_RS_ACK:
	{
		long rv = 0;
		if((rv = tftp_ack_send(&t->socket, t->local_block)) < 0) { /**@todo add time out */
			if(rv == TFTP_ERR_FAILED) {
				tftp_error(t->log, "send ack failed");
				tftp_goto_finalize(t, CS_ERROR);
				break;
			}
			assert(rv == TFTP_ERR_NO_BLOCK);
			return CS_WAIT;
		}
		if(t->local_block == t->remote_block) {
			tftp_debug(t->log, "ack %u", t->local_block);
			t->sm = SM_RS_WRITE_OUT;
		} else {
			tftp_goto_finalize(t, CS_ERROR);
			break;
		}
		break;
	}
	case SM_RS_WRITE_OUT:
		if(t->local_block == t->remote_block) {
			t->tries = t->retry;
			t->last_ms = f->time_ms();
			if(t->connected && tftp_fwrite_helper(t, t->r) < 0) {
				tftp_goto_finalize(t, CS_ERROR);
				break;
			}
			t->sm = t->r == TFTP_MAX_DATA_SIZE || !(t->connected) ? SM_RS_RECV : SM_LAST_PACKET;
			t->connected = true;
			t->local_block++;
		} else {
			t->sm = SM_RS_RECV;
		}
		break;
	case SM_WS_SEND_WWQ:
	{
		long r = 0;
		if((r = tftp_wrrq(t, false)) < 0) { /** @todo add retry counter */
			if(r == TFTP_ERR_FAILED) {
				tftp_goto_finalize(t, CS_ERROR);
				break;
			}
			assert(r == TFTP_ERR_NO_BLOCK);
			t->sm = SM_WS_SEND_WWQ;
			break;
		}
		t->sm = SM_WS_ACK;
		t->last_ms = f->time_ms();
		break;
	}
	case SM_WS_ACK:
		t->now_ms = f->time_ms();
		t->r = tftp_read_packet(t, &t->socket, &t->new_port, &t->remote_block, tftp_op_ack);
		if(t->r == TFTP_ERR_FAILED) {
			t->sm = SM_ERROR_PACKET;
		} else if(t->r == TFTP_ERR_NO_BLOCK) {
			switch(timed_out(t)) {
			case TIME_OUT_FAILED: return CS_CONTINUE; /* timed_out sets t->sm to fail */
			case TIME_OUT_RETRY:  t->sm = !(t->connected) && !(ops->server) ? SM_WS_SEND_WWQ : SM_WS_READ_IN; break;
			case TIME_OUT_WAIT:   return CS_WAIT;
			}
		} else {
			assert(t->r == 0);
			if(t->r)
				tftp_error(t->log, "%ld junk bytes in ACK packet", t->r);
			t->tries = t->retry;
			t->last_ms = f->time_ms();
			t->sm = !(t->connected) && !(ops->server) ? SM_WS_ACK_FIRST: SM_WS_READ_IN;
			if(t->local_block && t->tx_length < TFTP_MAX_DATA_SIZE)
				t->sm = SM_LAST_PACKET;
			t->local_block++;
		}
		break;
	case SM_WS_ACK_FIRST:
		if(tftp_port_new(t) < 0) {
			tftp_goto_finalize(t, CS_ERROR);
			break;
		}
		t->connected = true;
		t->sm = SM_WS_READ_IN;
		break;
	case SM_WS_READ_IN:
	{
		long tx_length = tftp_fread_helper(t);
		if(tx_length < 0) {
			tftp_goto_finalize(t, CS_ERROR);
			break;
		}
		t->tx_length = tx_length;
		t->sm = SM_WS_SEND;
	}
	case SM_WS_SEND:
	{
		long rv = 0;
		if((rv = tftp_data_send(t, &t->socket, t->local_block)) < 0) {
			tftp_error(t->log, "send data failed");
			tftp_goto_finalize(t, CS_ERROR);
			break;
		}
		tftp_debug(t->log, "data %u", t->local_block);
		if(rv != TFTP_ERR_NO_BLOCK) { //&& t->local_block == t->remote_block) {
			/**@todo send timeout? */
			t->sm = SM_WS_ACK;
		} else {
			t->sm = SM_WS_SEND;
			return CS_WAIT;
		}
	}
		break;
	/**@todo sending error packets as well*/
	case SM_ERROR_PACKET:
		tftp_error_print(t->log, t->buffer);
		tftp_error_send(&t->socket, tftp_error_unknown, "");
		tftp_goto_finalize(t, CS_ERROR);
		break;
	case SM_LAST_PACKET: /**@todo wait around to make sure everything is finalized */
		t->sm = SM_FINALIZE;
		break;
	case SM_FINALIZE:
		t->sm = SM_DONE;
		if(tftp_finalize(t) < 0)
			t->cs = CS_ERROR;
		break;
	case SM_DONE:
		return t->cs == CS_ERROR ? CS_ERROR : CS_DONE;
	default:
		tftp_fatal(t->log, "invalid read state: %u", t->sm);
		break;
	}
	return CS_CONTINUE;
}

static int tftp_transaction(tftp_t *t, tftp_options_t *ops)
{
	assert(t);
	assert(ops);
	tftp_debug(t->log, "state(%u) -> %s", (unsigned)t->sm, tftp_state_lookup(t->sm));
	tftp_state_e prev = t->sm;
        for(;;) {
		completion_state_e cs = tftp_state_machine(t, ops);
		if(prev != t->sm)
			tftp_debug(t->log, "state(%u) -> %s", (unsigned)t->sm, tftp_state_lookup(t->sm));
		prev = t->sm;
		switch(cs) {
		case CS_WAIT:
			f->wait_ms(TFTP_WAIT_TIME_MS);
			/* ... Fall through... */
		case CS_CONTINUE:
			break;
		case CS_DONE:
			return 0;
		default:
			tftp_error(t->log, "invalid completion state: %u", (unsigned)cs);
		case CS_ERROR:
			return -1;
		}
	}
	return 0;
}

typedef enum {
	TFTP_MODE_OCTET,    /**< Octet mode: AKA 'normal' mode */
	TFTP_MODE_NETASCII, /**< Net ASCII mode: AKA 'why is this a thing' mode */
	TFTP_MODE_MAIL,     /**< Mail mode: A legacy mode */
	TFTP_MODE_INVALID   /**< Used to signal specified mode is invalid */
} tftp_mode_e;

/** @return -2 = failure, -1 = no-data, 512 = done, 0-511 = more data
 * @todo also need IP back from nread * */
static long tftp_read_request(tftp_server_t *s, tftp_socket_t *socket, uint16_t *port, char *name, tftp_mode_e *m, bool *rrq)
{
	assert(s);
	assert(socket);
	assert(port);
	assert(name);
	assert(m);
	assert(rrq);

	memset(s->buffer, 0, sizeof(s->buffer));
	*m = TFTP_MODE_INVALID;

	long r = nread(socket, s->buffer, TFTP_MAX_PACKET_SIZE);
	if(r < 0) {
		assert(r == TFTP_ERR_FAILED || r == TFTP_ERR_NO_BLOCK);
		return r;
	}
	*port = f->nport(socket);
	if(r < (long)TFTP_HEADER_SIZE || r > (long)TFTP_MAX_PACKET_SIZE)
		return TFTP_ERR_FAILED;
	if(s->buffer[HD_OP_HI] != 0 || (s->buffer[HD_OP_LO] != tftp_op_rrq && s->buffer[HD_OP_LO] != tftp_op_wrq))
		return TFTP_ERR_FAILED;

	/* These should be NUL terminated by the s->buffer being bigger than it
	 * needs to be as well, just in case */
	char *file = (char*)&s->buffer[HD_FILE_NAME_START];
	const size_t file_length = strnlen(file,               TFTP_MAX_DATA_SIZE);
	const size_t mode_length = strnlen(file+file_length+1, TFTP_MAX_DATA_SIZE - file_length - 1);
	char *mode = file + file_length + 1;
	assert((uint8_t*)mode < (s->buffer + TFTP_MAX_PACKET_SIZE));

	for(size_t i = 0; i < mode_length; i++) /* mode field can be a mix of upper/lower case */
		mode[i] = tolower(mode[i]);

	if(!strcmp(mode, "octet"))
		*m = TFTP_MODE_OCTET;
	else if(!strcmp(mode, "netascii"))
		*m = TFTP_MODE_NETASCII;
	else if(!strcmp(mode, "mail"))
		*m = TFTP_MODE_MAIL;
	else
		return TFTP_ERR_FAILED;
	memcpy(name, file, file_length);
	*rrq = s->buffer[HD_OP_LO] == tftp_op_rrq;

	return r;
}

static tftp_connection_t *tftp_server_find_free_connection(tftp_server_t *srv)
{
	assert(srv);
	tftp_connection_t *con = NULL;
	for(size_t i = 0; i < TFTP_MAX_SERVER_CONNECTIONS; i++)
		if(srv->cons[i].t.sm == SM_DONE) { /* free connection */
			con = &srv->cons[i];
			break;
		}
	return con;
}

static int tftp_server_initialize(tftp_server_t *srv, const char *directory, const char *host, uint16_t port)
{
	assert(srv);
	assert(directory);
	assert(host);
	srv->log = TFTP_LOG_STREAM;

	if(f->chdir(directory) < 0) {
		tftp_error(srv->log, "chdir to '%s' failed", directory);
		return -1;
	}

	srv->server = f->nopen(host, port, true);
	if(srv->server.fd == -1) {
		tftp_error(srv->log, "open %s:%u failed", host, (unsigned)port);
		return -1;
	}

	for(size_t i = 0; i < TFTP_MAX_SERVER_CONNECTIONS; i++) {
		tftp_connection_t *con = &srv->cons[i];
		con->t.sm     = SM_DONE;
		con->previous = SM_DONE;
		con->ops.server = true;
		con->number   = i;
	}
	return 0;
}

/* returns wait status, true == wait */
static tftp_error_e tftp_server_process_request(tftp_server_t *srv, bool *wait)
{
	assert(srv);
	assert(wait);
	char name[TFTP_MAX_DATA_SIZE+1] = { 0 };
	uint16_t port    = 0;
	bool rrq         = false;
	tftp_mode_e mode = TFTP_MODE_INVALID;

	long r = tftp_read_request(srv, &srv->server, &port, name, &mode, &rrq);
	name[TFTP_MAX_DATA_SIZE] = '0';

	if(r < 0) {
		if(r == TFTP_ERR_FAILED) {
			tftp_error_print(srv->log, srv->buffer);
			/**@todo send error message if not a socket error */
			*wait = false;
		} else {
			assert(r == TFTP_ERR_NO_BLOCK);
		}
		return tftp_error_unknown;
	}

	if(mode != TFTP_MODE_OCTET) {
		tftp_error(srv->log, "only mode octet is supported");
		return tftp_error_unknown;
	}

	tftp_connection_t *con = tftp_server_find_free_connection(srv);
	if(!con) {
		tftp_error(srv->log, "no free connections");
		/**@todo send error message if not a socket error */
		return tftp_error_unknown;
	}

	f->nhost(&srv->server, con->remote_host);

	con->ops.file = name;
	con->ops.host = con->remote_host;
	con->ops.port = f->nport(&srv->server);
	con->ops.read = !rrq;
	con->t.sm     = SM_INIT;

	tftp_debug(srv->log, "connection on: %s %d", con->ops.host, con->ops.port);
	con->cs = tftp_state_machine(&con->t, &con->ops); /* first tick initializes */
	tftp_debug(con->t.log, "connection(%u) state(%u) -> %s",(unsigned)con->number, (unsigned)con->t.sm, tftp_state_lookup(con->t.sm));

	*wait = false;
	return -1;
}

static void tftp_server_process_connections(tftp_server_t *srv, bool *wait)
{
	assert(srv);
	assert(wait);
	for(size_t i = 0; i < TFTP_MAX_SERVER_CONNECTIONS; i++) {
		tftp_connection_t *con = &srv->cons[i];
		if(con->cs == CS_DONE || con->cs == CS_ERROR)
			continue;

		con->cs = tftp_state_machine(&con->t, &con->ops);
		if(con->previous != con->t.sm)
			tftp_debug(con->t.log, "connection(%u) state(%u) -> %s",(unsigned)con->number, (unsigned)con->t.sm, tftp_state_lookup(con->t.sm));
		con->previous = con->t.sm;
		switch(con->cs) {
		case CS_WAIT:
			break;
		case CS_CONTINUE:
			*wait = false;
			break;
		case CS_DONE:
			break;
		default:
			tftp_fatal(con->t.log, "invalid completion state: %u", (unsigned)(con->cs));
		case CS_ERROR:
			break;
		}
	}
}

int tftp_server(tftp_server_t *srv, const char *directory, const char *host, uint16_t port)
{
	assert(srv);
	assert(directory);
	assert(host);
	srv->log = TFTP_LOG_STREAM;

	tftp_info(srv->log, "server: %s %s %u", directory, host, (unsigned)port);

	if(tftp_server_initialize(srv, directory, host, port) < 0)
		return -1;

	tftp_info(srv->log, "starting");
	for(;!(f->quit());) {
		bool wait = true;
		tftp_server_process_request(srv, &wait);
		/**@todo add error handling? */
		tftp_server_process_connections(srv, &wait);
		if(wait)
			f->wait_ms(TFTP_WAIT_TIME_MS);
	}
	return 0;
}

int tftp_client(tftp_t *t, char *file, char *host, uint16_t port, bool read)
{
	memset(t, 0, sizeof *t);

	tftp_options_t options = {
		.file   = file,
		.host   = host,
		.port   = port,
		.read   = read,
		.server = false
	};

	if(tftp_transaction(t, &options) < 0) {
		tftp_error(t->log, "transaction failed");
		return -1;
	}
	return 0;
}

/**@todo move to separate file */
int main(int argc, char **argv)
{
	static tftp_t tftp_client_obj;
	static tftp_server_t tftp_server_obj;

	if(argc != 5)
		goto fail;
	uint16_t port = atoi(argv[4]);
	char *host = argv[3];
	char *file = argv[2];
	char *mode = argv[1];
	bool read  = true;
	bool server = false;
	if(!strcmp("-g", mode))
		read = true;
	else if(!strcmp("-p", mode))
		read = false;
	else if(!strcmp("-s", mode))
		server = true;
	else
		goto fail;
	if(server)
		return tftp_server(&tftp_server_obj, file, host, port);
	return tftp_client(&tftp_client_obj, file, host, port, read);
fail:
	fprintf(TFTP_LOG_STREAM, "usage: %s [-gps] file/directory host/interface port\n", argv[0]);
	return EXIT_FAILURE;
}

