/**@brief Embeddable and Non-Blocking TFTP server client
 * @author Richard James Howe
 * @license MIT
 * @copyright Richard James Howe (2018)
 * @email howe.r.j.89@gmail.com
 * @repository <https://github.com/howerj/tftp> */

/* TODO:
 * - Make sure this program never blocks
 * - Implement logging levels
 * - Reduce number of states in state machine by sharing more code
 * - Make an error simulator mode for testing different situations, this
 * could work by probabilistically dropping and corrupting packets, and
 * exiting early. This should be as easy as writing wrappers for the
 * nwrite and nread callbacks and using roulette selection for the randomized
 * behavior selection.
 * - Test more packet sizes, and make a test suite.
 * - Implement the server
 * - Ensure block numbers are checked correctly.
 * - When implementing the server, implement a single port version that only
 * uses port 69 for ease of use.
 * - Implement a configuration file
 * - Integration with multicall binary? <https://github.com/howerj/multicall>
 * - Port to Windows
 * - The API needs thinking about more and cleaning up */

#include "tftp.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

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
	HD_ERROR_MSG_START = 4, /**< Start of NUL terminated ASCIIZ string, if any */

	/* For RRQ and WRQ op codes */
	HD_FILE_NAME_START = 2,

	/* For DATA messages only */
	HD_DATA_START      = 4,
} tftp_header_e; /**< TFTP header field offsets (opcode dependent) */

#define TFTP_HEADER_SIZE     (4u)   /**< size of the header field */
#define TFTP_MAX_DATA_SIZE   (512u) /**< size of the data field */
#define TFTP_MAX_PACKET_SIZE (TFTP_MAX_DATA_SIZE + TFTP_HEADER_SIZE) /**< Maximum length of TFTP packet */
#define TFTP_BUFFER_LENGTH   (TFTP_MAX_DATA_SIZE + 8u) /**< TFTP_MAX_PACKET_SIZE + plus some padding */

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

const char *tftp_state_lookup(tftp_state_e state)
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

struct tftp_t {
	bool initialized;      /**< has this structure been initialized with host/ip/file data? */
	char *file_name;       /**< file to read/write */
	tftp_socket_t server;  /**< server to connect to */

	file_t file;           /**< file to write to */
	logger_t log;          /**< logging object to use logger with */
	bool read;             /**< true == read file from server, false == write file to server */
	bool log_on;           /**< is logging on? */
	uint8_t buffer[TFTP_BUFFER_LENGTH]; /**< Packet buffer for TX/RX network messages */

	uint8_t tx[TFTP_MAX_DATA_SIZE]; /**< file buffer for reading from file then networking transmit */
	size_t tx_length;      /**< Length of data, if any, in tx */

	unsigned retry,        /**< number of tries */
		 tries;        /**< current try count */

	uint64_t now_ms,
		 last_ms;
	long r;                /**< latest network read return value */
	uint16_t local_block,  /**< what block *we* think we are on */
		 remote_block; /**< block number the remote target thinks it is on */
	uint16_t new_port;     /**< new port the server gives a client for all new traffic */
	tftp_state_e sm;       /**< current TFTP client state */

#define X(FUNCTION) tftp_ ## FUNCTION ## _t FUNCTION ;
TFTP_FUNCTIONS_XMACRO
#undef X

};

#define TFTP_MAX_SERVER_CONNECTIONS (3)

typedef struct {
	char *file;
	char *host;
	uint16_t port;
	bool read;
} tftp_options_t;

typedef enum {
	CS_DONE,      /**< Finished all operations */
	CS_WAIT,      /**< Wait state, wait for a period of time and do something else */
	CS_CONTINUE,  /**< Continue on to next state */
	CS_ERROR = -2 /**< Error! Halt operations */
} completion_state_e;

typedef struct {
	tftp_t t;
	tftp_options_t ops;
	completion_state_e cs;
	char remote_host[64];
} tftp_connection_t;

typedef struct {
	tftp_connection_t cons[TFTP_MAX_SERVER_CONNECTIONS];
	uint8_t buffer[TFTP_BUFFER_LENGTH];
	tftp_socket_t server;
	const tftp_functions_t *f;
} tftp_server_t;

static int _logger(tftp_t *t, char *fmt, ...)
{
	if(t->log_on) {
		va_list arg;
		va_start(arg, fmt);
		int r = t->logger(t->log, fmt, arg);
		va_end(arg);
		return r;
	}
	return 0;
}

static int _logger_line(tftp_t *t, const char *file, const char *func, unsigned line, char *fmt, ...)
{
	if(t->log_on && t->logger) {
		va_list arg;
		int r1 = _logger(t, "%s:%s:%d\t", file, func, line);
		va_start(arg, fmt);
		int r2 = t->logger(t->log, fmt, arg);
		va_end(arg);
		int r3 = _logger(t, "\n");
		return r1 >= 0 && r2 >= 0 && r3 >= 0 ? r1+r2+r3 : -1;
	}
	return 0;
}

#define msg(T, ...) _logger_line((T), __FILE__, __func__, __LINE__, __VA_ARGS__)

static void tftp_copy_functions(tftp_t *t, const tftp_functions_t *f)
{
	assert(t);
	assert(f);
#define X(FUNCTION) t-> FUNCTION = f-> FUNCTION ;
TFTP_FUNCTIONS_XMACRO
#undef X
}

/**@todo move to init state of TFTP state machine */
static int tftp_init(tftp_t *t, tftp_options_t *ops, bool log_on)
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
	t->log        =  stderr; /** @warning setting logging should always succeed */

	tftp_copy_functions(t, tftp_get_functions());	

	t->log_on     =  log_on;

	t->file       =  t->fopen(ops->file, !(ops->read));

	if(!(t->file)) {
		msg(t, "file open ('%s'/%s) failed", ops->file, !(ops->read) ? "read" : "write");
		goto fail;
	}
	t->server = t->nopen(ops->host, ops->port, false);
	if(t->server.fd < 0) {
		msg(t, "socket open failed: %s:%u", ops->host, (unsigned)ops->port);
		goto fail;
	}
	return 0;
fail:
	if(t->file)
		t->fclose(t->file);
	if(t->server.fd >= 0)
		t->nclose(&t->server);
	return -1;
}

int tftp_finalize(tftp_t *t)
{
	assert(t);
	int r = 0;
	if(t->file && (t->fclose(t->file) < 0)) {
		msg(t, "closing file failed");
		r = -1;
	}
	if(t->server.fd > 0 && (t->nclose(&t->server) < 0)) {
		msg(t, "closing server socket failed");
		r = -1;
	}
	return r;
}

/* -2 == error, -1 == try again, 0 == ok */
static long tftp_send_ack(tftp_t *t, tftp_socket_t *socket, uint16_t block)
{
	uint8_t header[TFTP_HEADER_SIZE] = { 0, tftp_op_ack, block >> 8, block & 0xff };
	return t->nwrite(socket, header, sizeof header);
}

/* -2 == error, -1 == try again, 0 == ok */
static long tftp_send_data(tftp_t *t, tftp_socket_t *socket, uint16_t block)
{
	uint8_t header[TFTP_HEADER_SIZE] = { 0, tftp_op_data, block >> 8, block & 0xff };
	memcpy(t->buffer, header, sizeof header);
	assert(t->tx_length <= TFTP_MAX_DATA_SIZE);
	memcpy(&t->buffer[HD_DATA_START], t->tx, t->tx_length); 
	long r = t->nwrite(socket, t->buffer, TFTP_HEADER_SIZE + t->tx_length);
	if(r < 0) {
		assert(r == TFTP_ERR_FAILED || r == TFTP_ERR_NO_BLOCK);
		return r;
	}
	return 0;
}

/** -2 = failure, -1 = no-data, 512 = done, 0-511 = more data */
static long tftp_read_packet(tftp_t *t, tftp_socket_t *socket, uint16_t *port, uint16_t *block, tftp_opcode_e op)
{
	memset(t->buffer, 0, sizeof(t->buffer));
	long r = t->nread(socket, t->buffer, TFTP_MAX_PACKET_SIZE);
	if(r < 0) {
		assert(r == TFTP_ERR_FAILED || r == TFTP_ERR_NO_BLOCK);
		return r;
	}
	*port = t->nport(socket);

	if(r < TFTP_HEADER_SIZE || r > TFTP_MAX_PACKET_SIZE)
		return TFTP_ERR_FAILED;
	if(t->buffer[HD_OP_HI] != 0 || t->buffer[HD_OP_LO] != op)
		return TFTP_ERR_FAILED;
	*block = (t->buffer[HD_BLOCK_NUMBER_HI] << 8) | t->buffer[HD_BLOCK_NUMBER_LO];
	r -= TFTP_HEADER_SIZE;
	return r;
}

/**@todo separate out write request and write */
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

	return t->nwrite(&t->server, t->buffer, packet_length);
}

static uint64_t time_diff(uint64_t now, uint64_t past)
{
	return now-past;
}

static int tftp_fwrite_helper(tftp_t *t, long r)
{
	assert(t);
	assert(r >= 0 && r <= TFTP_MAX_DATA_SIZE);
	if(!r)
		return TFTP_ERR_OK;
	if(t->fwrite(t->file, &t->buffer[HD_DATA_START], r) != r) {
		msg(t, "fwrite failed of size: %lu", r);
		return TFTP_ERR_FAILED;
	}
	return TFTP_ERR_OK;
}

static long tftp_fread_helper(tftp_t *t)
{
	assert(t);
	long r = t->fread(t->file, t->tx, TFTP_MAX_DATA_SIZE);
	if(r < 0) {
		msg(t, "fread failed of size: %lu", TFTP_MAX_DATA_SIZE);
		return TFTP_ERR_FAILED;
	}
	return r;
}

const char *tftp_error_lookup(uint16_t e)
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
	if(/*(int)e < 0 ||*/ e >= tftp_LAST_ERROR) 
		return em[tftp_LAST_ERROR];
	return em[e];
}

static int tftp_error_print(tftp_t *t)
{
	assert(t);
	uint16_t op = (t->buffer[HD_OP_HI] << 8) | t->buffer[HD_OP_LO];
	if(op != tftp_op_error) {
		msg(t, "invalid packet");
		return TFTP_ERR_FAILED;
	}
	uint16_t e  = (t->buffer[HD_ERROR_CODE_HI] << 8) | t->buffer[HD_ERROR_CODE_LO];
	const char *em = tftp_error_lookup(e);
	if(!e) 
		msg(t,"%s -> %s", em, &(t->buffer[HD_ERROR_MSG_START]));
	else
		msg(t,"%s", em);
	return 0;
}

static int tftp_new_port(tftp_t *t)
{
	tftp_socket_t data = t->nopen(t->server.name, t->new_port, false); /** @note being lazy here...*/
	if(data.fd < 0) {
		msg(t, "connect RECV-1 failed");
		return TFTP_ERR_FAILED;
	} 
	void *inf = t->server.info;
	t->server.info = data.info;
	data.info = inf;
	if(t->nclose(&data) < 0) {
		msg(t, "close failed");
		return TFTP_ERR_FAILED;
	}
	if(t->nconnect(&t->server, t->server.info) < 0) {
		msg(t, "connect failed");
		return TFTP_ERR_FAILED;
	}
	msg(t, "connect @ %u", (unsigned)t->new_port);
	return 0;
}

static completion_state_e tftp_state_machine(tftp_t *t, tftp_options_t *ops)
{
	assert(t);
	assert(ops);
	/** @todo Modify state machine so it can be used as a server as well,
	 * it must bind straight away and not later */
	switch(t->sm) {
	case SM_INIT:
	{
		long r = tftp_init(t, ops, true);
		msg(t, "file '%s' (%s) -> %s:%u", ops->file, ops->read ? "read" : "write", ops->host, (unsigned)(ops->port));
		if(r < 0) {
			msg(t, "initialization failed");
			t->sm = SM_DONE;
			return CS_ERROR;
		}

		t->now_ms        =  0;
		t->last_ms       =  0;
		t->tries         =  t->retry;
		t->local_block   =  t->read ? 1 : 0;
		t->remote_block  =  0;
		t->new_port      =  0;
		t->r             =  0;
		t->sm            =  t->read ? SM_RS_SEND_RRQ : SM_WS_SEND_WWQ;
		break;
	}
	case SM_RS_SEND_RRQ:
	{
		long r = 0;
		if((r = tftp_wrrq(t, true)) < 0) { /** @todo add retry counter */
			if(r == TFTP_ERR_FAILED) {
				t->sm = SM_DONE; /** @todo send error packet? */
				return CS_ERROR;
			}
			assert(r == TFTP_ERR_NO_BLOCK);
			t->sm = SM_RS_SEND_RRQ;
			break;
		}
		t->sm = SM_RS_RECV;
		t->last_ms = t->time_ms();
		break;
	}
	case SM_RS_RECV:
		t->now_ms = t->time_ms();
		t->r = tftp_read_packet(t, &t->server, &t->new_port, &t->remote_block, tftp_op_data);
		if(t->r == TFTP_ERR_FAILED) {
			t->sm = SM_ERROR_PACKET;
		} else if(t->r == TFTP_ERR_NO_BLOCK) {
			if(time_diff(t->now_ms, t->last_ms) > TFTP_TIME_OUT_MS) {
				if(t->tries-- == 0) {
					msg(t, "retry count exceeded");
					t->sm = SM_DONE;
					return CS_ERROR;
				}
				t->sm = t->local_block == 1 ? SM_RS_SEND_RRQ : SM_RS_RECV;
			}
			return CS_WAIT;
		} else {
			assert(t->r >= 0);
			t->tries = t->retry;
			/**@bug local_block will roll over for long files! */
			t->sm = t->local_block == 1 ? SM_RS_RECV_FIRST_DONE: SM_RS_ACK;
		}
		break;
	case SM_RS_RECV_FIRST_DONE: /* The first received packet contains the port info we need */
		if(tftp_new_port(t) < 0) {
			t->sm = SM_DONE;
			return CS_ERROR;
		}
		t->sm = SM_RS_ACK;
		break;
	case SM_RS_ACK:
	{
		long rv = 0;
		if((rv = tftp_send_ack(t, &t->server, t->local_block)) < 0) {
			if(rv == TFTP_ERR_FAILED) {
				msg(t, "send ack failed");
				t->sm = SM_DONE;
				return CS_ERROR;
			}
			assert(rv == TFTP_ERR_NO_BLOCK);
			return CS_WAIT;
		} 
		msg(t, "ack %u", t->local_block);
		if(t->local_block == t->remote_block)
			t->sm = SM_RS_WRITE_OUT;
		break;
	}
	case SM_RS_WRITE_OUT:
		if(t->local_block == t->remote_block) {
			t->tries = t->retry;
			if(tftp_fwrite_helper(t, t->r) < 0) {
				t->sm = SM_DONE;
				return CS_ERROR;
			}
			t->sm = t->r == TFTP_MAX_DATA_SIZE ? SM_RS_RECV : SM_LAST_PACKET;
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
				t->sm = SM_DONE;
				return CS_ERROR;
			}
			assert(r == TFTP_ERR_NO_BLOCK);
			t->sm = SM_WS_SEND_WWQ;
			break;
		}
		t->sm = SM_WS_ACK;
		t->last_ms = t->time_ms();
		break;
	}
	case SM_WS_ACK:
		t->now_ms = t->time_ms();
		t->r = tftp_read_packet(t, &t->server, &t->new_port, &t->remote_block, tftp_op_ack);
		if(t->r == TFTP_ERR_FAILED) {
			t->sm = SM_ERROR_PACKET;
		} else if(t->r == TFTP_ERR_NO_BLOCK) {
			if(time_diff(t->now_ms, t->last_ms) > TFTP_TIME_OUT_MS) {
				if(t->tries-- == 0) {
					msg(t, "retry count exceeded");
					t->sm = SM_DONE;
					return CS_ERROR;
				}
				t->sm = t->local_block == 0 ? SM_WS_SEND_WWQ : SM_WS_READ_IN;
			}
			return CS_WAIT;
		} else {
			assert(t->r == 0);
			if(t->r)
				msg(t, "%ld junk bytes in ACK packet", t->r);
			t->tries = t->retry;
			/**@bug local_block will roll over for long files! */
			t->sm = t->local_block == 0 ? SM_WS_ACK_FIRST: SM_WS_READ_IN;
			if(t->local_block && t->tx_length < TFTP_MAX_DATA_SIZE)
				t->sm = SM_LAST_PACKET;
			t->local_block++;
		}
		break;
	case SM_WS_ACK_FIRST:
		if(tftp_new_port(t) < 0) {
			t->sm = SM_DONE;
			return CS_ERROR;
		}
		t->sm = SM_WS_READ_IN;
		break;
	case SM_WS_READ_IN:
	{
		long tx_length = tftp_fread_helper(t);
		if(tx_length < 0) {
			t->sm = SM_DONE;
			return CS_ERROR;
		}
		t->tx_length = tx_length;
		t->sm = SM_WS_SEND;
	}
	case SM_WS_SEND:
	{
		long rv = 0;
		if((rv = tftp_send_data(t, &t->server, t->local_block)) < 0) {
			msg(t, "send data failed");
			t->sm = SM_DONE;
			return CS_ERROR;
		} 
		msg(t, "data %u", t->local_block);
		if(rv != TFTP_ERR_NO_BLOCK) { //&& t->local_block == t->remote_block) {
			/**@todo send timeout? */
			t->sm = SM_WS_ACK;
		} else {
			t->sm = SM_WS_SEND;
			return CS_WAIT;
		}
	}
		break;
	case SM_ERROR_PACKET:
		tftp_error_print(t);
		t->sm = SM_DONE;
		return CS_ERROR;
	case SM_LAST_PACKET: /**@todo wait around to make sure everything is finalized */
		t->sm = SM_FINALIZE;
		break;
	case SM_FINALIZE:
		t->sm = SM_DONE;
		return tftp_finalize(t) < 0 ? CS_ERROR : CS_DONE;
	case SM_DONE:
		return CS_DONE;
	default:
		msg(t, "invalid read state: %u", t->sm);
		return CS_ERROR;
	}
	return CS_CONTINUE;
}

int tftp_transaction(tftp_t *t, tftp_options_t *ops)
{
	assert(t);
	assert(ops);
        for(;;) {
		msg(t, "state(%u) -> %s", (unsigned)t->sm, tftp_state_lookup(t->sm));
		completion_state_e cs = tftp_state_machine(t, ops);
		switch(cs) {
		case CS_WAIT:
			/*msg(t, "waiting...");*/
			t->wait_ms(0);
			/* ... Fall through... */
		case CS_CONTINUE:
			break;
		case CS_DONE:
			return 0;
		default:
			msg(t, "invalid completion state: %u", (unsigned)cs);
		case CS_ERROR:
			return -1;
		}
	}
	return 0;
}

typedef enum {
	TFTP_MODE_OCTET,
	TFTP_MODE_NETASCII,
	TFTP_MODE_MAIL,
	TFTP_MODE_INVALID
} tftp_mode_e;

/** -2 = failure, -1 = no-data, 512 = done, 0-511 = more data
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

	long r = s->f->nread(socket, s->buffer, TFTP_MAX_PACKET_SIZE);
	if(r < 0) {
		assert(r == TFTP_ERR_FAILED || r == TFTP_ERR_NO_BLOCK);
		return r;
	}
	*port = s->f->nport(socket);
	if(r < TFTP_HEADER_SIZE || r > TFTP_MAX_PACKET_SIZE)
		return TFTP_ERR_FAILED;
	if(s->buffer[HD_OP_HI] != 0 || (s->buffer[HD_OP_LO] != tftp_op_rrq && s->buffer[HD_OP_LO] != tftp_op_wrq))
		return TFTP_ERR_FAILED;

	/* These should be NUL terminated by the s->buffer being bigger than it
	 * needs to be as well, just in case */
	char *file = (char*)&s->buffer[HD_FILE_NAME_START];
	const size_t file_length = strnlen(file,               TFTP_MAX_DATA_SIZE);
	const size_t mode_length = strnlen(file+file_length+1, TFTP_MAX_DATA_SIZE - file_length - 1);
	char *mode = file + file_length + 1;
	
	for(size_t i = 0; i < mode_length; i++)
		mode[i] = tolower(mode[i]);

	if(!strcmp(mode, "octet"))
		*mode = TFTP_MODE_OCTET;
	else if(!strcmp(mode, "netascii"))
		*mode = TFTP_MODE_NETASCII;
	else if(!strcmp(mode, "mail"))
		*mode = TFTP_MODE_MAIL;
	else
		return TFTP_ERR_FAILED;
	memcpy(name, file, file_length);
	*rrq = s->buffer[HD_OP_LO] == tftp_op_rrq;

	return r;
}

int tftp_server(tftp_server_t *srv, char *directory, char *host, uint16_t port)
{
	assert(srv);
	assert(directory);
	assert(host);
	srv->f = tftp_get_functions();
	char name[TFTP_MAX_DATA_SIZE+1] = { 0 };

	fprintf(stderr, "server: %s %s %u\n", directory, host, (unsigned)port);

	if(srv->f->chdir(directory) < 0) {
		fprintf(stderr, "chdir failed\n");
	}

	srv->server = srv->f->nopen(host, port, true);
	if(srv->server.fd == -1) {
		fprintf(stderr, "open failed\n");
		return -1;
	}

	for(size_t i = 0; i < TFTP_MAX_SERVER_CONNECTIONS; i++) {
		tftp_connection_t *con = &srv->cons[i];
		con->t.sm = SM_DONE;
	}

	/**@todo better logging */

	fprintf(stderr, "starting\n");
	while(true) {
		bool wait = true;
		uint16_t port = 0;
		bool rrq = false;
		tftp_mode_e mode;
		long r = tftp_read_request(srv, &srv->server, &port, name, &mode, &rrq);
		name[TFTP_MAX_DATA_SIZE] = '0';
		if(r < 0) {
			if(r == TFTP_ERR_FAILED) {
				/**@todo send error message if not a socket error */
			} else {
				assert(r == TFTP_ERR_NO_BLOCK);
			}
		} else {
			fprintf(stderr, "new connection\n");
			tftp_connection_t *con = NULL;
			for(size_t i = 0; i < TFTP_MAX_SERVER_CONNECTIONS; i++) {
				if(srv->cons->t.sm == SM_DONE) { /* free! */
					con = &srv->cons[i];
					break;
				}
			}
			if(con) {
				con->ops.file = name;
				srv->f->nhost(&srv->server, con->remote_host);
				con->ops.host = con->remote_host; /* @todo get host name */
				con->ops.port = srv->f->nport(&srv->server);
				fprintf(stderr, "connection on: %s %d\n", con->ops.host, con->ops.port);
				con->ops.read = rrq;
				con->t.sm = SM_INIT;
				con->cs = tftp_state_machine(&con->t, &con->ops); /* first tick initializes */
				if(con->cs != CS_ERROR && (srv->f->nbind(&con->t.server) < 0)) {
					fprintf(stderr, "bind failed: %s %d\n", con->ops.host, con->ops.port);
				}
				wait = false;
			} else {
				fprintf(stderr, "no free connections\n");
			}
		}

		for(size_t i = 0; i < TFTP_MAX_SERVER_CONNECTIONS; i++) {
			tftp_connection_t *con = &srv->cons[i];
			/**If CS_ERROR send an error packet, then move to CS_DONE */
			if(con->cs == CS_DONE || con->cs == CS_ERROR)
				continue;

			con->cs = tftp_state_machine(&con->t, &con->ops);
			switch(con->cs) {
			case CS_WAIT:
				/*msg(t, "waiting...");*/
				//con->t.wait_ms(0);
				/* ... Fall through... */
				break;
			case CS_CONTINUE:
				wait = false;
				break;
			case CS_DONE:
				break;
			default:
				msg(&con->t, "invalid completion state: %u", (unsigned)(con->cs));
				return -1;
			case CS_ERROR:
				break;
			}
		}
		if(wait)
			srv->f->wait_ms(0);
	}
	return 0;
}

int tftp_client(tftp_t *t, char *file, char *host, uint16_t port, bool read)
{
	memset(t, 0, sizeof *t);

	tftp_options_t options = {
		.file = file,
		.host = host,
		.port = port,
		.read = read,
	};

	if(tftp_transaction(t, &options) < 0) {
		msg(t, "transaction failed");
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
	fprintf(stderr, "usage: %s [-gps] file/directory host/interface port\n", argv[0]);
	return EXIT_FAILURE;
}

