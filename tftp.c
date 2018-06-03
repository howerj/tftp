/**@brief Embeddable and Non-Blocking TFTP server client
 * @author Richard James Howe
 * @license MIT
 * @copyright Richard James Howe (2018)
 * @email howe.r.j.89@gmail.com
 * @repository <https://github.com/howerj/tftp> */

#include "tftp.h"

#define TFTP_BUFFER_LENGTH (550u) /* 516 is max packet size, plus some padding */

/* See: <https://en.wikipedia.org/wiki/X_Macro> */
#define TFTP_STATE_XMACRO\
	X(SM_INIT,             "r/w: initialize")\
	X(RS_SEND_RRQ,         "read: send read request")\
	X(RS_RECV_FIRST_DONE,  "read: reopen port")\
	X(RS_RECV,             "read: receive data")\
	X(RS_WRITE_OUT,        "read: write data to disk")\
	X(RS_ACK,              "read: acknowledge")\
	X(WS_SEND_WWQ,         "write: send write request")\
	X(WS_ACK_FIRST,        "write: reopen port")\
	X(WS_READ_IN,          "write: read in data")\
	X(WS_SEND,             "write: send data out")\
	X(WS_ACK,              "write: acknowledge")\
	X(SM_ERROR_PACKET,     "r/w: process error/invalid packet")\
	X(SM_DONE,             "r/w: done")

typedef enum {
#define X(STATE, DESCRIPTION) STATE,
	TFTP_STATE_XMACRO

	TFTP_LAST_STATE
#undef X
} tftp_state_e;

const char *tftp_state_lookup(tftp_state_e state)
{
	static const char *descriptions[] = {
#define X(STATE, DESCRIPTION) DESCRIPTION,
	TFTP_STATE_XMACRO
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
	uint8_t buffer[TFTP_BUFFER_LENGTH];
	unsigned retry,        /**< number of tries */
		 tries;        /**< current try count */

	uint64_t now_ms, last_ms;
	long r;
	uint16_t local_block, 
		 remote_block;
	uint16_t new_port;
	tftp_state_e sm;

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
};

#define _POSIX_C_SOURCE 200809L

/**@todo ensure normalization of error codes, -1 == no-data, -2 == error, this
 * is for read/write and everything else as well.
 * @todo handle error packets
 * @todo log-levels */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

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

/**@warning This is a gaping security hole, 'tftp_fopen' should check whether
 * the file/path provided against a *white list* to ensure that it is correct */
static file_t tftp_fopen(char *file, bool read)
{
	assert(file);
	errno = 0;
	return fopen(file, read ? "rb" : "wb");
}

static size_t tftp_fread(file_t file, uint8_t *data, size_t length)
{
	assert(file);
	assert(data);
	errno = 0;
	return fread(data, 1, length, file);
}

static size_t tftp_fwrite(file_t file, uint8_t *data, size_t length)
{
	assert(file);
	assert(data);
	errno = 0;
	size_t r = fwrite(data, 1, length, file);
	fflush(file);
	return r;
}

static int tftp_fclose(file_t file)
{
	errno = 0;
	return fclose(file);
}

static tftp_addr_t *tftp_addr_allocate(struct addrinfo *p)
{
	tftp_addr_t *a = calloc(sizeof *a, 1);
	if(!a)
		goto fail;
	a->addr = calloc(p->ai_addrlen, 1);
	if(!(a->addr))
		goto fail;
	a->length = p->ai_addrlen;
	memcpy(a->addr, p->ai_addr, p->ai_addrlen);
	return a;
fail:
	if(a)
		free(a->addr);
	free(a);
	return NULL;
}

static void tftp_addr_free(tftp_addr_t *addr)
{
	if(!addr)
		return;
	free(addr->addr);
	free(addr);
}

/**@todo split into getaddrinfo and open functions */
static tftp_socket_t tftp_nopen(char *host, uint16_t port)
{
	int sockfd = -1;
	struct addrinfo hints, *servinfo, *p;
	char sport[32] = { 0 };
	tftp_socket_t rv = {
		.name = host,
		.port = port,
		.fd   = -1,
		.info = NULL
	};

	sprintf(sport, "%u", (unsigned)port);

	memset(&hints, 0, sizeof hints);
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if ((sockfd = getaddrinfo(host, sport, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(sockfd));
		return rv;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
			continue;
		break;
		/**@todo free servinfo?? */
	}
	//freeaddrinfo()

	if(sockfd == -1)
		return rv;

	if(!(rv.info = tftp_addr_allocate(p)))
		goto fail;

	if(fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0) {
		fprintf(stderr, "fcntrl O_NONBLOCK apply failed\n");
		goto fail;
	}

	rv.fd = sockfd;
	return rv;
fail:
	tftp_addr_free(rv.info);
	close(sockfd);
	rv.info = NULL;
	rv.fd = -1;
	return rv;
}

static long tftp_nread(tftp_socket_t *socket, uint8_t *data, size_t length, uint16_t *port)
{
	assert(data);
	assert(socket);
	errno = 0;
	*port = 0;

	struct sockaddr_storage their_addr;
	socklen_t addr_len = sizeof their_addr;
	errno = 0;
	long r = recvfrom(socket->fd, data, length, 0, (struct sockaddr *) &their_addr, &addr_len);
	if(r < 0)
		return r;
	if(their_addr.ss_family == AF_INET) {
		struct sockaddr_in *si = (struct sockaddr_in*)&their_addr;
		*port = ntohs(si->sin_port);
	} else {
		assert(their_addr.ss_family == AF_INET6);
		struct sockaddr_in6 *si = (struct sockaddr_in6*)&their_addr;
		*port = ntohs(si->sin6_port);
	}
	return r;
}

static long tftp_nwrite(tftp_socket_t *socket, uint8_t *data, size_t length)
{
	assert(data);
	assert(socket);
	errno = 0;
	tftp_addr_t *a = socket->info;
	return sendto(socket->fd, data, length, 0, (struct sockaddr *) a->addr, a->length);
	//return send(socket->fd, data, length, 0);
}

static int tftp_nclose(tftp_socket_t *socket)
{
	if(socket->info) {
		tftp_addr_t *a = (tftp_addr_t*)socket->info;
		free(a->addr);
		free(socket->info);
	}
	errno = 0;
	return close(socket->fd);
}

int tftp_nconnect(tftp_socket_t *socket, tftp_addr_t *addr)
{
	assert(addr);
	assert(addr->addr);
	struct addrinfo *p = addr->addr;
	if(connect(socket->fd, p->ai_addr, p->ai_addrlen) < 0)
		return -1;
	return 0;
}

static int tftp_logger(void *logger, char *fmt, va_list arg)
{
	assert(logger);
	assert(fmt);
	return vfprintf(logger, fmt, arg);
}

static uint64_t tftp_time_ms(void)
{
	uint64_t ms = 0, s = 0;
	struct timespec spec;
	clock_gettime(CLOCK_MONOTONIC, &spec);
	s = spec.tv_sec;
	//ms = round(spec.tv_nsec / 1.0e6); // Convert nanoseconds to milliseconds
	ms = spec.tv_nsec / 1.0e6;
	if (ms > 999uLL) {
		s++;
		ms = 0;
	}
	return (s * 1000uLL) + ms;
}

static void tftp_wait_ms(uint64_t ms)
{
	usleep(ms * 1000);
}

int tftp_init(tftp_t *t, char *file, char *host, uint16_t port, bool read, bool log_on)
{
	assert(t);
	assert(file);
	assert(!(t->initialized));

	t->file_name  =  file;
	t->retry      =  TFTP_DEFAULT_RETRY;
	t->sm         =  SM_INIT;
	t->read       =  read;
	t->log        =  stderr; /** @warning setting logging should always succeed */
	t->fopen      =  tftp_fopen;
	t->fread      =  tftp_fread;
	t->fwrite     =  tftp_fwrite;
	t->fclose     =  tftp_fclose;
	t->nopen      =  tftp_nopen;
	t->nread      =  tftp_nread;
	t->nwrite     =  tftp_nwrite;
	t->nclose     =  tftp_nclose;
	t->nconnect   =  tftp_nconnect;
	t->logger     =  tftp_logger;
	t->time_ms    =  tftp_time_ms;
	t->wait_ms    =  tftp_wait_ms;
	t->log_on     =  log_on;

	t->file       =  t->fopen(file, !read);

	if(!(t->file)) {
		msg(t, "file open ('%s'/%s) failed", file, !read ? "read" : "write");
		goto fail;
	}
	t->server = t->nopen(host, port);
	if(t->server.fd < 0) {
		msg(t, "socket open failed: %s:%u", host, (unsigned)port);
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

void tftp_done(tftp_t *t)
{
	assert(t);
	if(t->file && (t->fclose(t->file) < 0))
		msg(t, "closing file failed");
	if(t->server.fd > 0 && (t->nclose(&t->server) < 0))
		msg(t, "closing server socket failed");
}

/* -2 == error, -1 == try again, 0 == ok */
static int tftp_send_ack(tftp_t *t, tftp_socket_t *socket, uint16_t block)
{
	uint8_t b[4] = { 0, tftp_op_ack, block >> 8, block & 0xff };
	long r = t->nwrite(socket, b, sizeof b);
	if(r < 0) {
		if(errno == EAGAIN || errno == EWOULDBLOCK) /**@todo not portable, fix this */
			return -1;
		return -2;
	}
	return r;
}

/** -2 = failure, -1 = no-data, 512 = done, 0-511 = more data */
static int tftp_read_packet(tftp_t *t, tftp_socket_t *socket, uint16_t *port, uint16_t *block, tftp_opcode_e op)
{
	memset(t->buffer, 0, sizeof t->buffer);
	long r = t->nread(socket, t->buffer, sizeof t->buffer, port);
	if(r < 0) {
		if(errno == EAGAIN || errno == EWOULDBLOCK)  /**@todo not portable, fix this */
			return -1;
	}

	if(r < 4 || r > 516)
		return -2;
	if(t->buffer[0] != 0 || t->buffer[1] != op)
		return -2;
	*block = (t->buffer[2] << 8) | t->buffer[3];
	r -= 4;
	return r;
}

/**@todo separate out */
static int tftp_wrrq(tftp_t *t, bool read)
{
	assert(t);
	assert(t->file_name);
	static const char *mode = "octet";
	const size_t mode_length = strlen(mode);
	size_t length = strlen(t->file_name);
	if(length + mode_length + 4 >= 512)
		return -2;
	memset(t->buffer, 0, TFTP_BUFFER_LENGTH);
	t->buffer[0] = 0;
	t->buffer[1] = read ? tftp_op_rrq : tftp_op_wrq;
	memcpy(&t->buffer[2], t->file_name, length);
	memcpy(&t->buffer[2+length+1], mode, mode_length);
	return t->nwrite(&t->server, t->buffer, 4 + length + mode_length);
}

static uint64_t time_diff(uint64_t now, uint64_t past)
{
	return now-past;
}

static int tftp_fwrite_helper(tftp_t *t, long r)
{
	assert(r >= 0 && r <= 512);
	if(!r)
		return 0;
	if(t->fwrite(t->file, &t->buffer[4], r) != (size_t)r) {
		msg(t, "fwrite failed of size: %lu", r);
		return -1;
	}
	return 0;
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
	uint16_t op = (t->buffer[0] << 8) | t->buffer[1];
	if(op != tftp_op_error) {
		msg(t, "invalid packet");
		return -1;
	}
	uint16_t e  = (t->buffer[2] << 8) | t->buffer[3];
	const char *em = tftp_error_lookup(e);
	if(!e) 
		msg(t,"%s -> %s", em, &(t->buffer[4]));
	else
		msg(t,"%s", em);
	return 0;
}

/**@todo fully non-blocking version */
/**@todo check block number */
/**@todo re-connect when first valid packet received from TFTP server with new port */

static int tftp_new_port(tftp_t *t)
{
	tftp_socket_t data = t->nopen(t->server.name, t->new_port); /** @note being lazy here...*/
	if(data.fd < 0) {
		msg(t, "connect RECV-1 failed");
		return -2;
	} 
	tftp_addr_free(t->server.info);
	t->server.info = data.info;
	data.info = NULL;
	if(t->nclose(&data) < 0) {
		msg(t, "close failed");
		return -2;
	}
	errno = 0;
	/*if(t->nconnect(&t->server, t->server.info) < 0) {
		msg(t, "connect failed");
		return CS_ERROR;
	}*/
	msg(t, "connect @ %u", (unsigned)t->new_port);
	return 0;
}

typedef enum {
	CS_DONE,
	CS_WAIT,
	CS_CONTINUE,
	CS_ERROR = -1
} completion_state_e;

completion_state_e tftp_state_machine(tftp_t *t)
{
	switch(t->sm) {
	case SM_INIT:
		t->now_ms        =  0;
		t->last_ms       =  0;
		t->tries         =  t->retry;
		t->local_block =  1;
		t->remote_block  =  0;
		t->new_port      =  0;
		t->r             =  0;
		t->sm            =  t->read ? RS_SEND_RRQ : WS_SEND_WWQ;
		break;
	case RS_SEND_RRQ:
		if(tftp_wrrq(t, true) < 0) /** @todo handle non-block write */
			return CS_ERROR;
		t->sm = RS_RECV;
		t->last_ms = t->time_ms();
		break;
	case RS_RECV:
		t->now_ms = t->time_ms();
		t->r = tftp_read_packet(t, &t->server, &t->new_port, &t->remote_block, tftp_op_data);
		if(t->r == -2) {
			t->sm = SM_ERROR_PACKET;
		} else if(t->r == -1) {
			if(time_diff(t->now_ms, t->last_ms) > TFTP_TIME_OUT_MS) {
				if(t->tries-- == 0) {
					msg(t, "retry count exceeded");
					return CS_ERROR;
				}
				t->sm = t->local_block == 1 ? RS_SEND_RRQ : RS_RECV;
			}
			return CS_WAIT;
		} else {
			assert(t->r > 0);
			t->sm = t->local_block == 1 ? RS_RECV_FIRST_DONE: RS_ACK;
		}
		break;
	case RS_RECV_FIRST_DONE: /* The first received packet contains the port info we need */
		if(tftp_new_port(t) < 0)
			return CS_ERROR;
		t->sm = RS_ACK;
		break;
	case RS_ACK:
		if(tftp_send_ack(t, &t->server, t->local_block) < 0) {
			msg(t, "send ack failed");
			return CS_ERROR;
		} 
		msg(t, "ack %u", t->local_block);
		if(t->local_block == t->remote_block) {
			t->sm = RS_WRITE_OUT;
		} else {
			t->sm = RS_ACK;
			return CS_WAIT;
		}
		break;
	case RS_WRITE_OUT:
		if(t->local_block == t->remote_block) {
			t->tries = t->retry;
			if(tftp_fwrite_helper(t, t->r) < 0)
				return CS_ERROR;
			t->sm = t->r == 512 ? RS_RECV : SM_DONE;
			t->local_block++;
		} else {
			t->sm = RS_RECV;
		}
		break;

	case WS_SEND_WWQ:
		if(tftp_wrrq(t, false) < 0) /** @todo handle non-block write */
			return CS_ERROR;
		t->sm = WS_ACK;
		t->last_ms = t->time_ms();
		break;
	case WS_ACK:
		t->now_ms = t->time_ms();
		t->r = tftp_read_packet(t, &t->server, &t->new_port, &t->remote_block, tftp_op_ack);
		if(t->r == -2) {
			t->sm = SM_ERROR_PACKET;
		} else if(t->r == -1) {
			if(time_diff(t->now_ms, t->last_ms) > TFTP_TIME_OUT_MS) {
				if(t->tries-- == 0) {
					msg(t, "retry count exceeded");
					return CS_ERROR;
				}
				t->sm = t->local_block == 1 ? WS_SEND_WWQ : WS_READ_IN;
			}
			return CS_WAIT;
		} else {
			assert(t->r > 0);
			t->sm = t->local_block == 1 ? WS_ACK_FIRST: WS_READ_IN;
		}
		break;
	case WS_ACK_FIRST:
		if(tftp_new_port(t) < 0)
			return CS_ERROR;
		t->sm = WS_READ_IN;
		break;
	case WS_READ_IN:
	case WS_SEND:
		return CS_ERROR;
	case SM_ERROR_PACKET:
		tftp_error_print(t);
		return CS_ERROR;
	case SM_DONE: /**@todo wait around to make sure everything is finalized */
		return CS_DONE;
	default:
		msg(t, "invalid read state: %u", t->sm);
		return CS_ERROR;
	}
	return CS_CONTINUE;
}

int tftp_transaction(tftp_t *t)
{
	assert(t);
	completion_state_e cs = CS_ERROR;
        for(;;) {
		msg(t, "state(%u) -> %s", (unsigned)t->sm, tftp_state_lookup(t->sm));
		cs = tftp_state_machine(t);
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

int tftp(char *file, char *host, uint16_t port, bool read)
{
	tftp_t tftp;
	tftp_t *t = &tftp;
	memset(t, 0, sizeof *t);
	if(tftp_init(t, file, host, port, read, true) < 0) {
		msg(t, "initialization failed");
		return -1;
	}

	msg(t, "file '%s' (%s) -> %s:%u", file, read ? "read" : "write", host, (unsigned)port);

	if(tftp_transaction(t) < 0) {
		msg(t, "transaction failed");
		return -1;
	}
	tftp_done(t);
	return 0;
}

tftp_t *tftp_new(const tftp_functions_t *f, logger_t log)
{
	tftp_t *t = calloc(sizeof *t, 1);
	if(!t)
		return NULL;
	t->retry      =  TFTP_DEFAULT_RETRY;
	t->sm         =  SM_INIT;
	t->log        =  log;
	t->log_on     =  !!log;
	t->initialized = false;

	t->fopen      =  f->fopen;
	t->fread      =  f->fread;
	t->fwrite     =  f->fwrite;
	t->fclose     =  f->fclose;
	t->nopen      =  f->nopen;
	t->nread      =  f->nread;
	t->nwrite     =  f->nwrite;
	t->nclose     =  f->nclose;
	t->nconnect   =  f->nconnect;
	t->logger     =  f->logger;
	t->time_ms    =  f->time_ms;
	t->wait_ms    =  f->wait_ms;
	return t;
}

void tftp_free(tftp_t *t)
{
	if(t)
		tftp_done(t);
}

int main(int argc, char **argv)
{
	if(argc != 5)
		goto fail;
	uint16_t port = atoi(argv[4]);
	char *host = argv[3];
	char *file = argv[2];
	char *mode = argv[1];
	bool read  = true;
	if(!strcmp("-g", mode))
		read = true;
	else if(!strcmp("-p", mode))
		read = false;
	else
		goto fail;
	return tftp(file, host, port, read);
fail:
	fprintf(stderr, "usage: %s [-gp] file host port\n", argv[0]);
	return EXIT_FAILURE;

}

