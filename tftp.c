/**@brief Embeddable and Non-Blocking TFTP server client
 * @author Richard James Howe
 * @license MIT
 * @copyright Richard James Howe (2018)
 * @email howe.r.j.89@gmail.com
 * @repository <https://github.com/howerj/tftp> */

#include "tftp.h"

#define _POSIX_C_SOURCE 200809L

/**@todo ensure normalization of error codes, -1 == no-data, -2 == error, this
 * is for read/write and everything else as well. */

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
	if(t->log_on) {
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

static void *allocate(size_t bytes)
{
	void *r = NULL;
	errno = 0;
	r = calloc(bytes, 1);
	if(!r) {
		fprintf(stderr, "allocate of size %zu failed: %s\n", bytes, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return r;
}

/**@warning This is a gaping security hole, 'tftp_fopen' should check whether
 * the file/path provided against a *white list* to ensure that it is correct */
static void *tftp_fopen(void *file, bool read)
{
	assert(file);
	errno = 0;
	return fopen(file, read ? "rb" : "wb");
}

static size_t tftp_fread(void *file, uint8_t *data, size_t length)
{
	assert(file);
	assert(data);
	errno = 0;
	return fread(data, 1, length, file);
}

static size_t tftp_fwrite(void *file, uint8_t *data, size_t length)
{
	assert(file);
	assert(data);
	errno = 0;
	size_t r = fwrite(data, 1, length, file);
	fflush(file);
	return r;
}

static int tftp_fclose(void *file)
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
	int r = recvfrom(socket->fd, data, length, 0, (struct sockaddr *) &their_addr, &addr_len);
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
	t->file_name = file;
	t->retry     = TFTP_DEFAULT_RETRY;

	t->read    =  read;
	t->log     =  stderr; /** @warning setting logging should always succeed */
	t->fopen   =  tftp_fopen;
	t->fread   =  tftp_fread;
	t->fwrite  =  tftp_fwrite;
	t->fclose  =  tftp_fclose;
	t->nopen   =  tftp_nopen;
	t->nread   =  tftp_nread;
	t->nwrite  =  tftp_nwrite;
	t->nclose  =  tftp_nclose;
	t->nconnect=  tftp_nconnect;
	t->logger  =  tftp_logger;
	t->time_ms =  tftp_time_ms;
	t->wait_ms =  tftp_wait_ms;
	t->log_on  =  log_on;

	t->file    =  t->fopen(file, !read);
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
	/**@todo free data properly */
	/* NB. server == data, but with a different port, don't close it! */
}

/* -2 == error, -1 == try again, 0 == ok */
static int tftp_send_ack(tftp_t *t, tftp_socket_t *socket, uint16_t block)
{
	uint8_t b[4] = { 0, tftp_op_ack, block >> 8, block & 0xff };
	long r = t->nwrite(socket, b, sizeof b);
	if(r < 0) {
		if(errno == EAGAIN || errno == EWOULDBLOCK)
			return -1;
		return -2;
	}
	return r;
}

/** -2 = failure, -1 = no-data, 512 = done, 0-511 = more data */
static int tftp_read_data_packet(tftp_t *t, tftp_socket_t *socket, uint16_t *port, uint16_t *block)
{
	memset(t->buffer, 0, sizeof t->buffer);
	long r = t->nread(socket, t->buffer, sizeof t->buffer, port);
	if(r < 0) {
		if(errno == EAGAIN || errno == EWOULDBLOCK)
			return -1;
	}

	if(r < 4 || r > 516)
		return -2;
	if(t->buffer[0] != 0 || t->buffer[1] != tftp_op_data)
		return -2;
	*block = (t->buffer[2] << 8) | t->buffer[3];
	r -= 4;
	return r;
}

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

/**@todo fully non-blocking version */
/**@todo check block number */
/**@todo re-connect when first valid packet received from TFTP server with new port */
int tftp_reader(tftp_t *t)
{
	uint64_t now_ms = 0, last_ms = 0;
	long r = 0;
	unsigned retry = t->retry;
	uint16_t block = 1;
	uint16_t actual_block = 0;
	uint16_t port = 0;

	typedef enum { /**@todo need more states for First Reception/Connection, non-block read/write*/
		RS_SEND_RRQ,
		RS_RECV_FIRST_DONE,
		RS_RECV,
		RS_WRITE_OUT,
		RS_ACK,
		RS_DONE,
	} reader_state_e;

	for(reader_state_e rs = RS_SEND_RRQ; rs != RS_DONE;) {
		msg(t, "state: %u", (unsigned)rs);
		switch(rs) {
		case RS_SEND_RRQ:
			if(tftp_wrrq(t, true) < 0) /** @todo do non-block write */
				return -1;
			rs = RS_RECV;
			last_ms = t->time_ms();
			break;
		case RS_RECV:
			now_ms = t->time_ms();
			r = tftp_read_data_packet(t, &t->server, &port, &actual_block);
			if(r == -2) {
				msg(t, "invalid packet received");
				return -1;
			} else if(r == -1) {
				if(time_diff(now_ms, last_ms) > TFTP_TIME_OUT_MS) {
					if(retry-- == 0) {
						msg(t, "retry count exceeded");
						return -1;
					}
					rs = block == 1 ? RS_SEND_RRQ : RS_RECV;
				}
				t->wait_ms(/*TFTP_SLEEP_MS*/0);
			} else {
				assert(r > 0);
				rs = block == 1 ? RS_RECV_FIRST_DONE: RS_ACK;
			}
			break;
		case RS_RECV_FIRST_DONE: /* The first received packet contains the port info we need */
		{
			tftp_socket_t data = t->nopen(t->server.name, port); /** @note being lazy here...*/
			if(data.fd < 0) {
				msg(t, "connect RECV-1 failed");
				return -1;
			} 
			tftp_addr_free(t->server.info);
			t->server.info = data.info;
			data.info = NULL;
			if(t->nclose(&data) < 0) {
				msg(t, "close failed");
				return -1;
			}
			/*if(t->nconnect(&t->server, t->server.info) < 0) {
				msg(t, "connect failed");
				return -1;
			}*/
			msg(t, "connect @ %u", (unsigned)port);
			rs = RS_ACK;
		}
			break;
		case RS_ACK:
			if(tftp_send_ack(t, &t->server, block) < 0) {
				msg(t, "send ack failed");
				return -1;
			} 
			msg(t, "ack %u", block);
			if(block == actual_block) {
				rs = RS_WRITE_OUT;
			} else {
				rs = RS_ACK;
				t->wait_ms(1000);
			}
			break;
		case RS_WRITE_OUT:
			if(block == actual_block) {
				retry = t->retry;
				if(tftp_fwrite_helper(t, r) < 0)
					return -1;
				rs = r == 512 ? RS_RECV : RS_DONE;
				block++;
			} else {
				rs = RS_RECV;
			}
			break;
		case RS_DONE:
			return 0;
		default:
			msg(t, "invalid state: %u", rs);
			return -1;
		}
	}

	return 0;
}

int tftp_writer(tftp_t *t)
{
	return 0;
}

int tftp_transaction(tftp_t *t)
{
	assert(t);
	return t->read ? tftp_reader(t) : tftp_writer(t);
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

int main(void)
{
	return tftp("image.bin", "127.0.0.1", TFTP_DEFAULT_PORT, true);
}

