#include "tftp.h"
#define _POSIX_C_SOURCE 200809L

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
#include <limits.h>

#define ERROR_LOG (stdout)

struct tftp_addr_t {
	struct addrinfo *addr; /**< address information for connect */
	size_t length;         /**< length of address information */
	struct sockaddr_storage their_addr;
	/*struct addrinfo *p;*/
};

/**@warning This is a gaping security hole, 'tftp_fopen' should check whether
 * the file/path provided against a *white list* to ensure that it is correct */
static file_t tftp_fopen(char *file, bool read)
{
	assert(file);
	errno = 0;
	return fopen(file, read ? "rb" : "wb");
}

static long tftp_fread(file_t file, uint8_t *data, size_t length)
{
	assert(file);
	assert(data);
	assert(length < LONG_MAX);
	errno = 0;
	long r = fread(data, 1, length, file);
	if(r == 0 && ferror(file))
		return TFTP_ERR_FAILED;
	return r;
}

static long tftp_fwrite(file_t file, uint8_t *data, size_t length)
{
	assert(file);
	assert(data);
	errno = 0;
	size_t r = fwrite(data, 1, length, file);
	fflush(file);
	return ferror(file) ? (long)TFTP_ERR_FAILED: (long)r;
}

static int tftp_fclose(file_t file)
{
	errno = 0;
	int r = fclose(file);
	return errno ? TFTP_ERR_FAILED : r;
}

static tftp_addr_t *tftp_addr_allocate(struct addrinfo *p)
{
	tftp_addr_t *a = calloc(sizeof *a, 1);
	if(!a)
		goto fail;
	a->addr   = p;
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
static tftp_socket_t tftp_nopen(const char *host, uint16_t port, bool server)
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
	hints.ai_flags    = server ? AI_PASSIVE : hints.ai_flags; 

	if ((sockfd = getaddrinfo(host/*server ? NULL : host*/, sport, &hints, &servinfo)) != 0) {
		fprintf(ERROR_LOG, "getaddrinfo: %s\n", gai_strerror(sockfd));
		return rv;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		errno = 0;
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			fprintf(ERROR_LOG, "socket fail: %s\n", strerror(errno));
			continue;
		}
		if(server) {
			errno = 0;
			if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
				fprintf(ERROR_LOG, "socket fail: %s\n", strerror(errno));
				close(sockfd);
				sockfd = -1;
				continue;
			}
		}
		break;
	}

	if(sockfd == -1)
		goto fail;

	if(!(rv.info = tftp_addr_allocate(p)))
		goto fail;

	if(fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0) {
		fprintf(ERROR_LOG, "fcntrl O_NONBLOCK apply failed\n");
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

/*void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}*/

static uint16_t sockaddr_storage_port(struct sockaddr_storage *ss)
{
	assert(ss);
	if(ss->ss_family == AF_INET) {
		struct sockaddr_in *si = (struct sockaddr_in*)ss;
		return ntohs(si->sin_port);
	} 
	assert(ss->ss_family == AF_INET6);
	struct sockaddr_in6 *si = (struct sockaddr_in6*)ss;
	return ntohs(si->sin6_port);
}

static uint16_t tftp_nport(tftp_socket_t *socket)
{
	assert(socket);
	assert(socket->info);
	return sockaddr_storage_port(&socket->info->their_addr);
}

static char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
	assert(sa);
	assert(s);
	switch(sa->sa_family) {
	case AF_INET:
		inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr), s, maxlen);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr), s, maxlen);
		break;
	default:
		strncpy(s, "Unknown AF", maxlen);
		return NULL;
	}
	return s;
}

static void tftp_nhost(tftp_socket_t *socket, char host[static 64])
{
	assert(socket);
	assert(host);
	get_ip_str((struct sockaddr *)&socket->info->their_addr, host, 64);
}

static long tftp_nread(tftp_socket_t *socket, uint8_t *data, size_t length)
{
	assert(data);
	assert(socket);
	errno = 0;
	/**@todo receive from specific port? Needed for multiple connections */
	struct sockaddr_storage *their_addr = &socket->info->their_addr;
	socklen_t addr_len = sizeof(*their_addr);
	errno = 0;
	long r = recvfrom(socket->fd, data, length, 0, (struct sockaddr *) their_addr, &addr_len);
	if(r < 0) {
		if(errno == EAGAIN || errno == EWOULDBLOCK)
			return TFTP_ERR_NO_BLOCK;
		return TFTP_ERR_FAILED;
	}
	return r;
}

static long tftp_nwrite(tftp_socket_t *socket, const uint8_t *data, size_t length)
{
	assert(data);
	assert(socket);
	tftp_addr_t *a = socket->info;
	errno = 0;
	long r = sendto(socket->fd, data, length, 0, (struct sockaddr *) a->addr, a->length);
	if(r < 0) {
		if(errno == EAGAIN || errno == EWOULDBLOCK)
			return TFTP_ERR_NO_BLOCK;
		return TFTP_ERR_FAILED;
	}
	return r;
}

static int tftp_nclose(tftp_socket_t *socket)
{
	assert(socket);
	if(socket->info) {
		tftp_addr_t *a = socket->info;
		if(a) {
			free(a->addr);
			a->addr = NULL;
		}
		free(socket->info);
		socket->info = NULL;
	}
	errno = 0;
	int r = close(socket->fd);
	socket->fd = -1;
	return r;
}

static int tftp_nconnect(tftp_socket_t *socket, tftp_addr_t *addr)
{
	assert(socket);
	assert(addr);
	assert(addr->addr);
	struct addrinfo *p = addr->addr;
	errno = 0;
	if(connect(socket->fd, p->ai_addr, p->ai_addrlen) < 0)
		return TFTP_ERR_FAILED;
	return TFTP_ERR_OK;
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
	usleep(ms * 1000uLL);
}

static int tftp_chdir(const char *path)
{
	assert(path);
	return chdir(path);
}

/* This function list is exported */
const tftp_functions_t tftp_os_specific_functions = {
#define X(FUNCTION) .FUNCTION = tftp_ ## FUNCTION ,
TFTP_FUNCTIONS_XMACRO
#undef X
};

