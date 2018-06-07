/* NOT IMPLEMENTED YET
 * NB. This is more likely to be incorrect as it will be tested less */

#include "tftp.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <direct.h>
#include <time.h>

//#pragma comment (lib, "Ws2_32.lib")

/**@todo normalize returned error values */

/* https://msdn.microsoft.com/en-us/library/ms679351%28v=VS.85%29.aspx
 * https://stackoverflow.com/questions/3400922/how-do-i-retrieve-an-error-string-from-wsagetlasterror */
static void winsock_perror(char *msg)
{
	wchar_t *s = NULL;
	int e = WSAGetLastError();
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
		       NULL, e,
		       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		       (LPWSTR)&s, 0, NULL);
	fprintf(stderr, "%s: (%d) %S\n", msg, e, s);
	LocalFree(s);
}

struct tftp_addr_t {
	struct addrinfo *addr; /**< address information for connect */
	size_t length;         /**< length of address information */
	struct sockaddr_storage their_addr;
	/*struct addrinfo *p;*/
};

static bool tcp_stack_initialized = false;

static void tcp_stack_init(void)
{
	static WSADATA wsaData;
	if(!tcp_stack_initialized) {
		if(WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
			winsock_perror("WSAStartup failed");
			exit(EXIT_FAILURE);
		}
		tcp_stack_initialized = true;
	}
}

static void tcp_stack_cleanup(void)
{
	if(tcp_stack_initialized && WSACleanup() != 0) {
		winsock_perror("WSACleanup() failed");
		exit(EXIT_FAILURE);
	}
}

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

static int tftp_nbind(tftp_socket_t *socket, const char *device, uint16_t port)
{ /**@todo find out if needed? */
	return TFTP_ERR_OK;
}

/**@todo split into getaddrinfo and open functions */
static tftp_socket_t tftp_nopen(const char *host, uint16_t port, bool server)
{
#if 0
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
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(sockfd));
		return rv;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		errno = 0;
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			fprintf(stderr, "socket fail: %s\n", strerror(errno));
			continue;
		}
		if(server) {
			errno = 0;
			if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
				fprintf(stderr, "socket fail: %s\n", strerror(errno));
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
#endif
	tcp_stack_init();
	tftp_socket_t rv = {
		.name = host,
		.port = port,
		.fd   = -1,
		.info = NULL
	};
	assert(INVALID_SOCKET == -1);

	return rv;
}

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
	tcp_stack_init();
	return sockaddr_storage_port(&socket->info->their_addr);
	return TFTP_ERR_FAILED;
}

static char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
	return NULL;
}

static void tftp_nhost(tftp_socket_t *socket, char host[static 64])
{
	assert(socket);
	assert(host);
	tcp_stack_init();
	get_ip_str((struct sockaddr *)&socket->info->their_addr, host, 64);
}

static long tftp_nread(tftp_socket_t *socket, uint8_t *data, size_t length)
{
	assert(data);
	assert(socket);
	tcp_stack_init();

	// (length = recvfrom(socket, data, length, 0, (struct sockaddr *) &si_other, &slen)

	return TFTP_ERR_FAILED;
}

static long tftp_nwrite(tftp_socket_t *socket, const uint8_t *data, size_t length)
{
	assert(data);
	assert(socket);
	tcp_stack_init();
	return TFTP_ERR_FAILED;
}

static int tftp_nclose(tftp_socket_t *socket)
{
	assert(socket);
	tcp_stack_init();
	int r = closesocket(socket->fd);
	socket->fd = INVALID_SOCKET;
	return r == SOCKET_ERROR ? TFTP_ERR_FAILED : TFTP_ERR_OK;
}

static int tftp_nconnect(tftp_socket_t *socket, tftp_addr_t *addr)
{
	assert(socket);
	assert(addr);
	tcp_stack_init();
	return TFTP_ERR_OK;
}

static int tftp_logger(void *logger, char *fmt, va_list arg)
{
	assert(logger);
	assert(fmt);
	return vfprintf(logger, fmt, arg);
}

/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms724950(v=vs.85).aspx */
static uint64_t tftp_time_ms(void)
{ /* @todo ensure monotonic, also increase time period between rollovers */
	uint64_t ms = 0;
	SYSTEMTIME st;
	GetSystemTime(&st);
	ms  = st.wMilliseconds;
	ms += st.wSecond * 1000uLL;
	ms += st.wMinute * 1000uLL * 60u;
	ms += st.wHour   * 1000uLL * 60u * 60u;
	return ms;
}

static void tftp_wait_ms(uint64_t ms)
{
	Sleep(ms);
}

static int tftp_chdir(const char *path)
{
	assert(path);
	return _chdir(path); /**@todo process error codes? */
}

/* This function list is exported */
const tftp_functions_t tftp_os_specific_functions = {
#define X(FUNCTION) .FUNCTION = tftp_ ## FUNCTION ,
TFTP_FUNCTIONS_XMACRO
#undef X
};

