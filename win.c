/* NOT IMPLEMENTED YET
 * NB. This is more likely to be incorrect as it will be tested less */

#define _WIN32_WINNT 0x0600
#include "tftp.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <direct.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <conio.h>

#define ESC (27) /**< ASCII Escape Character */

#ifndef SIO_UDP_CONNRESET 
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12) 
#endif

#define ERROR_LOG (stdout)
#undef  tftp_debug
#define tftp_debug(...)

/*#pragma comment(lib, "Ws2_32.lib")*/

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
	tftp_error(ERROR_LOG, "%s: (%d) %S", msg, e, s);
	LocalFree(s);
}

struct tftp_addr_t {
	struct addrinfo *addr; /**< address information for connect */
	size_t length;         /**< length of address information */
	struct sockaddr_storage their_addr;
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

/*static void tcp_stack_cleanup(void)
{
	if(tcp_stack_initialized && WSACleanup() != 0) {
		winsock_perror("WSACleanup() failed");
		exit(EXIT_FAILURE);
	}
}*/

/**@warning This is a gaping security hole, 'tftp_fopen' should check whether
 * the file/path provided against a *white list* to ensure that it is correct */
static file_t tftp_fopen(char *file, bool read)
{
	assert(file);
	tftp_debug(ERROR_LOG, "fopen(%s, %s)", file, read ? "rb" : "wb");
	errno = 0;
	return fopen(file, read ? "rb" : "wb");
}

static long tftp_fread(file_t file, uint8_t *data, size_t length)
{
	assert(file);
	assert(data);
	assert(length < LONG_MAX);
	tftp_debug(ERROR_LOG, "fread(%p, %p, %u)", file, data, (unsigned)length);
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
	tftp_debug(ERROR_LOG, "fwrite(%p, %p, %u)", file, data, (unsigned)length);
	errno = 0;
	size_t r = fwrite(data, 1, length, file);
	fflush(file);
	return ferror(file) ? (long)TFTP_ERR_FAILED: (long)r;
}

static int tftp_fclose(file_t file)
{
	tftp_debug(ERROR_LOG, "fclose(%p)", file);
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
	tftp_debug(ERROR_LOG, "addr_free(%p)", addr);

	if(!addr)
		return;
	/*@bug This 'free' causes problems on Windows, it's invalid and
	 * causes a signal to be raised */

	free(addr->addr);
	addr->addr = NULL;
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
	tcp_stack_init();
	assert((int)INVALID_SOCKET == -1);

	tftp_debug(ERROR_LOG, "nopen(%s, %u, %s)", host, (unsigned)port, server ? "server" : "client");
	sprintf(sport, "%u", (unsigned)port);

	memset(&hints, 0, sizeof hints);
	hints.ai_family   = AF_INET; //AF_UNSPEC; /** @bug IPV4 only */
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags    = server ? AI_PASSIVE : hints.ai_flags;

	if ((sockfd = getaddrinfo(host/*server ? NULL : host*/, sport, &hints, &servinfo)) != 0) {
		tftp_error(ERROR_LOG, "getaddrinfo: %s", gai_strerror(sockfd));
		return rv;
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		errno = 0;
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			tftp_error(ERROR_LOG, "socket fail: %s", strerror(errno));
			winsock_perror("socket() failed");
			continue;
		}
		if(server) {
			errno = 0;
			if(bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
				tftp_error(ERROR_LOG, "bind fail: %s", strerror(errno));
				winsock_perror("bind() failed");
				closesocket(sockfd);
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

	u_long mode = 1; /* 1 = non-blocking socket */
	if(ioctlsocket(sockfd, FIONBIO, &mode) < 0) {
		tftp_error(ERROR_LOG, "ioctlsocket non-blocking apply failed");
		winsock_perror("ioctlsocket() failed");
		goto fail;
	}

	{ /* Fix some UDP junk, see <https://web.archive.org/web/20061025233722/http://blog.devstone.com/aaron/archive/2005/02/20.aspx> */
		DWORD ioctl_length = 0;
		BOOL behave = false;
		if(WSAIoctl(sockfd, SIO_UDP_CONNRESET, &behave,
					  sizeof(behave), NULL, 0,
					  &ioctl_length, NULL, NULL) == SOCKET_ERROR) {
			tftp_error(ERROR_LOG, "WSAIoctl UDP fix apply failed");
			winsock_perror("WSAIoctl failed");
			goto fail;
		}
	}

	rv.fd = sockfd;
	return rv;
fail:
	tftp_error(ERROR_LOG, "socket open failed");
	tftp_addr_free(rv.info);
	if(sockfd != (int)INVALID_SOCKET)
		closesocket(sockfd);
	rv.info = NULL;
	rv.fd = -1;
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
}

/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms738532(v=vs.85).aspx */
static char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
	assert(sa);
	assert(s);
	char server_info[NI_MAXSERV] = { 0 };
	/* InetNtop could not be found for some reason, so getnameinfo is used */
	return getnameinfo((struct sockaddr *) &sa,
                           sizeof (struct sockaddr),
                           s,
                           maxlen/*NI_MAXHOST*/, server_info, NI_MAXSERV, NI_NUMERICSERV) ? NULL :s;
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
	tftp_debug(ERROR_LOG, "nread(%p, %p, %u)", socket, data, (unsigned)length);
	struct sockaddr_storage *their_addr = &socket->info->their_addr;
	int addr_len = sizeof(*their_addr);
	errno = 0;
	WSASetLastError(0);
	long r = recvfrom(socket->fd, (char*)data, length, 0, (struct sockaddr *) their_addr, &addr_len);
	if(r < 0) {
		if(WSAEWOULDBLOCK == WSAGetLastError())
			return TFTP_ERR_NO_BLOCK;
		winsock_perror("nread failed");
		return TFTP_ERR_FAILED;
	}
	return r;
}

static long tftp_nwrite(tftp_socket_t *socket, const uint8_t *data, size_t length)
{
	assert(data);
	assert(socket);
	tftp_addr_t *a = socket->info;
	tftp_debug(ERROR_LOG, "nwrite(%p, %p, %u)", socket, data, (unsigned)length);
	errno = 0;
	WSASetLastError(0);
	long r = sendto(socket->fd, (char*)data, length, 0, (struct sockaddr *) a->addr, a->length);
	if(r < 0) {
		if(WSAEWOULDBLOCK == WSAGetLastError())
			return TFTP_ERR_NO_BLOCK;
		winsock_perror("nwrite failed");
		return TFTP_ERR_FAILED;
	}
	return r;
}

static int tftp_nclose(tftp_socket_t *socket)
{
	assert(socket);
	tcp_stack_init();
	assert(socket);
	tftp_debug(ERROR_LOG, "nclose(%p)", socket);
	if(socket->info) {
		tftp_addr_t *a = socket->info;
		if(a) {
			// free(a->addr); // @bug Windows double free if left in
			a->addr = NULL;
		}
		free(socket->info);
		socket->info = NULL;
	}
	int r = closesocket(socket->fd);
	socket->fd = INVALID_SOCKET;
	return r == SOCKET_ERROR ? TFTP_ERR_FAILED : TFTP_ERR_OK;
}

static int tftp_nconnect(tftp_socket_t *socket, tftp_addr_t *addr)
{
	assert(socket);
	assert(addr);
	assert(addr->addr);
	tcp_stack_init();
	struct addrinfo *p = addr->addr;
	errno = 0;
	if(connect(socket->fd, p->ai_addr, p->ai_addrlen) < 0) {
		winsock_perror("nconnect failed");
		return TFTP_ERR_FAILED;
	}
	return TFTP_ERR_OK;
}

static int tftp_logger(logger_t logger, char *fmt, va_list arg)
{
	assert(logger);
	assert(fmt);
	int r = vfprintf(logger, fmt, arg);
	fflush(logger);
	return r;
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
	tftp_debug(ERROR_LOG, "time_ms(%u)", (unsigned)ms);
	return ms;
}

static void tftp_wait_ms(uint64_t ms)
{
	tftp_debug(ERROR_LOG, "sleep(%u)", (unsigned)ms);
	Sleep(ms);
}

static int tftp_chdir(const char *path)
{
	assert(path);
	tftp_debug(ERROR_LOG, "chdir(%s)", path);
	return _chdir(path); /**@todo process error codes? */
}

static bool tftp_quit(void)
{
	if(_kbhit()) {
		int ch = _getch();
		tftp_info(ERROR_LOG, "getch() = %d", ch);
		if(/*ch == EOF || */ch == ESC)
			return true;
	}
	return false;
}

/* This function list is exported */
const tftp_functions_t tftp_os_specific_functions = {
#define X(FUNCTION) .FUNCTION = tftp_ ## FUNCTION ,
TFTP_FUNCTIONS_XMACRO
#undef X
};

