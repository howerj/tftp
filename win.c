/* NOT IMPLEMENT YET */

#include "tftp.h"
#include <stdlib.h>
#include <stdio.h>

#include <string.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#pragma comment (lib, "Ws2_32.lib")

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

static int tftp_nbind(tftp_socket_t *socket, const char *device, uint16_t port)
{ /**@todo find out if needed? */
	return TFTP_ERR_OK;
}

/**@todo split into getaddrinfo and open functions */
static tftp_socket_t tftp_nopen(const char *host, uint16_t port, bool server)
{
	tftp_socket_t rv = {
		.name = host,
		.port = port,
		.fd   = -1,
		.info = NULL
	};
	return rv;
}

static uint16_t sockaddr_storage_port(struct sockaddr_storage *ss)
{
	return 0;
}

static uint16_t tftp_nport(tftp_socket_t *socket)
{
	assert(socket);
	assert(socket->info);
	return sockaddr_storage_port(&socket->info->their_addr);
}

static char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
	return NULL;
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
	return -1;
}

static long tftp_nwrite(tftp_socket_t *socket, const uint8_t *data, size_t length)
{
	assert(data);
	assert(socket);
	return -1;
}

static int tftp_nclose(tftp_socket_t *socket)
{
	socket->fd = -1;
	return r;
}

int tftp_nconnect(tftp_socket_t *socket, tftp_addr_t *addr)
{
	assert(addr);
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
	exit(EXIT_FAILURE);
	return 0;
}

static void tftp_wait_ms(uint64_t ms)
{
	
}

static int tftp_chdir(const char *path)
{
	assert(path);
	return -1;
}

/* This function list is exported */
const tftp_functions_t tftp_os_specific_functions = {
#define X(FUNCTION) .FUNCTION = tftp_ ## FUNCTION ,
TFTP_FUNCTIONS_XMACRO
#undef X
};

