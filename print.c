#include "tftp.h"
#include <assert.h>
#include <stdio.h>
#include <ctype.h>

#define COLUMNS (16u)
#define REPLACE ('.')
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

int tftp_packet_process(bool send, uint8_t *buffer, size_t length)
{
	assert(buffer);
	FILE *out = stdout;
	fprintf(out, "%p(%zu): %s\n", buffer, length, send ? "TX" : "RX");
	for(size_t i = 0; i < length; i+= COLUMNS) {
		for(size_t j = i; j < MIN(length, i+COLUMNS); j++)
			fprintf(out, "%02x ", buffer[j]);
		fputs("\t|", out);
		for(size_t j = i; j < MIN(length, i+COLUMNS); j++)
			fputc(isgraph(buffer[j]) || buffer[j] == ' ' ? buffer[j] : REPLACE, out);
		fputs("|\n", out);
	}
	return 0;
}

