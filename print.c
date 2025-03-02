#include "tftp.h"
#include <assert.h>
#include <stdio.h>
#include <ctype.h>

#define COLUMNS (16u)
#define REPLACE ('.')
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))

int tftp_packet_process(bool send, const uint8_t *buffer, size_t length) {
	assert(buffer);
	FILE *out = stdout;
	if (fprintf(out, "%p(%u): %s\n", buffer, (unsigned)length, send ? "TX" : "RX") < 0) return -1;
	for (size_t i = 0; i < length; i+= COLUMNS) {
		for (size_t j = i; j < MIN(length, i+COLUMNS); j++)
			if (fprintf(out, "%02x ", buffer[j]) < 0) return -1;
		if (fputs("\t|", out) < 0) return -1;
		for (size_t j = i; j < MIN(length, i+COLUMNS); j++)
			if (fputc(isgraph(buffer[j]) || buffer[j] == ' ' ? buffer[j] : REPLACE, out) < 0) return -1;
		if (fputs("|\n", out) < 0) return -1;
	}
	return 0;
}

