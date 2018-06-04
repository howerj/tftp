CFLAGS=-Wall -Wextra -std=gnu99 -g -O2
PORT=69
SERVER=127.0.0.1
GET=image1.bin
PUT=image2.bin
OS=unix
TFTP=tftp
RM=rm -fv

.PHONY: all get put run clean

all: ${TFTP}

%.d: %.c
	${CC} -E -MMD $< >/dev/null

%.o: %.d %.c

${TFTP}: ${TFTP}.o ${OS}.o

-include ${TFTP}.d ${OS}.d

get: ${TFTP}
	./${TFTP} -g ${GET} ${SERVER} ${PORT}

put: ${TFTP}
	./${TFTP} -p ${PUT} ${SERVER} ${PORT}

run: get

clean:
	${RM} ${TFTP}
	${RM} *.o
	${RM} *.d
