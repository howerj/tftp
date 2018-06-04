CFLAGS=-Wall -Wextra -std=gnu99 -g -O2
PORT=69
SERVER=127.0.0.1
GET=image1.bin
PUT=image2.bin
OS=unix
TFTP=tftp
RM=rm -fv

SOURCES := ${wildcard *.c}
OBJECTS := ${SOURCES:%.c=%.o}
DEPS    := ${SOURCES:%.c=%.d}


.PHONY: all get put run clean

all: ${TFTP}

%.d: %.c
	${CC} -E -MMD $< >/dev/null

%.o: %.d %.c

${TFTP}: ${TFTP}.o ${OS}.o

-include ${DEPS}

get: ${TFTP}
	./${TFTP} -g ${GET} ${SERVER} ${PORT}

put: ${TFTP}
	./${TFTP} -p ${PUT} ${SERVER} ${PORT}

run: get

check:
	cppcheck --enable=all ${SOURCES}

clean:
	${RM} ${TFTP}
	${RM} *.o
	${RM} *.d
