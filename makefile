#
# Run with:
#
# TRACER = valgrind  # or ltrace, strace, gdb, etcetera.
#
# For debugging.
#

CFLAGS=-Wall -Wextra -std=gnu99 -g -O2
PORT=69
SERVER=127.0.0.1

SPORT=6969
DIRECTORY=t/
DEVICE=127.0.0.1

GET=image1.bin
PUT=image2.bin
TFTP=tftp
RM=rm -fv

ifeq ($(OS),Windows_NT)
    OS := win
    # LDFLAGS +=
    CFLAGS += -mwindows
    LINK += -lws2_32
else # Assume Unix
    # detected_OS := $(shell uname -s)
    OS := unix
endif

SOURCES := ${TFTP}.c ${OS}.c
OBJECTS := ${SOURCES:%.c=%.o}
DEPS    := ${SOURCES:%.c=%.d}
TRACER  =

.PHONY: all get put run clean

all: ${TFTP}

%.d: %.c
	${CC} -E -MMD $< >/dev/null

%.o: %.d %.c

${TFTP}: ${OS}.o ${TFTP}.o
	${CC} ${CFLAGS} ${LDFLAGS} $^ ${LINK} -o $@

-include ${DEPS}

get: ${TFTP}
	${TRACER} ./${TFTP} -g ${GET} ${SERVER} ${PORT}

put: ${TFTP}
	${TRACER} ./${TFTP} -p ${PUT} ${SERVER} ${PORT}

server: ${TFTP}
	${TRACER} ./${TFTP} -s ${DIRECTORY} ${DEVICE} ${SPORT}

run: get

check:
	cppcheck --enable=all ${SOURCES}

clean:
	${RM} ${TFTP}
	${RM} *.o
	${RM} *.d
