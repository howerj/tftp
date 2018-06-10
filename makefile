# TFTP client/server
#
# Run with:
#
# TRACER = valgrind  # or ltrace, strace, gdb, etcetera.
# TRACER = 'gdb --args'
#
# PACKET = print  # print network packets
# PACKET = null   # normal operation
# PACKET = error  # introduce random errors for testing
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
PACKET=null
RM=rm -fvr

ifeq ($(OS),Windows_NT)
    OS := win
    # LDFLAGS +=
    CFLAGS += -mwindows
    LINK += -lws2_32
else # Assume Unix
    # detected_OS := $(shell uname -s)
    OS := unix
endif

SOURCES := ${TFTP}.c ${OS}.c ${PACKET}.c
OBJECTS := ${SOURCES:%.c=%.o}
DEPS    := ${SOURCES:%.c=%.d}
TRACER  =

.PHONY: all get put run clean doxygen check test

all: ${TFTP}

%.d: %.c
	${CC} -E -MMD $< >/dev/null

%.o: %.d %.c

${TFTP}: ${OS}.o ${TFTP}.o ${PACKET}.o
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

doxygen.conf:
	doxygen -g $@

doxygen: doxygen.conf
	doxygen $<

test: ${TFTP}
	${RM} t/${OS}.o t/${TFTP}.o
	cp ${OS}.o t/
	${RM} ${OS}.o
	-make server &
	make get GET=${OS}.o   PORT=${SPORT}
	make put PUT=${TFTP}.o PORT=${SPORT}
	cmp ${OS}.o t/${OS}.o
	cmp ${TFTP}.o t/${TFTP}.o
	killall -9 ${TFTP}

clean:
	${RM} ${TFTP}
	${RM} *.o
	${RM} *.d
	${RM} *.db
	${RM} *.log
	${RM} html/
	${RM} latex/
	${RM} doxygen.conf
