CFLAGS=-Wall -Wextra -std=gnu99 -g 

PORT=69
SERVER=127.0.0.1
GET=image1.bin
PUT=image2.bin


# SERVER=tftpd
CLIENT=tftp
RM=rm -fv

.PHONY: all get put run clean

all: ${CLIENT}

%.d: %.c
	${CC} -E -MMD $< >/dev/null

%.o: %.d %.c

${CLIENT}: ${CLIENT}.o

-include ${CLIENT}.d

get: ${CLIENT}
	./${CLIENT} -g ${GET} ${SERVER} ${PORT}

put: ${CLIENT}
	./${CLIENT} -p ${PUT} ${SERVER} ${PORT}

run: get

clean:
	${RM} ${CLIENT}
	${RM} *.o
	${RM} *.d
