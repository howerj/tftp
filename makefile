CFLAGS=-Wall -Wextra -std=gnu99 -g 

# SERVER=tftpd
CLIENT=tftp
RM=rm -fv

all: ${CLIENT}

%.d: %.c
	${CC} -E -MMD $< >/dev/null

%.o: %.d %.c

${CLIENT}: ${CLIENT}.o

-include ${CLIENT}.d

run: ${CLIENT}
	./${CLIENT}

clean:
	${RM} ${CLIENT}
	${RM} *.o
	${RM} *.d
