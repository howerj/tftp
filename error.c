#include "tftp.h"
#include <assert.h>
#include <stdlib.h>
#include <time.h>

/**@todo make better, and configurable, test bench */

#define NUMBER_OF_ELEMENTS_IN_ARRAY(X) (sizeof(X)/sizeof(X[0]))
#define LOG_ERROR                      (stdout)

typedef struct {
	unsigned frequency;
	double   probability;
} numbers_t;

typedef struct {
	numbers_t *numbers;
	size_t length;
	unsigned total_frequency;
} wheel_t;

typedef enum {
	NONE,
	RRQ,
	WRQ,
	DATA,
	ACK,
	ERROR,
} op_to_modify;

static numbers_t numbers[] = {
	[NONE]    = { .frequency = 50 },
	[RRQ]     = { .frequency = 0 },
	[WRQ]     = { .frequency = 0 },
	[DATA]    = { .frequency = 50 },
	[ACK]     = { .frequency = 50 },
	[ERROR]   = { .frequency = 0 },
};

static wheel_t wheel = {
	.numbers = numbers,
	.length = NUMBER_OF_ELEMENTS_IN_ARRAY(numbers),
	/* .total_frequency not set yet */
};

static bool init = false;

static void wheel_initialize(wheel_t *wheel)
{
	assert(wheel);
	assert(wheel->numbers);
	unsigned total = 0;
	numbers_t *n = wheel->numbers;
	for(size_t i = 0; i < wheel->length; i++)
		total += n[i].frequency;
	if(!total)
		return;
	for(size_t i = 0; i < wheel->length; i++)
		n[i].probability = (double)(n[i].frequency) / (double)(total);
	wheel->total_frequency = total;

	fprintf(LOG_ERROR, "total: %u\n", total);
	for(size_t i = 0; i < wheel->length; i++) {
		fprintf(LOG_ERROR, "%zu = %f\n", i, n[i].probability);
	}
}

static void initialize(void)
{
	if(init)
		return;	
	init = true;
	srand(time(NULL));
	tftp_set_logging_level(TFTP_LOG_LEVEL_ALL_ON);
	wheel_initialize(&wheel);
}

static double random_float(void)
{
	return ((float)rand()/(float)(RAND_MAX));
}

static size_t roulette(wheel_t *wheel)
{
	assert(wheel);
	double cumulative = 0;
	double random = random_float();
	for(size_t i = 0; i < wheel->length; i++) {
		cumulative += wheel->numbers[i].probability;
		if(cumulative > random)
			return i;
	}
	return -1; 
}

static void blk(uint8_t *buffer, size_t length)
{
	assert(buffer);
	if(length < 4)
		return;
	buffer[HD_BLOCK_NUMBER_HI] = 0;
	buffer[HD_BLOCK_NUMBER_LO] = 0;
}

int tftp_packet_process(bool send, uint8_t *buffer, size_t length)
{
	assert(buffer);
	initialize();
	size_t i = roulette(&wheel);
	tftp_opcode_e op = buffer[0] << 8 | buffer[1];
	if(op != i)
		return 0;

	tftp_debug(LOG_ERROR, "MODIFYING(%u) %s %zu", (unsigned)op, send ? "TX" : "RX", length);

	switch(roulette(&wheel)) {
	case NONE:
		break;
	case RRQ:
		break;
	case WRQ:
		break;
	case DATA: 
		blk(buffer, length);
		break;
	case ACK: 
		blk(buffer, length);
		break;
	case ERROR:
		break;
	}

	return 1;
}


