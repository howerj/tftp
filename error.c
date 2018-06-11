/**@brief This module modifies TFTP packets sent and received by
 * the TFTP client and server for testing purposes by injecting
 * errors in a configurable manner. */

#include "tftp.h"
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>

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
	OPCODE
} op_to_modify;

static numbers_t numbers[] = {
	[NONE]    = { .frequency = 100 },
	[RRQ]     = { .frequency = 0 },
	[WRQ]     = { .frequency = 0 },
	[DATA]    = { .frequency = 0 },
	[ACK]     = { .frequency = 0 },
	[ERROR]   = { .frequency = 0 },
	[OPCODE]  = { .frequency = 0 },
};

typedef enum {
	BFM_NULLED,
	BFM_RANDOM,
	BFM_FIXED,
	BFM_LAST_METHOD,
} fail_method;

#define CONFIGURATION_FILE ("error.conf")

static unsigned failure_value_fixed = 0;

static fail_method fm_opcode = BFM_RANDOM, 
		   fm_error  = BFM_RANDOM, 
		   fm_ack    = BFM_RANDOM, 
		   fm_data   = BFM_RANDOM;

#define CONFIGURATION_X_MACRO\
	X("freq.none",   &numbers[NONE].frequency,   unsigned)\
	X("freq.rrq",    &numbers[RRQ].frequency,    unsigned)\
	X("freq.wrq",    &numbers[WRQ].frequency,    unsigned)\
	X("freq.data",   &numbers[DATA].frequency,   unsigned)\
	X("freq.ack",    &numbers[ACK].frequency,    unsigned)\
	X("freq.error",  &numbers[ERROR].frequency,  unsigned)\
	X("freq.opcode", &numbers[OPCODE].frequency, unsigned)\
	X("fm.opcode",   &fm_opcode,                 unsigned)\
	X("fm.error",    &fm_error,                  unsigned)\
	X("fm.ack",      &fm_ack,                    unsigned)\
	X("fm.data",     &fm_data,                   unsigned)\
	X("failure.fix", &failure_value_fixed,       unsigned)

typedef enum {
	double_t,
	unsigned_t,
} type_t;

typedef struct {
	char *name;  /**< name of configuration item */
	void *data;  /**< pointer to data for configuration item */
	type_t type; /**< data type of *data */
} config_t; /**< configuration item */

static config_t config[] = { /**< module configuration structure */
#define X(NAME, DATA, TYPE) { .name = NAME, .data = DATA, .type = TYPE ## _t },
	CONFIGURATION_X_MACRO
#undef X
};

static double configuration_get(config_t *c)
{
	assert(c);
	switch(c->type) {
	case double_t:   return *((double*)(c->data));
	case unsigned_t: return *((unsigned*)(c->data));
	default: tftp_fatal(LOG_ERROR, "unknown type %u", c->type);
	}
	return 0.0;
}

static void configuration_set(config_t *c, double v)
{
	assert(c);
	switch(c->type) {
	case double_t:   *((double*)(c->data))   = v; break;
	case unsigned_t: *((unsigned*)(c->data)) = v; break;
	default: tftp_fatal(LOG_ERROR, "unknown type %u", c->type);
	}
}

static int configuration_save_file(const char *file, config_t *c, size_t length)
{
	FILE *f = fopen(file, "wb");
	if(!f) {
		tftp_debug(LOG_ERROR, "unable to open %s/rb: ", file, strerror(errno));
		return -1;
	}
	for(size_t i = 0; i < length; i++)
		fprintf(f, "%s %f\n", c[i].name, configuration_get(&c[i]));
	fclose(f);
	return 0;
}

static int configuration_load_file(const char *file, config_t *c, size_t length)
{
	assert(config);
	errno = 0;
	double d = 0;
	char s[64] = { 0 };

	errno = 0;
	FILE *f = fopen(file, "rb");
	if(!f) {
		tftp_debug(LOG_ERROR, "unable to open %s/rb: %s", file, strerror(errno));
		return -1;
	}

	while(fscanf(f, "%63s %lf", s, &d) == 2) {
		tftp_debug(LOG_ERROR, "cfg: %s %f", s, d);
		size_t i = 0;
		for(; i < length; i++) {
			if(!strcmp(c[i].name, s)) {
				configuration_set(&c[i], d);
				break;
			}
		}
		if(!(i < length))
			tftp_error(LOG_ERROR, "unknown configuration option: %s", s);
		memset(s, 0, sizeof s);
		d = 0;
	}
	fclose(f);
	return 0;
}


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
		fprintf(LOG_ERROR, "%u = %f\n", (unsigned)i, n[i].probability);
	}
}

/** From <http://xoshiro.di.unimi.it/xoshiro256starstar.c> */


/* This is xoshiro256** 1.0, our all-purpose, rock-solid generator. It has
   excellent (sub-ns) speed, a state (256 bits) that is large enough for
   any parallel application, and it passes all tests we are aware of.

   For generating just floating-point numbers, xoshiro256+ is even faster.

   The state must be seeded so that it is not everywhere zero. If you have
   a 64-bit seed, we suggest to seed a splitmix64 generator and use its
   output to fill s. */

static inline uint64_t rotl(const uint64_t x, int k) 
{
	return (x << k) | (x >> (64 - k));
}


static uint64_t xoshiro256mm(uint64_t s[static 4]) 
{
	const uint64_t result_starstar = rotl(s[1] * 5, 7) * 9;
	const uint64_t t = s[1] << 17;
	s[2] ^= s[0];
	s[3] ^= s[1];
	s[1] ^= s[2];
	s[0] ^= s[3];
	s[2] ^= t;
	s[3] = rotl(s[3], 45);
	return result_starstar;
}

static uint32_t random_u32(void)
{
	static uint64_t s[4] = { 1, 2, 3, 4 };
	static bool init = false;
	if(!init) {
		unsigned i = time(NULL);
		s[0] = i;
		s[1] = i & 0xff;
		init = true;
	}
	return xoshiro256mm(s);
} 

static double random_float(void)
{
	return ((double)random_u32()/(double)UINT32_MAX);
}

static void initialize(void)
{
	if(init)
		return;	
	init = true;
	tftp_set_logging_level(TFTP_LOG_LEVEL_ALL_ON);
	tftp_warning(LOG_ERROR, " ~~~ Error Injector Running ~~~ ");
	size_t config_length = NUMBER_OF_ELEMENTS_IN_ARRAY(config);
	if(configuration_load_file(CONFIGURATION_FILE, config, config_length) < 0)
		configuration_save_file(CONFIGURATION_FILE, config, config_length);
	wheel_initialize(&wheel);
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

static void modify(uint8_t h[static 2], fail_method fm)
{
	const uint16_t fixed = failure_value_fixed;
	switch(fm) {
	default:
	case BFM_RANDOM:
	{
		uint16_t rnd = random_u32();
		h[1] = rnd;
		h[0] = rnd >> 8;
		break;
	}
	case BFM_NULLED:
		h[1] = 0;
		h[0] = 0;
		break;
	case BFM_FIXED:
		h[1] = fixed >> 8;
		h[0] = fixed;
		break;
	}
}

static void oper(uint8_t *buffer, size_t length, fail_method fm)
{
	assert(buffer);
	if(length < 2)
		return;
	modify(&buffer[HD_OP_HI], fm);
}

static void blk(uint8_t *buffer, size_t length, fail_method fm)
{ /* Modify a block, or an error number */
	assert(buffer);
	if(length < 4)
		return;
	modify(&buffer[HD_BLOCK_NUMBER_HI], fm);
}

static void invalid_asciiz(uint8_t *b, size_t length)
{
	memset(b, 0xff, length);
}

int tftp_packet_process(bool send, uint8_t *buffer, size_t length)
{
	assert(buffer);
	initialize();
	size_t i = roulette(&wheel);
	tftp_opcode_e op = buffer[0] << 8 | buffer[1];
	if(op != i)
		return 0;

	tftp_debug(LOG_ERROR, "MODIFYING(%u) %s %u", (unsigned)op, send ? "TX" : "RX", (unsigned)length);

	/**@bug use roulette wheel for this? */
	switch(roulette(&wheel)) {
	case NONE:   break;
	case RRQ:    invalid_asciiz(&buffer[HD_FILE_NAME_START], length - HD_FILE_NAME_START); break;
	case WRQ:    invalid_asciiz(&buffer[HD_FILE_NAME_START], length - HD_FILE_NAME_START); break;
	case DATA:   blk(buffer,  length, fm_data);   break;
	case ACK:    blk(buffer,  length, fm_ack);    break;
	case ERROR:  blk(buffer,  length, fm_error);  break; /* Block Number is in same position as Error code */
	case OPCODE: oper(buffer, length, fm_opcode); break;
	}

	return 1;
}


