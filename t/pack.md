# Pack Compiler

Turn pack/unpack strings into C functions of equivalent power, could also
create structures for handling data.

It should accept a string describing the function to generate, such as:

	function-name, structure-on, value, format, value, format, value, format, ...

Given the example:

	foo, true, A, C, B, h, C, H, D, 128s

It would generate code to pack and unpack a structure:


	#include "libpack.h"
	typedef struct {
		uint8_t A;
		int16_t B;
		uint16_t C;
		uint8_t D[128];
	} foo_t;

	uint8_t *foo_unpack(const uint8_t buf[static sizeof(foo_t)], foo_t *foo)
	{
		assert(buf);
		assert(foo);
		foo->A = buf[0];
		foo->B = unpack_i16(buf+1); // Perhaps "buf+offsetof(foo_t, B)"
		                            // Could be used instead?
		foo->C = unpack_u16(buf+3);
		foo->D = memcpy(foo->D, buf, 128);
		return buf+sizeof(foo_t);
	}

	uint8_t *foo_pack(uint8_t buf[static sizeof(foo_t)], const foo_t *foo)
	{
		assert(buf);
		assert(foo);
		buf[0] = foo->A;
		pack_i16(buf+1, foo->B);
		pack_u16(buf+3, foo->C);
		memcpy(buf+5, foo->D, 128);
		return buf+sizeof(foo_t);
	}

Perhaps it would be better to pass in a buffer object:

	typedef struct {
		size_t length;
		uint8_t b[];
	} buffer_t;

And a pointer to an iterator object:

	typedef struct {
		size_t position;
	} buffer_iterator_t;


# To Do

* Improve current pack/unpack code
  - assertions
  - longer strings
  - useful return values for pack/unpack
  - accept a maximum length
  - better error handling
* Make a pack library
* Make a pack compiler that works with the library
* This could be knocked together in perl, but it would be nice to have
it as a C program.


