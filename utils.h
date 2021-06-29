#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define ARRAY_LEN(array) sizeof(array)/sizeof(array[0])

void packed_bit_array_set(uint8_t *bits, size_t i, bool b);
bool packed_bit_array_get(uint8_t *bits, size_t i);
