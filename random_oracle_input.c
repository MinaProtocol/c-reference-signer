#include "random_oracle_input.h"
#include "utils.h"
#include "pasta_fp.h"
#include "pasta_fq.h"

void roinput_print_fields(const ROInput *input) {
  for (size_t i = 0; i < LIMBS_PER_FIELD * input->fields_len; ++i) {
    printf("fs[%zu] = 0x%" PRIx64 "\n", i, input->fields[i]);
  }
}

void roinput_print_bits(const ROInput *input) {
  for (size_t i = 0; i < input->bits_len; ++i) {
    printf("bs[%zu] = %u\n", i, packed_bit_array_get(input->bits, i));
  }
}

// input for poseidon
void roinput_add_field(ROInput *input, const Field a) {
  int remaining = (int)input->fields_capacity - (int)input->fields_len;
  if (remaining < 1) {
    printf("fields at capacity\n");
    exit(1);
  }

  size_t offset = LIMBS_PER_FIELD * input->fields_len;

  fiat_pasta_fp_copy(input->fields + offset, a);

  input->fields_len += 1;
}

void roinput_add_bit(ROInput *input, bool b) {
  int remaining = (int)input->bits_capacity - (int)input->bits_len;

  if (remaining < 1) {
    printf("add_bit: bits at capacity\n");
    exit(1);
  }

  size_t offset = input->bits_len;

  packed_bit_array_set(input->bits, offset, b);
  input->bits_len += 1;
}

void roinput_add_scalar(ROInput *input, const Scalar a) {
  int remaining = (int)input->bits_capacity - (int)input->bits_len;
  const size_t len = FIELD_SIZE_IN_BITS;

  uint64_t scalar_bigint[4];
  fiat_pasta_fq_from_montgomery(scalar_bigint, a);

  if (remaining < len) {
    printf("add_scalar: bits at capacity\n");
    exit(1);
  }

  size_t offset = input->bits_len;
  for (size_t i = 0; i < len; ++i) {
    size_t limb_idx = i / 64;
    size_t in_limb_idx = (i % 64);
    bool b = (scalar_bigint[limb_idx] >> in_limb_idx) & 1;
    packed_bit_array_set(input->bits, offset + i, b);
  }

  input->bits_len += len;
}

void roinput_add_bytes(ROInput *input, const uint8_t *bytes, size_t len) {
  int remaining = (int)input->bits_capacity - (int)input->bits_len;
  if (remaining < 8 * len) {
    printf("add_bytes: bits at capacity (bytes)\n");
    exit(1);
  }

  // LSB bits
  size_t k = input->bits_len;
  for (size_t i = 0; i < len; ++i) {
    const uint8_t b = bytes[i];

    for (size_t j = 0; j < 8; ++j) {
      packed_bit_array_set(input->bits, k, (b >> j) & 1);
      ++k;
    }
  }

  input->bits_len += 8 * len;
}

void roinput_add_uint32(ROInput *input, const uint32_t x) {
  const size_t NUM_BYTES = 4;
  uint8_t le[NUM_BYTES];

  for (size_t i = 0; i < NUM_BYTES; ++i) {
    le[i] = (uint8_t) (0xff & (x >> (8 * i)));
  }

  roinput_add_bytes(input, le, NUM_BYTES);
}

void roinput_add_uint64(ROInput *input, const uint64_t x) {
  const size_t NUM_BYTES = 8;
  uint8_t le[NUM_BYTES];

  for (size_t i = 0; i < NUM_BYTES; ++i) {
    le[i] = (uint8_t) (0xff & (x >> (8 * i)));
  }

  roinput_add_bytes(input, le, NUM_BYTES);
}

void roinput_to_bytes(uint8_t *out, const ROInput *input) {
  size_t bit_idx = 0;

  Field tmp;

  // first the field elements, then the bitstrings
  for (size_t i = 0; i < input->fields_len; ++i) {
    fiat_pasta_fp_from_montgomery(tmp, input->fields + (i * LIMBS_PER_FIELD));

    for (size_t j = 0; j < FIELD_SIZE_IN_BITS; ++j) {
      size_t limb_idx = j / 64;
      size_t in_limb_idx = (j % 64);
      bool b = (tmp[limb_idx] >> in_limb_idx) & 1;

      packed_bit_array_set(
          out
          , bit_idx
          , b);
      bit_idx += 1;
    }
  }

  for (size_t i = 0; i < input->bits_len; ++i) {
    packed_bit_array_set(out, bit_idx, packed_bit_array_get(input->bits, i));
    bit_idx += 1;
  }
}

size_t roinput_to_fields(uint64_t *out, const ROInput *input) {
  size_t output_len = 0;

  // Copy over the field elements
  for (size_t i = 0; i < input->fields_len; ++i) {
    size_t offset = i * LIMBS_PER_FIELD;
    fiat_pasta_fp_copy(out + offset, input->fields + offset);
  }
  output_len += input->fields_len;

  size_t bits_consumed = 0;

  // pack in the bits
  uint64_t* next_chunk = out + input->fields_len * LIMBS_PER_FIELD;
  const size_t MAX_CHUNK_SIZE = FIELD_SIZE_IN_BITS - 1;
  while (bits_consumed < input->bits_len) {
    uint64_t chunk_non_montgomery[4] = { 0, 0, 0, 0 };

    size_t remaining = input->bits_len - bits_consumed;
    size_t chunk_size_in_bits = remaining >= MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remaining;

    for (size_t i = 0; i < chunk_size_in_bits; ++i) {
      size_t limb_idx = i / 64;
      size_t in_limb_idx = (i % 64);
      size_t b = packed_bit_array_get(input->bits, bits_consumed + i);

      chunk_non_montgomery[limb_idx] =  chunk_non_montgomery[limb_idx] | (((uint64_t) b) << in_limb_idx);
    }
    fiat_pasta_fp_to_montgomery(next_chunk, chunk_non_montgomery);

    output_len += 1;
    bits_consumed += chunk_size_in_bits;
    next_chunk += LIMBS_PER_FIELD;
  }

  return output_len;
}
