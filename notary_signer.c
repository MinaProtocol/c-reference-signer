#include "notary_signer.h"
#include "pasta_fp.h"
#include "pasta_fq.h"
#include "poseidon.h"

extern void message_derive(Scalar out, const Keypair *kp, const ROInput *msg, uint8_t network_id);
extern void message_hash(Scalar out, const Affine *pub, const Field rx, const ROInput *msg, const uint8_t hash_type, const uint8_t network_id);
extern void decompress(Affine *pt, const Compressed *compressed);
extern void group_scalar_mul(Group *r, const Scalar k, const Group *p);
extern void affine_to_group(Group *r, const Affine *p);
extern void affine_from_group(Affine *r, const Group *p);
extern void group_add(Group *r, const Group *p, const Group *q);

bool notary_sign(Signature *sig, const Keypair *kp, const uint8_t *msg, const size_t len, const uint8_t network_id)
{
  // Convert msg bytes to ROInput
  uint64_t input_fields[4 * 0]; // Messages are stored in bits (no fields)
  uint8_t input_bits[len];
  ROInput input;
  input.fields_capacity = 0;
  input.bits_capacity = 8 * len;
  input.fields = input_fields;
  input.bits = input_bits;
  input.fields_len = 0;
  input.bits_len = 0;

  roinput_add_bytes(&input, msg, len);

  Scalar k;
  message_derive(k, kp, &input, network_id);

  uint64_t k_nonzero;
  fiat_pasta_fq_nonzero(&k_nonzero, k);
  if (! k_nonzero) {
    return false;
  }

  // r = k*g
  Affine r;
  generate_pubkey(&r, k);

  field_copy(sig->rx, r.x);

  if (field_is_odd(r.y)) {
      // negate (k = -k)
      Scalar tmp;
      fiat_pasta_fq_copy(tmp, k);
      scalar_negate(k, tmp);
  }

  Scalar e;
  message_hash(e, &kp->pub, r.x, &input, POSEIDON_3W, network_id);

  // s = k + e*sk
  Scalar e_priv;
  scalar_mul(e_priv, e, kp->priv);
  scalar_add(sig->s, k, e_priv);

  return true;
}

bool notary_verify(Signature *sig, const Compressed *pub_compressed, const uint8_t *msg, const size_t len, uint8_t network_id)
{
  // Convert msg to ROInput
  uint64_t input_fields[4 * 0]; // Messages are stored in bits (no fields)
  uint8_t input_bits[len];
  ROInput input;
  input.fields_capacity = 0;
  input.bits_capacity = 8 * len;
  input.fields = input_fields;
  input.bits = input_bits;
  input.fields_len = 0;
  input.bits_len = 0;

  roinput_add_bytes(&input, msg, len);

  Affine pub;
  decompress(&pub, pub_compressed);

  Scalar e;
  message_hash(e, &pub, sig->rx, &input, POSEIDON_3W, network_id);

  Group g;
  group_one(&g);

  Group sg;
  group_scalar_mul(&sg, sig->s, &g);

  Group pub_proj;
  affine_to_group(&pub_proj, &pub);
  Group epub;
  group_scalar_mul(&epub, e, &pub_proj);

  Group neg_epub;
  fiat_pasta_fp_copy(neg_epub.X, epub.X);
  fiat_pasta_fp_opp(neg_epub.Y, epub.Y);
  fiat_pasta_fp_copy(neg_epub.Z, epub.Z);

  Group r;
  group_add(&r, &sg, &neg_epub);

  Affine raff;
  affine_from_group(&raff, &r);

  Field ry_bigint;
  fiat_pasta_fp_from_montgomery(ry_bigint, raff.y);

  const bool ry_even = (ry_bigint[0] & 1) == 0;

  return (ry_even && fiat_pasta_fp_equals(raff.x, sig->rx));
}
