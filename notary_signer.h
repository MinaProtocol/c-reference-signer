#pragma once

#include "crypto.h"

bool notary_sign(Signature *sig, const Keypair *kp, const uint8_t *msg, const size_t len, const uint8_t network_id);
bool notary_verify(Signature *sig, const Compressed *pub_compressed, const uint8_t *msg, const size_t len, uint8_t network_id);
