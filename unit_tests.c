#include <stdio.h>
#include <assert.h>
#include <sys/resource.h>
#include <inttypes.h>

#include "pasta_fp.h"
#include "pasta_fq.h"
#include "crypto.h"
#include "base10.h"
#include "utils.h"

#define DEFAULT_TOKEN_ID 1
static bool _verbose;
static bool _ledger_gen;

void privkey_to_hex(char *hex, const size_t len, const Scalar priv_key) {
  uint64_t priv_words[4];
  hex[0] = '\0';

  assert(len > 2*sizeof(priv_words));
  if (len < 2*sizeof(priv_words)) {
    return;
  }

  uint8_t *p = (uint8_t *)priv_words;
  fiat_pasta_fq_from_montgomery(priv_words, priv_key);
  for (size_t i = sizeof(priv_words); i > 0; i--) {
    sprintf(&hex[2*(sizeof(priv_words) - i)], "%02x", p[i - 1]);
  }
  hex[len] = '\0';
}

void sig_to_hex(char *hex, const size_t len, const Signature sig) {
  hex[0] = '\0';

  assert(len == 2*sizeof(Signature) + 1);
  if (len < 2*sizeof(Signature) + 1) {
    return;
  }

  uint64_t priv_words[4];
  uint8_t *p = (uint8_t *)priv_words;
  size_t count = 0;
  fiat_pasta_fp_from_montgomery(priv_words, sig.rx);
  for (size_t i = sizeof(priv_words); i > 0; i--) {
    sprintf(&hex[2*(sizeof(priv_words) - i)], "%02x", p[i - 1]);
    count += 2;
  }
  fiat_pasta_fq_from_montgomery(priv_words, sig.s);
  for (size_t i = sizeof(priv_words); i > 0; i--) {
    sprintf(&hex[count + 2*(sizeof(priv_words) - i)], "%02x", p[i - 1]);
  }
  hex[len] = '\0';
}

bool hex_to_privkey(Scalar priv_key, const char *priv_hex) {
  size_t priv_hex_len = strnlen(priv_hex, 64);
  assert(priv_hex_len == 64);
  if (priv_hex_len != 64) {
    return false;
  }
  uint8_t priv_bytes[32];
  for (size_t i = sizeof(priv_bytes); i > 0; i--) {
    sscanf(&priv_hex[2*(i - 1)], "%02hhx", &priv_bytes[sizeof(priv_bytes) - i]);
  }

  fiat_pasta_fq_to_montgomery(priv_key, (uint64_t *)priv_bytes);

  char priv_key_hex[65];
  privkey_to_hex(priv_key_hex, sizeof(priv_key_hex), priv_key);

  // sanity check
  int result = memcmp(priv_key_hex, priv_hex, sizeof(priv_key_hex)) == 0;
  assert(result);
  return result;
}

bool privhex_to_address(char *address, const size_t len,
                        const char *account_number, const char *priv_hex) {
  Scalar priv_key;
  if (!hex_to_privkey(priv_key, priv_hex)) {
    return false;
  }

  Keypair kp;
  scalar_copy(kp.priv, priv_key);
  generate_pubkey(&kp.pub, priv_key);

  if (!get_address(address, len, &kp.pub)) {
    return false;
  }

  if (_verbose) {
    printf("%s => %s\n", priv_hex, address);
  }
  else if (_ledger_gen) {
    printf("    # account %s\n", account_number);
    printf("    # private key %s\n", priv_hex);
    printf("    assert(mina.ledger_get_address(%s) == \"%s\")\n\n",
           account_number, address);
  }

  return true;
}

bool sign_transaction(char *signature, const size_t len,
                      const char *account_number,
                      const char *sender_priv_hex,
                      const char *receiver_address,
                      Currency amount,
                      Currency fee,
                      Nonce nonce,
                      GlobalSlot valid_until,
                      const char *memo,
                      bool delegation) {
  Transaction txn;

  assert(len == 2*sizeof(Signature) + 1);
  if (len != 2*sizeof(Signature) + 1) {
    return false;
  }

  prepare_memo(txn.memo, memo);

  Scalar priv_key;
  if (!hex_to_privkey(priv_key, sender_priv_hex)) {
    return false;
  }

  Keypair kp;
  scalar_copy(kp.priv, priv_key);
  generate_pubkey(&kp.pub, priv_key);

  char source_str[MINA_ADDRESS_LEN];
  if (!get_address(source_str, sizeof(source_str), &kp.pub)) {
    return false;
  }

  char *fee_payer_str = source_str;

  txn.fee = fee;
  txn.fee_token = DEFAULT_TOKEN_ID;
  read_public_key_compressed(&txn.fee_payer_pk, fee_payer_str);
  txn.nonce = nonce;
  txn.valid_until = valid_until;

  if (delegation) {
    txn.tag[0] = 0;
    txn.tag[1] = 0;
    txn.tag[2] = 1;
  }
  else {
    txn.tag[0] = 0;
    txn.tag[1] = 0;
    txn.tag[2] = 0;
  }

  read_public_key_compressed(&txn.source_pk, source_str);
  read_public_key_compressed(&txn.receiver_pk, receiver_address);
  txn.token_id = DEFAULT_TOKEN_ID;
  txn.amount = amount;
  txn.token_locked = false;

  Compressed pub_compressed;
  compress(&pub_compressed, &kp.pub);

  Signature sig;
  sign(&sig, &kp, &txn);

  if (!verify(&sig, &pub_compressed, &txn)) {
    return false;
  }

  sig_to_hex(signature, len, sig);

  if (_verbose) {
    fprintf(stderr, "%d %s\n", delegation, signature);
  }
  else if (_ledger_gen) {
    // TX_TYPE_PAYMENT
    printf("    # account %s\n", account_number);
    printf("    # private key %s\n", sender_priv_hex);
    printf("    # sig=%s\n", signature);
    printf("    assert(mina.ledger_sign_tx(mina.%s,\n"
           "                               %s,\n"
           "                               \"%s\",\n"
           "                               \"%s\",\n"
           "                               %zu,\n"
           "                               %zu,\n"
           "                               %u,\n"
           "                               %u,\n"
           "                               \"%s\") == \"%s\")\n\n",
           delegation ? "TX_TYPE_DELEGATION" : "TX_TYPE_PAYMENT",
           account_number,
           source_str,
           receiver_address,
           amount,
           fee,
           nonce,
           valid_until,
           memo,
           signature);
  }

  return true;
}

bool check_get_address(const char *account_number,
                       const char *priv_hex, const char *address) {
  char target[MINA_ADDRESS_LEN];
  if (!privhex_to_address(target, sizeof(target), account_number, priv_hex)) {
    return false;
  }

  return strcmp(address, target) == 0;
}

bool check_sign_tx(const char *account_number,
                   const char *sender_priv_hex,
                   const char *receiver_address,
                   Currency amount,
                   Currency fee,
                   Nonce nonce,
                   GlobalSlot valid_until,
                   const char *memo,
                   bool delegation,
                   const char *signature) {
  char target[129];
  if (!sign_transaction(target, sizeof(target),
                        account_number,
                        sender_priv_hex,
                        receiver_address,
                        amount,
                        fee,
                        nonce,
                        valid_until,
                        memo,
                        delegation)) {
    return false;
   }

   return strcmp(signature, target) == 0;
}

int main(int argc, char* argv[]) {
  printf("Running unit tests\n");

  if (argc > 1) {
    if (strncmp(argv[1], "ledger_gen", 10) == 0) {
        _ledger_gen = true;
    }
    else {
        _verbose = true;
    }
  }
  struct rlimit lim = {1, 1};
  if (setrlimit(RLIMIT_STACK, &lim) == -1) {
    printf("rlimit failed\n");
    return 1;
  }

  // Address tests

  if (_ledger_gen) {
    printf("    # These tests were automatically generated from the Mina c-reference-signer\n");
    printf("    #\n");
    printf("    #     Details: https://github.com/MinaProtocol/c-reference-signer/README.markdown\n");
    printf("    #     Command: ./unit_tests ledger_gen\n\n");
  }

  assert(check_get_address("0",
                           "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                           "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV"));

  assert(check_get_address("1",
                           "3ca187a58f09da346844964310c7e0dd948a9105702b716f4d732e042e0c172e",
                           "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt"));

  assert(check_get_address("2",
                           "336eb4a19b3d8905824b0f2254fb495573be302c17582748bf7e101965aa4774",
                           "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi"));

  assert(check_get_address("3",
                           "1dee867358d4000f1dafa5978341fb515f89eeddbe450bd57df091f1e63d4444",
                           "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N"));

  assert(check_get_address("49370",
                           "20f84123a26e58dd32b0ea3c80381f35cd01bc22a20346cc65b0a67ae48532ba",
                           "B62qkiT4kgCawkSEF84ga5kP9QnhmTJEYzcfgGuk6okAJtSBfVcjm1M"));

  assert(check_get_address("0x312a",
                           "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
                           "B62qoG5Yk4iVxpyczUrBNpwtx2xunhL48dydN53A2VjoRwF8NUTbVr4"));

  // Sign payment tx tests

  if (_ledger_gen) {
    printf("    # These tests were automatically generated from the Mina c-reference-signer\n");
    printf("    #\n");
    printf("    #     Details: https://github.com/MinaProtocol/c-reference-signer/README.markdown\n");
    printf("    #     Command: ./unit_tests ledger_gen\n\n");
  }

  assert(check_sign_tx("0",
                       "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                       "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt",
                       1729000000000,
                       2000000000,
                       16,
                       271828,
                       "Hello Mina!",
                       false,
                       "0a68fc40b470abedd14cd8b830effa4fa6225e76cbc67fa46dfb0f825c0d1a7d1a8685817e449150070456b5628eeb9af954040e023d3a1b4211c818d210ee56"));

  assert(check_sign_tx("12586",
                       "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
                       "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi",
                       314159265359,
                       1618033988,
                       0,
                       4294967295,
                       "",
                       false,
                       "32d7ea2ae54df316e7baa4bebf8a62ea1cfb321debc75e27fc0ba302beba383a398ec6e103e0101a20179955bb11a1956bf0b470d7782344aec4d8d0fc73ed92"));

  assert(check_sign_tx("12586",
                       "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
                       "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N",
                       271828182845904,
                       100000,
                       5687,
                       4294967295,
                       "01234567890123456789012345678901",
                       false,
                       "063a7b5b5b78090760eb93cbfacf5672155e1c0bcfd5629d75b06bbb079694922f1394b7eb2f929b5a97f229e988523223e4b7fee531d8d85caafd1c702b1673"));

  assert(check_sign_tx("3",
                       "1dee867358d4000f1dafa5978341fb515f89eeddbe450bd57df091f1e63d4444",
                       "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
                       0,
                       2000000000,
                       0,
                       1982,
                       "",
                       false,
                       "09c5712632f6281a43c64dbb936ce6002a0c2e004b375037a05ec7e266f9f1be3f8e5bdd506c35c6546cfc4edbeaff816a38096c0bdb408341eb0e25adbf4d83"));

  // Sign delegation tx tests

  assert(check_sign_tx("0",
                       "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                       "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt",
                       0,
                       2000000000,
                       16,
                       1337,
                       "Delewho?",
                       true,
                       "376cd8a00b4ce495b3b23187b94a688a1c36837d2eb911c0085b3e37ba96dea02a3573e6a6471b068e14a03fe0b7d6399119ea52e4a310c3f98d7af5d988c676"));

  assert(check_sign_tx("49370",
                       "20f84123a26e58dd32b0ea3c80381f35cd01bc22a20346cc65b0a67ae48532ba",
                       "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
                       0,
                       2000000000,
                       0,
                       4294967295,
                       "",
                       true,
                       "05a1f5f50c6fe5616023251653e5be099d0ad942323498fb23bcfcd21c5fab6a3a641fce6d51e05566b0ce1244da30b0014cb7580f760f84e58eb654190bc607"));

  assert(check_sign_tx("12586",
                       "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
                       "B62qkiT4kgCawkSEF84ga5kP9QnhmTJEYzcfgGuk6okAJtSBfVcjm1M",
                       0,
                       42000000000,
                       1,
                       4294967295,
                       "more delegates, more fun........",
                       true,
                       "29febace385dfad1bcc97f1297d5f8c5bdadb57faf1c20a9c9f6c7516f80c6af05b0a0a186332f544b70c8e8717355bd7ebde310dee31b351f333219443ac798"));

  assert(check_sign_tx("2",
                       "336eb4a19b3d8905824b0f2254fb495573be302c17582748bf7e101965aa4774",
                       "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt",
                       0,
                       1202056900,
                       0,
                       577216,
                       "",
                       true,
                       "08a668739ec0bd4149e51a85ea9f05887232f91accb884c312dbca8ef7de0c9b341178cfb969c69bb9fc87df110276880cf09bcdf6b899ea3d1d1b4aa59e7c33"));

  printf("Unit tests completed successfully\n");

  return 0;
}
