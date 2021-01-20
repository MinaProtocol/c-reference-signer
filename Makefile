all: reference_signer unit_tests

OBJS = base10.o \
	base58.o \
	blake2b-ref.o \
	crypto.o \
	pasta_fp.o \
	pasta_fq.o \
	poseidon.o \
	utils.o

reference_signer: $(OBJS) reference_signer.c
	$(CC) -Wall -Werror $@.c -o $@ $(OBJS) -lm -lcrypto

.PRECIOUS: unit_tests
unit_tests: $(OBJS) unit_tests.c
	$(CC) -Wall -Werror $@.c -o $@ $(OBJS) -lm -lcrypto
	@./$@

%.o: %.c
	$(CC) -Wall -Werror $< -c

clean:
	rm -rf *.o *.log reference_signer unit_tests
