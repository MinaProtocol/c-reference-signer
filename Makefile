all: reference_signer unit_tests

OBJS = base10.o \
	base58.o \
	blake2b-ref.o \
	sha256.o \
	crypto.o \
	pasta_fp.o \
	pasta_fq.o \
	poseidon.o \
	utils.o \
	curve_checks.o

reference_signer: $(OBJS) reference_signer.c
	$(CC) -Wall -Werror $@.c -o $@ $(OBJS) -lm

.PRECIOUS: unit_tests
unit_tests: $(OBJS) *.c *.h
	$(CC) -Wall -Werror $@.c -o $@ $(OBJS) -lm
	@./$@

%.o: %.c %.h
	$(CC) -fPIC -Wall -Werror $< -c

clean:
	rm -rf *.o *.log *.so *.a reference_signer unit_tests

libmina_signer.a: $(OBJS)
	ar rcs $@ $(OBJS)

libmina_signer.so: $(OBJS)
	$(CC) -shared -o $@ $(OBJS)
