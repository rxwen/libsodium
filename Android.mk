LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	./src/libsodium/crypto_verify/sodium/verify.c \
	./src/libsodium/crypto_sign/crypto_sign.c \
	./src/libsodium/crypto_sign/ed25519/sign_ed25519.c \
	./src/libsodium/crypto_sign/ed25519/ref10/keypair.c \
	./src/libsodium/crypto_sign/ed25519/ref10/open.c \
	./src/libsodium/crypto_sign/ed25519/ref10/obsolete.c \
	./src/libsodium/crypto_sign/ed25519/ref10/sign.c \
	./src/libsodium/crypto_scalarmult/crypto_scalarmult.c \
	./src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe_frombytes_sandy2x.c \
	./src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe51_invert.c \
	./src/libsodium/crypto_scalarmult/curve25519/sandy2x/curve25519_sandy2x.c \
	./src/libsodium/crypto_scalarmult/curve25519/donna_c64/curve25519_donna_c64.c \
	./src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c \
	./src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c \
	./src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c \
	./src/libsodium/crypto_stream/salsa20/stream_salsa20.c \
	./src/libsodium/crypto_stream/salsa20/xmm6/salsa20_xmm6.c \
	./src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c \
	./src/libsodium/crypto_stream/chacha20/stream_chacha20.c \
	./src/libsodium/crypto_stream/xchacha20/stream_xchacha20.c \
	./src/libsodium/crypto_stream/salsa2012/stream_salsa2012.c \
	./src/libsodium/crypto_stream/salsa2012/ref/stream_salsa2012_ref.c \
	./src/libsodium/crypto_stream/crypto_stream.c \
	./src/libsodium/crypto_stream/aes128ctr/nacl/consts_aes128ctr.c \
	./src/libsodium/crypto_stream/aes128ctr/nacl/int128_aes128ctr.c \
	./src/libsodium/crypto_stream/aes128ctr/nacl/stream_aes128ctr_nacl.c \
	./src/libsodium/crypto_stream/aes128ctr/nacl/xor_afternm_aes128ctr.c \
	./src/libsodium/crypto_stream/aes128ctr/nacl/beforenm_aes128ctr.c \
	./src/libsodium/crypto_stream/aes128ctr/nacl/afternm_aes128ctr.c \
	./src/libsodium/crypto_stream/aes128ctr/stream_aes128ctr.c \
	./src/libsodium/crypto_stream/salsa208/stream_salsa208.c \
	./src/libsodium/crypto_stream/salsa208/ref/stream_salsa208_ref.c \
	./src/libsodium/crypto_stream/xsalsa20/stream_xsalsa20.c \
	./src/libsodium/crypto_secretbox/crypto_secretbox.c \
	./src/libsodium/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.c \
	./src/libsodium/crypto_secretbox/crypto_secretbox_easy.c \
	./src/libsodium/crypto_secretbox/xchacha20poly1305/secretbox_xchacha20poly1305.c \
	./src/libsodium/sodium/utils.c \
	./src/libsodium/sodium/runtime.c \
	./src/libsodium/sodium/version.c \
	./src/libsodium/sodium/core.c \
	./src/libsodium/crypto_box/crypto_box_seal.c \
	./src/libsodium/crypto_box/crypto_box.c \
	./src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c \
	./src/libsodium/crypto_box/curve25519xchacha20poly1305/box_curve25519xchacha20poly1305.c \
	./src/libsodium/crypto_box/crypto_box_easy.c \
	./src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c \
	./src/libsodium/crypto_auth/hmacsha256/auth_hmacsha256.c \
	./src/libsodium/crypto_auth/hmacsha512256/auth_hmacsha512256.c \
	./src/libsodium/crypto_auth/crypto_auth.c \
	./src/libsodium/crypto_shorthash/crypto_shorthash.c \
	./src/libsodium/crypto_shorthash/siphash24/shorthash_siphash24.c \
	./src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphashx24_ref.c \
	./src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphash24_ref.c \
	./src/libsodium/crypto_shorthash/siphash24/shorthash_siphashx24.c \
	./src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c \
	./src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c \
	./src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c \
	./src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c \
	./src/libsodium/crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c \
	./src/libsodium/crypto_generichash/crypto_generichash.c \
	./src/libsodium/crypto_generichash/blake2b/ref/blake2b-ref.c \
	./src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ref.c \
	./src/libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.c \
	./src/libsodium/crypto_generichash/blake2b/generichash_blake2.c \
	./src/libsodium/crypto_hash/sha512/hash_sha512.c \
	./src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c \
	./src/libsodium/crypto_hash/crypto_hash.c \
	./src/libsodium/crypto_hash/sha256/hash_sha256.c \
	./src/libsodium/crypto_hash/sha256/cp/hash_sha256_cp.c \
	./src/libsodium/crypto_kdf/crypto_kdf.c \
	./src/libsodium/crypto_kdf/blake2b/kdf_blake2b.c \
	./src/libsodium/crypto_kx/crypto_kx.c \
	./src/libsodium/crypto_pwhash/crypto_pwhash.c \
	./src/libsodium/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c \
	./src/libsodium/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c \
	./src/libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c \
	./src/libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c \
	./src/libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c \
	./src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.c \
	./src/libsodium/crypto_pwhash/argon2/argon2-encoding.c \
	./src/libsodium/crypto_pwhash/argon2/argon2-core.c \
	./src/libsodium/crypto_pwhash/argon2/argon2.c \
	./src/libsodium/crypto_pwhash/argon2/blake2b-long.c \
	./src/libsodium/crypto_pwhash/argon2/pwhash_argon2i.c \
	./src/libsodium/randombytes/nativeclient/randombytes_nativeclient.c \
	./src/libsodium/randombytes/salsa20/randombytes_salsa20_random.c \
	./src/libsodium/randombytes/randombytes.c \
	./src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c \
	./src/libsodium/crypto_core/hsalsa20/core_hsalsa20.c \
	./src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c \
	./src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c \
	./src/libsodium/crypto_core/hchacha20/core_hchacha20.c \
	./src/libsodium/crypto_core/curve25519/ref10/curve25519_ref10.c


LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/src/libsodium/include/sodium/

LOCAL_CFLAGS += -DPACKAGE_NAME="libsodium" \
	-DPACKAGE_TARNAME="libsodium" \
	-DPACKAGE_VERSION="1.0.12" \
	-DPACKAGE_STRING="libsodium 1.0.12" \
	-DPACKAGE_BUGREPORT=\"https://github.com/jedisct1/libsodium/issues\" \
	-DPACKAGE_URL=\"https://github.com/jedisct1/libsodium\" \
	-DPACKAGE=\"libsodium\" \
	-DVERSION=\"1.0.12\" \
	-DHAVE_PTHREAD_PRIO_INHERIT=1 \
	-DHAVE_PTHREAD=1 \
	-DSTDC_HEADERS=1 \
	-DHAVE_SYS_TYPES_H=1 \
	-DHAVE_SYS_STAT_H=1 \
	-DHAVE_STDLIB_H=1 \
	-DHAVE_STRING_H=1 \
	-DHAVE_MEMORY_H=1 \
	-DHAVE_STRINGS_H=1 \
	-DHAVE_INTTYPES_H=1 \
	-DHAVE_STDINT_H=1 \
	-DHAVE_UNISTD_H=1 \
	-D__EXTENSIONS__=1 \
	-D_ALL_SOURCE=1 \
	-D_GNU_SOURCE=1 \
	-D_POSIX_PTHREAD_SEMANTICS=1 \
	-D_TANDEM_SOURCE=1 \
	-DHAVE_DLFCN_H=1 \
	-DHAVE_PMMINTRIN_H=1 \
	-DHAVE_SMMINTRIN_H=1 \
	-DHAVE_WMMINTRIN_H=1 \
	-DHAVE_SYS_MMAN_H=1 \
	-DNATIVE_LITTLE_ENDIAN=1 \
	-DHAVE_CPUID=1 \
	-DASM_HIDE_SYMBOL=.hidden \
	-DHAVE_WEAK_SYMBOLS=1 \
	-DCPU_UNALIGNED_ACCESS=1 \
	-DHAVE_ATOMIC_OPS=1 \
	-DHAVE_MMAP=1 \
	-DHAVE_MLOCK=1 \
	-DHAVE_MADVISE=1 \
	-DHAVE_MPROTECT=1 \
	-DHAVE_NANOSLEEP=1 \
	-DHAVE_POSIX_MEMALIGN=1 \
	-DHAVE_GETPID=1 \
	-DCONFIGURED=1 \
	#-I. \
	#-I./include/sodium \
	#-I./include/sodium \
	#-g \
	#-O2 \
	#-pthread \
	#-fvisibility=hidden \
	#-fPIC \
	#-fno-strict-aliasing -fno-strict-overflow -fstack-protector -Wwrite-strings -Wdiv-by-zero -MT crypto_stream/aes128ctr/nacl/libsodium_la-afternm_aes128ctr.lo -MD -MP -MF crypto_stream/aes128ctr/nacl/.deps/libsodium_la-afternm_aes128ctr.Tpo -c crypto_stream/aes128ctr/nacl/afternm_aes128ctr.c  -fPIC -DPIC -o crypto_stream/aes128ctr/nacl/.libs/libsodium_la-afternm_aes128ctr.o

LOCAL_MODULE_TAGS := eng

LOCAL_MODULE := libsodium

include $(BUILD_SHARED_LIBRARY)
