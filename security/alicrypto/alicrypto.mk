
NAME := alicrypto
ALICRYPTO_TEST := yes

ifneq (,$(BINS))
ifeq ($(MBEDTLS_SHARE),1)
$(NAME)_TYPE := framework&kernel
else
$(NAME)_TYPE := kernel
endif
endif

$(NAME)_SOURCES :=
$(NAME)_COMPONENTS :=

GLOBAL_INCLUDES     += inc
GLOBAL_LDFLAGS      +=
GLOBAL_DEFINES      += CONFIG_ALICRYPTO
GLOBAL_CFLAGS       +=

$(NAME)_PREBUILT_LIBRARY := lib/$(HOST_ARCH)/libmbedcrypto.a  \
		lib/$(HOST_ARCH)/libalicrypto.a
				
ifeq ($(ALICRYPTO_TEST), yes)
GLOBAL_INCLUDES     += test
GLOBAL_LDFLAGS      +=
$(NAME)_SOURCES += \
				test/ali_crypto_test.c \
				test/ali_crypto_test_comm.c \
				test/ali_crypto_test_aes.c \
				test/ali_crypto_test_hash.c \
				test/ali_crypto_test_rand.c \
				test/ali_crypto_test_rsa.c \
				test/ali_crypto_test_hmac.c 
endif # end ALICRYPTO_TEST=yes
