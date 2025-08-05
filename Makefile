CXXFLAGS := -std=c++17 -Wall -Ilibtommath -Icrypto/hashing -Icrypto/aes
LDFLAGS := -Llibtommath -ltommath -Lcrypto/aes

CRYPTO_SRCS := crypto/crypto.cpp crypto/hashing/sha256.cpp crypto/aes/aescrypt.c crypto/aes/aeskey.c crypto/aes/aestab.c crypto/aes/aes_modes.c
CRYPTO_OBJS := $(CRYPTO_SRCS:.cpp=.o)
CRYPTO_OBJS := $(CRYPTO_OBJS:.c=.o)

all: libtommath/libtommath.a assh asshd

libtommath/libtommath.a:
	@if [ ! -d "libtommath" ]; then \
		git clone https://github.com/libtom/libtommath.git libtommath; \
	fi
	@echo "Building libtommath..."
	@cd libtommath && make

assh: assh.o $(CRYPTO_OBJS)
	$(CXX) $^ $(LDFLAGS) -o $@

asshd: asshd.o $(CRYPTO_OBJS)
	$(CXX) $^ $(LDFLAGS) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.c
	clang -Wall -Icrypto/aes -c $< -o $@

clean:
	rm assh asshd *.o crypto/*.o crypto/hashing/*.o crypto/aes/*.o
	@if [ -d "libtommath" ]; then cd libtommath && $(MAKE) clean; fi

.PHONY: all clean
