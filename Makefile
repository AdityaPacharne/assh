CXX := clang++
CXXFLAGS := -std=c++11 -Wall -Ilibtommath -Icrypto/hashing -Icrypto/aes
# -Icrypto/aes -Icrypto/aes/openssl/include
LDFLAGS := -Llibtommath -ltommath -Lcrypto/aes
# -Lcrypto/aes/openssl

CRYPTO_SRCS := crypto/crypto.cpp crypto/hashing/sha256.cpp crypto/aes/aescrypt.c crypto/aes/aeskey.c crypto/aes/aestab.c crypto/aes/aes_modes.c
CRYPTO_OBJS := $(CRYPTO_SRCS:.cpp=.o)
CRYPTO_OBJS := $(CRYPTO_OBJS:.c=.o)

all: assh asshd

assh: assh.o $(CRYPTO_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@

asshd: asshd.o $(CRYPTO_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.c
	clang -Wall -Icrypto/aes -c $< -o $@

clean:
	rm assh asshd *.o crypto/*.o crypto/hashing/*.o crypto/aes/*.o
