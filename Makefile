CXX := clang++
CXXFLAGS := -std=c++11 -Wall -Ilibtommath -Icrypto -Icrypto/hashing
LDFLAGS := -Llibtommath -ltommath

CRYPTO_SRCS := crypto/crypto.cpp crypto/hashing/sha256.cpp
CRYPTO_OBJS := $(CRYPTO_SRCS:.cpp=.o)

all: assh asshd

assh: assh.o $(CRYPTO_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@

asshd: asshd.o $(CRYPTO_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm assh asshd *.o crypto/*.o crypto/hashing/*.o
