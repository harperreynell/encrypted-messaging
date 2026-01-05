clang++ server.cpp \
        crypto/crypto.cpp \
        protocol/packet.cpp \
        transport/transport.cpp \
        -I/opt/homebrew/include \
        -L/opt/homebrew/lib \
        -lsodium \
	-o server.out
