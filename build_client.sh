clang++ client.cpp \
        crypto/crypto.cpp \
        protocol/packet.cpp \
        transport/transport.cpp \
        -I/opt/homebrew/include \
        -L/opt/homebrew/lib \
        -lsodium \
        -o client.out   
