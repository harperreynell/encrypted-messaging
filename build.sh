mkdir build &> /dev/null

printf "Building client app..."
clang++ client.cpp \
        crypto/crypto.cpp \
        protocol/packet.cpp \
        transport/transport.cpp \
        session/session.cpp \
        iparser/iparser.cpp \
        -I/opt/homebrew/include \
        -L/opt/homebrew/lib \
        -lsodium \
        -o build/client.out  
printf "Done. Executable file in build/client.out\n"

printf "Building server app..."
clang++ server.cpp \
        crypto/crypto.cpp \
        protocol/packet.cpp \
        transport/transport.cpp \
        session/session.cpp \
        iparser/iparser.cpp \
        -I/opt/homebrew/include \
        -L/opt/homebrew/lib \
        -lsodium \
	      -o build/server.out
printf "Done. Executable file in build/server.out\n"

chmod +x build/*

