clang++ main.cpp crypto/crypto.cpp protocol/packet.cpp\
  -I/opt/homebrew/include \
  -L/opt/homebrew/lib \
  -lsodium

  ./a.out