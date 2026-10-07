gcc src/main.c src/core/*.c src/modules/*.c src/thirdparty/*.c -Iinclude -Ldependencies/libsodium-win64/lib -lsodium -static -o chroma.exe
