:: For some reason premake does not generate a makefile with proxy.def, so lets just compile everything ourselves because it's simple enough anyway.

g++ -std=c++20 -shared -static -static-libgcc -static-libstdc++ -O3 src/main.cpp src/proxy.def -o bin/unicode.dll -lDbghelp -lntdll -lwinmm