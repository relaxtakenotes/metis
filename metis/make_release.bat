@echo off

SETLOCAL

SET PATH=%PATH%;C:\msys64\mingw64\bin

premake5 gmake2
compiledb -n make config=release

@RD /S /Q "bin/Release/"

make config=release -j 4

ENDLOCAL