@echo off

SETLOCAL

SET PATH=%PATH%;C:\msys64\mingw64\bin

premake5 gmake2
compiledb -n make config=debug

@RD /S /Q "bin/Debug/"

make config=debug -j 4

ENDLOCAL