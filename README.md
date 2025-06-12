# Metis

This is a crash diagnostic tool intended for every application/game that allows 3rd party DLL's.

## How to use

Current built module is intended for Team Fortress 2. Installing it is easy. You copy the unicode.dll, head into the TF2 directory, "bin" and then "x64". In the folder you should see another unicode.dll, rename it into unicode_original.dll and paste in the unicode.dll you downloaded. You will hear a sound playing when the game boots up if it is installed correctly. If it's not installed correctly, the game will most likely error out and wont boot. If you are unable to restore the original unicode dll, you can copy it from the repository or just verify game integrity through steam.

Alternatively you can just inject the DLL using your favorite injector.

## Features

If the application crashes, Metis will output two text files named Crash\_(uptimetickcount).txt and ThreadInformation\_(uptimetickcount).txt right beside the main executable.

You can trigger a dump of the currently running threads manually by pressing this hotkey: CTRL + SHIFT + CAPSLOCK. You will hear a sound if you held it for long enough. This may be useful for locked up threads that dont necessarily cause a crash.

The crash dump includes a stack trace, exception type and register values.

The thread dump includes the thread id, start address, cycle delta, state, wait reason and the stack trace.

## Safety

I can not guarantee your accounts safety when using this tool. For VAC protected games that aren't CS2, you will be fine. For other games or applications I can not say for certain, make sure to research potential protection measures in said software. If paranoid, feel free to ask in the issues.

## How to compile

Install the GCC compiler for Windows, modify the gcc path in the make_*.bat scripts and then run the appropriate one. For everything else but make_build_proxy.bat you will also require premake5 along with compiledb (a python package) (although the latter is only needed for clangd).

### Small caveat

Due to an unknown reason to me, premake5 does not include the .def files in its generated makefile. Therefore if you wish to use this as a proxy DLL, you must compile with make_build_proxy.bat.

## How to change the target proxy dll

First pick your proxy DLL. Then you should copy it beside the generate_def.py script and edit it to contain the correct DLL names (ex. if the original dll is named unicode.dll, you should rename it into unicode_original.dll in all required places of the script). After that you may run it and then copy & paste the output into src/proxy.def. In the make_build_proxy.bat script you can also rename the output dll name if you do not wish to do it yourself after the compilation is done.

## Credits

- Cleric - Majority of the exception handler