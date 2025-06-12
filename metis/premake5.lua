workspace "detailed-crash-logs"
   configurations { "Debug", "Release" }

project "detailed-crash-logs"
   language "C++"
   targetdir "bin/%{cfg.buildcfg}"

   files { "src/**.h", "src/**.cpp", "src/**.def" }

   links { "Dbghelp", "ntdll", "winmm" }

   buildoptions { 
      "-Wall", 
      "-Wextra",
      "-Wformat-security",
      "-Wno-comment",
      "-Wno-deprecated-copy",
      "-Wno-strict-aliasing",
      "-Wno-unknown-pragmas",
      "-Wno-pedantic",
      "-Wno-missing-field-initializers",
      "-Wno-parentheses",
      "-Wno-cast-function-type",
      "-Wno-misleading-indentation",
      "-Wno-unused-function",
      "-Wno-unused-parameter",
      "-Wno-int-to-pointer-cast",
      "-Wno-multichar",
      "-fPIE", 
      "-fstack-protector-all",
      "-D_FORTIFY_SOURCE=2"
   }

   linkoptions {
      "-static",
      "-static-libgcc",
      "-static-libstdc++",
      "-Wl,--exclude-all-symbols"
   }

   cppdialect "C++20"

   kind "SharedLib"
   
   filter "configurations:Debug"
      defines { "_DEBUG" }
      symbols "On"

   filter "configurations:Release"
      buildoptions { "-fno-ident", "-s" }
      optimize "Full"
