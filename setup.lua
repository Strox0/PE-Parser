outputdir = "%{cfg.buildcfg}-%{cfg.architecture}"

workspace "PE-Parser"
	architecture "x64"
	configurations {"Debug","Release"}

    filter "system:windows"
      buildoptions { "/EHsc", "/Zc:preprocessor", "/Zc:__cplusplus" }
      systemversion "latest"

    filter "configurations:Debug"
      defines { "_DEBUG" }
      runtime "Debug"
      symbols "On"

    filter "configurations:Release"
      defines { "NDEBUG" }
      runtime "Release"
      optimize "On"
      symbols "Off"

project "PE-Parser"
	kind "ConsoleApp"
	language "C++"
	cppdialect "C++20"
	staticruntime "off"

	targetdir ("bin/" .. outputdir .. "/")
	objdir ("bin-int/" .. outputdir .. "/")

	includedirs {
		"src/"
	}

	files {
		"src/**.cpp",
		"src/**.h",
		"src/**.c"
	}