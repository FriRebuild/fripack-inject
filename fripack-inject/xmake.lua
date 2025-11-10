set_languages("cxx23")
set_version("0.1.0")
add_rules("plugin.compile_commands.autoupdate", {outputdir = "build"})

if is_plat("windows") then
    set_runtimes("MT")
end

includes("./deps/frida-gumjs-devkit.lua")
add_requires("fmt", "frida-gumjs-devkit", "xz", "reflect-cpp")

target("fripack-inject")
    set_kind("shared")
    add_files("src/**.cc")
    add_packages("fmt", "frida-gumjs-devkit", "xz", "reflect-cpp")
    set_strip("all")
    set_symbols("hidden")
    set_optimize("smallest")

    if is_plat("android") then
        add_syslinks("log")
    elseif is_plat("windows") then
        add_defines("NOMINMAX", "WIN32_LEAN_AND_MEAN")
        add_syslinks("ole32", "user32", "advapi32", "shell32")
    end