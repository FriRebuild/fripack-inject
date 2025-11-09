set_languages("cxx23")
set_version("0.1.0")
add_rules("plugin.compile_commands.autoupdate", {outputdir = "build"})

add_requires("fmt")

target("fripack-inject")
    set_kind("shared")
    add_files("src/**.cc")
    add_packages("fmt")
    -- frida gum devkit
    add_includedirs("./frida-gumjs-devkit", {public = true})
    add_linkdirs("./frida-gumjs-devkit/")
    add_links("frida-gumjs")
    set_strip("all")
    set_symbols("hidden")
    set_optimize("smallest")
    
    if is_plat("android") then
        add_syslinks("log")
    elseif is_plat("windows") then
        set_runtimes("MT")
        add_syslinks("ole32", "user32", "advapi32", "shell32")
    end