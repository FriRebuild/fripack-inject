set_languages("cxx23")
set_version("0.1.0")

target("fripack-inject")
    set_kind("shared")
    add_files("src/**.cc")
    -- frida gum devkit
    add_includedirs("./frida-gumjs-devkit", {public = true})
    add_linkdirs("./frida-gumjs-devkit/")
    add_links("frida-gumjs")

    if is_plat("android") then
        add_syslinks("log")
    end