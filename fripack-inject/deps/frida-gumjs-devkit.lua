package("frida-gumjs-devkit")
    on_install(function (package)
        local dir = package:scriptdir() .. "/frida-gumjs-devkit"
        io.replace(dir .. "/gumenumtypes.h", "#include <glib-object.h>", "// #include <glib-object.h>", {plain = true})
        os.cp(dir .. "/frida-gumjs.h", package:installdir("include"))
        os.cp(dir .. "/gumenumtypes.h", package:installdir("include", "gum"))
        os.cp(dir .. "/*.a", package:installdir("lib"))
        os.cp(dir .. "/*.lib", package:installdir("lib"))

        -- Extract extra link flags from Frida's generated example file.
        -- devkit.py embeds the exact platform-specific ldflags in the compile comment:
        --   clang++ ... -L. -lfrida-gumjs <extra_ldflags>
        local example_file = dir .. "/frida-gumjs-example.c"
        if os.isfile(example_file) then
            local content = io.readfile(example_file)
            local extra = content:match("%-lfrida%-gumjs%s+(.-)%s*\n%s*%*")
            if extra and extra ~= "" then
                io.writefile(package:installdir("lib") .. "/frida-gumjs-ldflags", extra)
            end
        end
    end)

    on_load(function (package)
        package:add("links", "frida-gumjs")

        local ldflags_file = package:installdir("lib") .. "/frida-gumjs-ldflags"
        if os.isfile(ldflags_file) then
            local content = io.readfile(ldflags_file)
            for flag in content:gmatch("%S+") do
                local fw = flag:match("^%-framework$")
                -- handle "-framework Foo" as two tokens or "-Wl,..." style
                if flag == "-framework" then
                    -- will be consumed by next iteration — handled below
                elseif content:find("%-framework%s+" .. flag) then
                    -- skip: this token is the framework name, already captured
                else
                    local lib = flag:match("^%-l(.+)$")
                    if lib then
                        package:add("syslinks", lib)
                    end
                end
            end
            -- handle "-framework Foo" pairs
            for fw in content:gmatch("%-framework%s+(%S+)") do
                package:add("frameworks", fw)
            end
        end
    end)