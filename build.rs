fn main() {
    #[cfg(target_os = "macos")]
    {
        // dynarmic-sys is a C++ library that needs the C++ standard library
        println!("cargo:rustc-link-lib=c++");

        // Compile mach_exc_server (MIG-generated) needed by dynarmic's exception handler on macOS
        cc::Build::new()
            .file("mach_excServer.c")
            .compile("mach_exc_server");
    }
}
