fn main()
{
    // Use the `cc` crate to build a C file and statically link it.
    cc::Build::new()
        .file("src/stub.asm")
        .compile("stub");
}