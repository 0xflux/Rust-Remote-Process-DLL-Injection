# Remote DLL Injection

This Rust project injects a DLL from disk into a remote process, to run you need to edit the path to the DLL you are
injecting, found here:

```rust
    let path_to_dll = "path\\to\\dll\\rust_dll.dll";
```

And when running, you must specify the PID of the process you are injecting into:

```shell
cargo run -- 123
```

![image](https://github.com/0xflux/Rust-Remote-Process-DLL-Injection/assets/49762827/db46804e-6b46-4623-b6de-b4560104851c)

![image](https://github.com/0xflux/Rust-Remote-Process-DLL-Injection/assets/49762827/8bf01304-3252-4354-a6b0-8d56461d113a)
