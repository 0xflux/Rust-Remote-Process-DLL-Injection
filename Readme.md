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