//! iTunes directory visitation — FUN_080b4bd0 at 0x080b4bd0.
//!
//! Raw extent [0x080b4bd0,0x080b4bfc): 20 instruction bytes and a
//! 24-byte NUL-terminated path literal. Zero outgoing plain/predicated
//! BLs; one tail B to 0x08093f70. Two incoming plain BLs (0x08113818,
//! 0x08114d8c), zero predicated BLs. Move the callback and continuation
//! argument into r1/r2, supply iPod_Control/iTunes/ in r0 and a zero
//! exclusion mask in r3, then tail-call the directory walker.
//! Deliberate deviations: use a Rust static path instead of the firmware
//! literal and a replaceable host walker; target calls the unported stock
//! walker. Ghidra incorrectly inlines the walker into this function.

/// The walker invokes this callback with context, flags, two metadata words,
/// zero, full path, and the final metadata word. Zero stops iteration.
pub type DirectoryVisitor = unsafe extern "C" fn(u32, u32, u32, u32, u32, *const u8, u32) -> i32;
pub type DirectoryWalk = unsafe extern "C" fn(*const u8, DirectoryVisitor, u32, u32);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_directory_walk(
    _: *const u8, _: DirectoryVisitor, _: u32, _: u32,
) {
    panic!("install directory walker host operations before visiting iTunes")
}

/// Host substitute for the unported directory walker at 0x08093f70.
#[cfg(not(target_os = "none"))]
pub static mut DIRECTORY_WALK: DirectoryWalk = missing_directory_walk;

/// Visit eligible entries in the iTunes control directory without excluding flags.
///
/// # Safety
/// The callback and continuation argument must satisfy the stock walker's
/// contract. Host callers must install DIRECTORY_WALK without concurrent access.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn itunes_directory_visit(visitor: DirectoryVisitor, continuation: u32) {
    #[cfg(target_os = "none")]
    let walk: DirectoryWalk = core::mem::transmute(0x0809_3f70usize);
    #[cfg(not(target_os = "none"))]
    let walk = core::ptr::read_volatile(core::ptr::addr_of!(DIRECTORY_WALK));
    walk(b"iPod_Control/iTunes/\0".as_ptr(), visitor, continuation, 0);
}
