//! Block-manager client construction — `FUN_081e6b34` @ **0x081e6b34**.
//! True extent: 140 bytes (136 instruction bytes and callback literal at
//! 0x081e6bbc); next real function begins at 0x081e6bc0. Raw A32 decoding
//! verifies nine outbound plain BLs, zero predicated BLs, and two inbound
//! plain BLs (0x081efd00, 0x081efd6c).
//!
//! Construct a 100-element context-array owner, clear its execution handle,
//! retain the borrowed name, construct the mutex and mutex/context member,
//! and clear byte +0x16c. Initialize a temporary 40-byte AHTP layout, measure
//! the name, invoke the constant-0x52 helper (NOT a string assignment), allocate
//! a 12-byte result and execute operation 0x081dbbd4 with this and the layout.
//! Store the result and destroy the temporary before returning this.
//!
//! Deliberate deviations: discard unused strlen/constant results; initialize
//! incidental mutex scope seeds to zero as existing constructors do. Host
//! uses the original native name pointer for strlen rather than reloading its
//! truncated target-layout word. Target fields remain four-byte words. The
//! private parameterized allocator/executor permits isolated host fixtures;
//! firmware uses the existing ports, with no new retail callee seams.
//! A compiler barrier retains the discarded strlen scan despite LLVM's
//! builtin knowledge. Constant return and temporary tag clear can be elided.
//! ARM match review: 37 Rust versus 34 stock instructions; member offsets,
//! 100-element count, 12-byte allocation and operation literal agree.
//! LLVM elides the constant helper and dead temporary tag clear; strlen is
//! retained. Frame-pointer setup and explicit zero seeds account for changes.

use crate::cxx::mutex::cxx_mutex_construct;
use crate::cxx::mutex_opaque_context_construct::cxx_mutex_opaque_context_construct;
use crate::cxx::opaque_context_array_construct::opaque_context_array_construct;
use crate::cxx::opaque_layout_construct::opaque_layout_construct;
use crate::cxx::resource_handle_execute::resource_handle_execute;
use crate::cxx::return_constant_0x52::cxx_return_constant_0x52;
use crate::util::ahtp_state_destroy::ahtp_state_destroy;

/// # Safety
/// `this` must address 0x170 aligned writable bytes; `name` must be a valid
/// NUL-terminated string. The resident execution worker's contracts apply.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn block_manager_client_construct(this: *mut u8, name: *const u8) -> *mut u8 {
    construct_with(this, name, super::veneers::operator_new, resource_handle_execute)
}

unsafe fn construct_with(
    this: *mut u8,
    name: *const u8,
    allocate: unsafe extern "C" fn(usize) -> *mut u8,
    execute: unsafe extern "C" fn(*mut u8, u32, u32, u32) -> *mut u8,
) -> *mut u8 {
    let this = opaque_context_array_construct(this, 100);
    let words = this.cast::<u32>();
    words.add(0x10c / 4).write(0);
    words.add(0x110 / 4).write(name as usize as u32);
    let mutex = cxx_mutex_construct(this.add(0x114), 0, 0, 0);
    let member = cxx_mutex_opaque_context_construct(mutex.add(0x1c).cast(), 0, 0, 0);
    let this = member.cast::<u8>().sub(0x130);
    this.add(0x16c).write(0);
    let mut layout = core::mem::MaybeUninit::<[u32; 10]>::uninit();
    let layout = layout.as_mut_ptr().cast::<u32>();
    opaque_layout_construct(layout.cast());
    core::hint::black_box(crate::libc::strlen::strlen(name));
    cxx_return_constant_0x52();
    let result = allocate(12);
    let result = execute(result, 0x081d_bbd4, this as usize as u32, layout as usize as u32);
    this.cast::<u32>().add(0x10c / 4).write(result as usize as u32);
    ahtp_state_destroy(layout);
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn allocate(_size: usize) -> *mut u8 { 0x1234usize as *mut u8 }
    unsafe extern "C" fn execute(result: *mut u8, _operation: u32, _subject: u32, _context: u32) -> *mut u8 { result }
    unsafe extern "C" fn null_result(_result: *mut u8, _operation: u32, _subject: u32, _context: u32) -> *mut u8 { core::ptr::null_mut() }

    #[test]
    fn initializes_client_fields_without_overwriting_tail_or_guards() {
        for name in [&b"\0"[..], &b"client\0ignored"[..]] {
            for worker in [execute as unsafe extern "C" fn(*mut u8, u32, u32, u32) -> *mut u8, null_result] {
                let mut storage = [0xa5a5_a5a5u32; 0x170 / 4 + 2];
                let this = unsafe { storage.as_mut_ptr().add(1).cast::<u8>() };
                assert_eq!(unsafe { construct_with(this, name.as_ptr(), allocate, worker) }, this);
                let object = &storage[1..1 + 0x170 / 4];
                assert_eq!(object[0x104 / 4], 100);
                assert_eq!(object[0x110 / 4], name.as_ptr() as usize as u32);
                let expected = if worker as usize == execute as usize { 0x1234 } else { 0 };
                assert_eq!(object[0x10c / 4], expected);
                assert_eq!(object[0x168 / 4], 0);
                assert_eq!(object[0x16c / 4], 0xa5a5_a500);
                assert_eq!(storage[0], 0xa5a5_a5a5);
                assert_eq!(storage[storage.len() - 1], 0xa5a5_a5a5);
            }
        }
    }
}
