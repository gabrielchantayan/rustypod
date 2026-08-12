//! `pair_header_destruct` — the non-deleting destructor of the
//! 200-byte "pair header" service object whose constructor is the
//! ported `cxx::pair_header::pair_header_construct` @ 0x08124a38 (same
//! translation unit, 0x24 bytes earlier).
//!
//! Original: `FUN_08124a5c` @ 0x08124a5c (52 bytes exactly,
//! 0x08124a5c..0x08124a90 — thirteen instructions, no literal pool;
//! the timer-area thunk opens immediately after. 63 `bl` call sites
//! in the disassembly listing, 0 `b`; three further words @
//! 0x081990e0/0x081990f4/0x08199108 decode as `bl` here but sit
//! outside every Ghidra function extent, likely data).
//!
//! # Algorithm
//!
//! ```text
//! if *(u32 *)(this + 0xc4) != 0:          ; the owned sub-object
//!     trivial_destructor(owned)           ; 0x082646ac — ported, empty
//!     operator_delete(owned)              ; 0x082aad24 — ported, tag 2
//! *(u32 *)(this + 0xc4) = 0               ; unconditional, after the if
//! return FUN_0810ec10(this + 0xc) - 0xc   ; base sub-destructor chain,
//!                                         ; container_of back-adjust
//! ```
//!
//! Ghidra's decompile marks the `FUN_082aad24()` call "Subroutine does
//! not return", which makes the trailing store look conditional; the
//! raw ARM shows the normal fall-through — 0x082aad24 is the ordinary
//! ported `operator_delete`, and the +0xc4 word is cleared on BOTH
//! paths (the constructor @ 0x08124a38 clears the same word at
//! construction, so NULL is the field's born state).
//!
//! # What the object is
//!
//! The class layout comes from the ported constructor: vtable + two
//! header words at +0x00/+0x04, the 0x0810ebbc base subobject at
//! +0x0c, the owned heap sub-object at +0xc4, 200 bytes total. The
//! destructor mirrors it: dispose the owned +0xc4 object
//! (destruct-then-free, the crate's documented pair), then chain into
//! the base subobject's own teardown `FUN_0810ec10` at this+0x0c and
//! back the result off by 0x0c — the multiple-inheritance
//! destructor-chain adjustment. Every one of the 63 call sites is
//! itself a destructor doing `ldr r0, [r4, #FIELD]; cmp; beq; bl
//! 0x08124a5c; bl 0x082aad24` on an owner-class member (e.g. the
//! 0x0814219c class's +0xec/+0xf0/+0xf4 triple, the 0x0811dce8
//! class's +0xa4), confirming this is the member's non-deleting
//! destructor (the caller supplies the `operator delete`).
//!
//! # Seams
//!
//! Both destruct/delete callees are ported and called directly
//! (`cxx::trivial_destructor::trivial_destructor`,
//! `heap::veneers::operator_delete`). Only the base sub-destructor
//! `FUN_0810ec10` is unported; it rides [`PAIR_HEADER_BASE_DESTRUCT`]
//! (the event_list.rs pattern: transmuted firmware default on target,
//! panicking default on host), so this port is hook-ready on target.

use core::ptr::addr_of_mut;

/// Byte offset of the owned heap sub-object the destructor disposes
/// (`ldr/str [r4, #0xc4]`).
pub const PAIR_HEADER_OWNED: usize = 0xc4;
/// Byte offset of the base subobject handed to the chained teardown
/// (`add r0, r4, #0xc`).
pub const PAIR_HEADER_BASE: usize = 0x0c;
/// The container_of back-adjust on the chained teardown's result
/// (`sub r0, r0, #0xc`).
pub const PAIR_HEADER_BASE_ADJUST: usize = 0x0c;

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_base_destruct(base: *mut u8) -> *mut u8 {
    let f: unsafe extern "C" fn(*mut u8) -> *mut u8 =
        unsafe { core::mem::transmute(0x0810_ec10usize) };
    unsafe { f(base) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base_destruct(_base: *mut u8) -> *mut u8 {
    panic!("pair_header_destruct requires base teardown 0x0810ec10")
}

/// Active base-subobject teardown (`FUN_0810ec10` @ 0x0810ec10).
/// retailOS default invokes the firmware function directly; host tests
/// replace it with a recording mock.
#[cfg(target_os = "none")]
pub static mut PAIR_HEADER_BASE_DESTRUCT: unsafe extern "C" fn(
    base: *mut u8,
) -> *mut u8 = firmware_base_destruct;

#[cfg(not(target_os = "none"))]
pub static mut PAIR_HEADER_BASE_DESTRUCT: unsafe extern "C" fn(
    base: *mut u8,
) -> *mut u8 = missing_base_destruct;

/// pair_header_destruct — original: `FUN_08124a5c` @ 0x08124a5c
/// (52 bytes; 63 `bl` call sites).
///
/// Disposes the owned sub-object at +0xc4 when one is installed
/// (ported trivial destructor + ported tag-2 `operator delete`),
/// clears the word unconditionally, then chains to the base
/// subobject's teardown at this+0x0c and returns its result backed
/// off by 0x0c. See the module header for the evidence and the seam
/// contract.
///
/// # Safety
///
/// `this` must point into a writable allocation covering
/// `this..this+0xc8`, word-aligned; a non-zero +0xc4 word must name a
/// live tag-2 heap block. All as in the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pair_header_destruct(this: *mut u8) -> *mut u8 {
    let owned = (this.add(PAIR_HEADER_OWNED) as *const u32).read_volatile();
    if owned != 0 {
        // Destruct-then-free, both ported. The destruct call's result
        // is discarded exactly as the original discards it.
        unsafe {
            crate::cxx::trivial_destructor::trivial_destructor(owned as *mut core::ffi::c_void);
            crate::heap::veneers::operator_delete(owned as *mut u8);
        }
    }
    unsafe { (this.add(PAIR_HEADER_OWNED) as *mut u32).write_volatile(0) };
    let base_destruct = unsafe { addr_of_mut!(PAIR_HEADER_BASE_DESTRUCT).read_volatile() };
    let adjusted = unsafe { base_destruct(unsafe { this.add(PAIR_HEADER_BASE) }) };
    unsafe { adjusted.sub(PAIR_HEADER_BASE_ADJUST) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::veneers::tests::{free_log, mock_heap};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the tests that swap the seam and the heap ops.
    static DESTRUCT_LOCK: Mutex<()> = Mutex::new(());

    /// Base-teardown invocations, in order.
    static mut BASE_CALLS: Vec<*mut u8> = Vec::new();

    /// What the mock base teardown returns.
    static mut BASE_RESULT: *mut u8 = core::ptr::null_mut();

    /// A fake owned-block address that round-trips through the 32-bit
    /// field (the veneers.rs BLOCK_A convention); the mock heap only
    /// records it.
    const OWNED: u32 = 0xA110_0000;

    /// A fixture address for the base teardown's return; must clear
    /// the 0xc back-adjust. A bare constant: the port only does
    /// arithmetic on it.
    const BASE_RESULT_ADDR: usize = 0x0855_0400;

    unsafe extern "C" fn recording_base_destruct(base: *mut u8) -> *mut u8 {
        unsafe {
            (*addr_of_mut!(BASE_CALLS)).push(base);
            core::ptr::read_volatile(core::ptr::addr_of!(BASE_RESULT))
        }
    }

    /// 0xc8-byte fixture object (the class's 200-byte extent).
    #[repr(align(4))]
    struct Object([u8; 0xc8]);

    fn mock() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let slot_guard = DESTRUCT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let heap_guard = mock_heap();
        unsafe {
            addr_of_mut!(PAIR_HEADER_BASE_DESTRUCT).write_volatile(recording_base_destruct);
            (*addr_of_mut!(BASE_CALLS)).clear();
            BASE_RESULT = BASE_RESULT_ADDR as *mut u8;
        }
        (slot_guard, heap_guard)
    }

    fn restore(guards: (MutexGuard<'static, ()>, MutexGuard<'static, ()>)) {
        unsafe {
            addr_of_mut!(PAIR_HEADER_BASE_DESTRUCT).write_volatile(missing_base_destruct);
        }
        drop(guards);
    }

    fn object_with(owned: u32) -> Object {
        let mut object = Object([0xa5; 0xc8]);
        object.0[PAIR_HEADER_OWNED..PAIR_HEADER_OWNED + 4]
            .copy_from_slice(&owned.to_le_bytes());
        object
    }

    #[test]
    fn an_installed_subobject_is_destructed_freed_and_cleared() {
        let guards = mock();
        let mut object = object_with(OWNED);
        let this = object.0.as_mut_ptr();
        unsafe {
            let returned = pair_header_destruct(this);

            let (frees, freed, tag) = free_log();
            assert_eq!(frees, 1, "the owned block is deleted exactly once");
            assert_eq!(freed, OWNED as *mut u8, "the +0xc4 pointer, not this");
            assert_eq!(tag, 2, "through the tag-2 operator delete");
            assert_eq!(
                u32::from_le_bytes(
                    object.0[PAIR_HEADER_OWNED..PAIR_HEADER_OWNED + 4].try_into().unwrap()
                ),
                0,
                "the word is cleared after the free"
            );
            assert_eq!(
                *core::ptr::addr_of!(BASE_CALLS),
                std::vec![this.add(PAIR_HEADER_BASE)],
                "the chained teardown gets this + 0xc"
            );
            assert_eq!(
                returned,
                (BASE_RESULT_ADDR - PAIR_HEADER_BASE_ADJUST) as *mut u8,
                "the teardown's result minus 0xc"
            );
        }
        restore(guards);
    }

    #[test]
    fn an_empty_subobject_field_skips_the_free_but_still_clears_and_chains() {
        let guards = mock();
        let mut object = object_with(0);
        let this = object.0.as_mut_ptr();
        unsafe {
            let returned = pair_header_destruct(this);

            let (frees, _, _) = free_log();
            assert_eq!(frees, 0, "cmp/beq: no delete without an owned block");
            assert_eq!(
                u32::from_le_bytes(
                    object.0[PAIR_HEADER_OWNED..PAIR_HEADER_OWNED + 4].try_into().unwrap()
                ),
                0,
                "the (already zero) word is stored regardless"
            );
            assert_eq!(
                *core::ptr::addr_of!(BASE_CALLS),
                std::vec![this.add(PAIR_HEADER_BASE)],
                "the base teardown is unconditional"
            );
            assert_eq!(returned, (BASE_RESULT_ADDR - PAIR_HEADER_BASE_ADJUST) as *mut u8);
        }
        restore(guards);
    }

    #[test]
    fn the_container_of_adjustment_is_exact() {
        let guards = mock();
        let mut object = object_with(0);
        unsafe {
            for result in [0x0855_0400usize, 0x0800_1000, 0x0fff_ff00] {
                addr_of_mut!(BASE_RESULT).write_volatile(result as *mut u8);
                assert_eq!(
                    pair_header_destruct(object.0.as_mut_ptr()),
                    (result - 0xc) as *mut u8,
                    "result {result:#x} minus 0xc"
                );
            }
        }
        restore(guards);
    }
}
