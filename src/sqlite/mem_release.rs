//! The value guts release — how the VDBE frees the dynamic resources of
//! a `Mem`/`sqlite3_value` without freeing the shell.
//!
//! - `mem_release` — original: `FUN_0838c04c` @ 0x0838c04c (40 bytes;
//!   ~20 `bl` call sites across the VDBE column/row teardowns plus one
//!   tail `b` @ 0x082d9728; `value_free` @ 0x08386504 calls it before
//!   freeing the shell, and the aggregate branch of the extern release
//!   @ 0x0838c074 tail-calls back into it). Upstream SQLite's
//!   `sqlite3VdbeMemRelease`.
//!
//! Algorithm: three steps. First the extern release @ 0x0838c074 runs
//! (`bl`) — that helper finalizes an aggregate context when the flags
//! halfword at +0x1c has bit 0x400 set (`MEM_Agg`), invokes the `xDel`
//! destructor at +0x20 on the string pointer at +0x14 when bit 0x40 is
//! set (`MEM_Dyn`), and NULLs `xDel`; it IS ported
//! ([`sqlite::mem_extern_release`](crate::sqlite::mem_extern_release))
//! and is the shipped default of the [`MEM_EXTERN_OPS`] slot. Then
//! `zMalloc` at +0x24 is freed raw — the original's
//! `ldr r0,[r4,#0x24]; bl sqlite3_free` @ 0x083906f4, here
//! [`tracked_free`] (NULL-tolerant, matching the original's
//! unconditional call on a possibly-NULL `zMalloc`). Finally `z` +0x14,
//! `zMalloc` +0x24 and `xDel` +0x20 are NULLed in that order
//! (`mov r0,#0x0; str` x3) so a re-released `Mem` is inert.
//!
//! `Mem` layout this build uses (cross-checked against the value
//! destructor @ 0x08386504 and the extern release @ 0x0838c074):
//!
//! ```text
//! +0x14 z        string/blob payload pointer
//! +0x1c flags    u16; bit 0x400 = aggregate context, bit 0x40 = has xDel
//! +0x20 xDel     external destructor for z
//! +0x24 zMalloc  owned buffer backing z
//! ```
//!
//! Deviations:
//! - The extern release @ 0x0838c074 IS ported
//!   ([`sqlite::mem_extern_release`](crate::sqlite::mem_extern_release))
//!   and is the shipped default of the [`MEM_EXTERN_OPS`] slot (the
//!   slot is kept so host tests can intercept it); its own aggregate
//!   finalize dependency @ 0x0838bc38 IS ported
//!   ([`sqlite::mem_finalize`](crate::sqlite::mem_finalize::mem_finalize))
//!   and is the shipped default of that module's
//!   `MEM_AGG_FINALIZE_OPS` slot.
//! - `sqlite3_free` @ 0x083906f4 IS ported
//!   ([`tracked_free`](crate::heap::tracked::tracked_free)) and is
//!   called directly, per the porting rules. Its NULL guard stands in
//!   for the original's, which also runs unconditionally on `zMalloc`.
//! - This port is the shipped default `mem_release` slot of
//!   `value_free`'s `VALUE_MEM_OPS`.

use crate::heap::tracked::tracked_free;
use crate::sqlite::mem_extern_release::mem_extern_release;

/// Byte offset of `Mem.z` (original: `str r0,[r4,#0x14]`).
pub const Z_OFFSET: usize = 0x14;
/// Byte offset of the `Mem` flags halfword (read by the extern release
/// @ 0x0838c074: `ldrh r0,[r0,#0x1c]`).
pub const FLAGS_OFFSET: usize = 0x1c;
/// Flags bit: the value holds an aggregate context (upstream `MEM_Agg`).
pub const FLAG_AGG: u16 = 0x400;
/// Flags bit: the value has an external `xDel` destructor (upstream
/// `MEM_Dyn`).
pub const FLAG_DYN: u16 = 0x40;
/// Byte offset of `Mem.xDel` (original: `str r0,[r4,#0x20]`).
pub const X_DEL_OFFSET: usize = 0x20;
/// Byte offset of `Mem.zMalloc` (original: `ldr r0,[r4,#0x24]`).
pub const Z_MALLOC_OFFSET: usize = 0x24;

/// Indirect dispatch for the unported extern release @ 0x0838c074
/// (kept behind the table so host tests can intercept it).
#[derive(Clone, Copy)]
pub struct MemExternOps {
    /// The extern release @ 0x0838c074: finalize the aggregate context
    /// (flags bit [`FLAG_AGG`] at [`FLAGS_OFFSET`]) or invoke the
    /// `xDel` destructor at [`X_DEL_OFFSET`] on the string at
    /// [`Z_OFFSET`] (flags bit [`FLAG_DYN`]), and clear `xDel`.
    /// Upstream's `vdbeMemClearExternAndSetNull`. Ported
    /// ([`mem_extern_release`]) and the shipped default.
    pub extern_release: unsafe extern "C" fn(value: *mut u8),
}

/// Wired default: the ported extern release @ 0x0838c074
/// ([`mem_extern_release`]).
pub const DEFAULT_MEM_EXTERN_OPS: MemExternOps = MemExternOps {
    extern_release: mem_extern_release,
};

/// The active extern release. Host tests install recording mocks.
pub static mut MEM_EXTERN_OPS: MemExternOps = DEFAULT_MEM_EXTERN_OPS;

/// Reads the extern-release slot (volatile — the slot is meant to be
/// swapped at runtime, and a plain read lets LLVM const-fold the
/// default away).
#[inline(always)]
pub(crate) unsafe fn extern_release_op() -> unsafe extern "C" fn(*mut u8) {
    core::ptr::read_volatile(core::ptr::addr_of!(MEM_EXTERN_OPS.extern_release))
}

/// mem_release — original: `FUN_0838c04c` @ 0x0838c04c (40 bytes).
///
/// `sqlite3VdbeMemRelease`: release the dynamic guts of the value
/// `value` without freeing the shell. The extern release @ 0x0838c074
/// (the [`MEM_EXTERN_OPS`] slot) runs first, then `zMalloc` is freed
/// raw through the tag-57 tracked allocator, then `z`, `zMalloc` and
/// `xDel` are NULLed in that order — the original's
/// `bl; ldr/bl; mov r0,#0x0; str; str; str` body.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn mem_release(value: *mut u8) {
    (extern_release_op())(value);
    let z_malloc = (value.add(Z_MALLOC_OFFSET) as *const *mut u8).read();
    tracked_free(z_malloc);
    let zero = core::ptr::null_mut::<u8>();
    (value.add(Z_OFFSET) as *mut *mut u8).write(zero);
    (value.add(Z_MALLOC_OFFSET) as *mut *mut u8).write(zero);
    (value.add(X_DEL_OFFSET) as *mut *mut u8).write(zero);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes tests that swap the extern-release slot.
    static OPS_LOCK: Mutex<()> = Mutex::new(());

    /// Every release/free the code under test triggered, in order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        ExternRelease(usize),
        RawFree(usize, usize),
    }

    static mut EVENTS: Vec<Event> = Vec::new();

    unsafe extern "C" fn recording_extern_release(value: *mut u8) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::ExternRelease(value as usize));
    }

    unsafe extern "C" fn recording_heap_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(EVENTS)).push(Event::RawFree(ptr as usize, tag));
    }

    /// Installs the mock heap (first — the lock order `error_msg`'s
    /// tests establish), routes frees into the event log, and installs
    /// the recording extern release. The guards must stay alive for the
    /// whole test.
    fn bench() -> (MutexGuard<'static, ()>, MutexGuard<'static, ()>) {
        let heap_guard = mock_heap();
        let ops_guard = OPS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            (*core::ptr::addr_of_mut!(EVENTS)).clear();
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!(MEM_EXTERN_OPS),
                MemExternOps {
                    extern_release: recording_extern_release,
                },
            );
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_heap_free;
        }
        (heap_guard, ops_guard)
    }

    fn events() -> Vec<Event> {
        unsafe { (*core::ptr::addr_of!(EVENTS)).clone() }
    }

    /// A hand-built tag-57 tracked block (layout: `heap::tracked`). Raw
    /// block at offset 0 of a 32-aligned buffer, payload at raw + 32,
    /// pad word 32 - 8 = 24.
    #[repr(align(32))]
    struct TrackedBlock([u8; 64]);

    impl TrackedBlock {
        fn new() -> Self {
            let mut block = TrackedBlock([0; 64]);
            block.0[0..4].copy_from_slice(&24i32.to_le_bytes());
            let pad = (32 - BLOCK_HEADER_SIZE) as u32;
            block.0[28..32].copy_from_slice(&pad.to_le_bytes());
            block
        }
        fn raw(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn payload(&mut self) -> *mut u8 {
            // In-bounds by construction (64-byte block, payload at 32).
            unsafe { self.0.as_mut_ptr().add(32) }
        }
    }

    /// A scratch `Mem` big enough for the +0x24 field plus one host
    /// pointer (word writes at 0x24 span 0x24..0x2c on a 64-bit host).
    #[repr(align(8))]
    struct Mem([u8; 0x30]);

    impl Mem {
        fn new() -> Self {
            Mem([0; 0x30])
        }
        fn ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn set_word(&mut self, offset: usize, word: *mut u8) {
            // In-bounds: largest field is zMalloc at 0x24, block is 0x30.
            unsafe { (self.ptr().add(offset) as *mut *mut u8).write(word) };
        }
        fn word(&self, offset: usize) -> *mut u8 {
            unsafe { (self.0.as_ptr().add(offset) as *const *mut u8).read() }
        }
    }

    #[test]
    fn releases_extern_then_frees_z_malloc_then_nulls_the_three_fields() {
        let _guards = bench();
        let mut value = Mem::new();
        let mut z_malloc_block = TrackedBlock::new();
        let z_malloc_raw = z_malloc_block.raw();
        let z = 0x0bad_beefusize as *mut u8;
        let x_del = 0x0bad_d00dusize as *mut u8;
        value.set_word(Z_OFFSET, z);
        value.set_word(X_DEL_OFFSET, x_del);
        value.set_word(Z_MALLOC_OFFSET, z_malloc_block.payload());

        let value_ptr = value.ptr();
        unsafe { mem_release(value_ptr) };

        assert_eq!(
            events(),
            std::vec![
                Event::ExternRelease(value_ptr as usize),
                Event::RawFree(z_malloc_raw as usize, TAG_TRACKED),
            ],
            "extern release first, zMalloc free second — the original's bl; ldr/bl order"
        );
        assert!(value.word(Z_OFFSET).is_null(), "z NULLed");
        assert!(value.word(Z_MALLOC_OFFSET).is_null(), "zMalloc NULLed");
        assert!(value.word(X_DEL_OFFSET).is_null(), "xDel NULLed");
    }

    #[test]
    fn a_null_z_malloc_is_tolerated_and_the_fields_are_still_nulled() {
        let _guards = bench();
        let mut value = Mem::new();
        let z = 0x0bad_beefusize as *mut u8;
        value.set_word(Z_OFFSET, z);
        value.set_word(X_DEL_OFFSET, 0x0bad_d00dusize as *mut u8);
        // zMalloc left NULL: the original calls sqlite3_free on it
        // unconditionally and relies on the free's NULL guard.

        let value_ptr = value.ptr();
        unsafe { mem_release(value_ptr) };

        assert_eq!(
            events(),
            std::vec![Event::ExternRelease(value_ptr as usize)],
            "no free for a NULL zMalloc, extern release still runs"
        );
        assert!(value.word(Z_OFFSET).is_null());
        assert!(value.word(Z_MALLOC_OFFSET).is_null());
        assert!(value.word(X_DEL_OFFSET).is_null());
    }

    #[test]
    fn the_default_value_free_slot_is_this_function() {
        use crate::sqlite::value_free::DEFAULT_VALUE_MEM_OPS;
        assert_eq!(
            DEFAULT_VALUE_MEM_OPS.mem_release as usize,
            mem_release as usize,
            "value_free's guts release is the ported mem_release by default"
        );
    }

    #[test]
    fn the_default_extern_release_is_the_ported_function() {
        use crate::sqlite::mem_extern_release::mem_extern_release;
        assert_eq!(
            DEFAULT_MEM_EXTERN_OPS.extern_release as usize,
            mem_extern_release as usize,
            "the extern release @ 0x0838c074 is ported and shipped by default"
        );
    }
}
