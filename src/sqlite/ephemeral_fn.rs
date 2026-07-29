//! The ephemeral-function release — how the VDBE decides whether a
//! `FuncDef` payload is owned (schema-generated, to be freed) or
//! borrowed (registered at startup, left alone).
//!
//! - `free_ephemeral_function` — original: `FUN_082cf358` @ 0x082cf358
//!   (20 bytes; 1 `bl` + 1 tail `b` call site, both inside
//!   `vdbe_free_p4` @ 0x082cf388: the -7 branch calls it on the
//!   context's first word, the -5 branch tail-calls it on the payload
//!   itself). Upstream SQLite's `freeEphemeralFunction`, minus the `db`
//!   argument (this build's allocators are global).
//!
//! Algorithm: five instructions. A NULL `FuncDef` returns immediately
//! (`cmp r0,#0`); otherwise the flags byte at +4 is loaded
//! (`ldrbne r1,[r0,#0x4]`) and tested against the ephemeral bit 0x4
//! (`tstne r1,#0x4`). Only an ephemeral definition is freed — a
//! conditional tail branch (`bne`) into `sqlite3_free` @ 0x083906f4,
//! here its ported twin [`tracked_free`]. A non-ephemeral definition is
//! a borrowed pointer into the function registry and is left untouched.
//!
//! The `FuncDef` layout this build uses has a single flags byte at +4
//! (upstream of this era carries `i16 nArg` at +2 and `u8 flags` at
//! +4 with `SQLITE_FUNC_EPHEM == 0x04`; the layout matches).
//!
//! Deviations: none.

use crate::heap::tracked::tracked_free;

/// Byte offset of the `FuncDef` flags byte (`ldrbne r1,[r0,#0x4]`).
const FUNC_FLAGS_OFFSET: usize = 4;

/// The owned/ephemeral bit of the flags byte (`tstne r1,#0x4`) —
/// upstream's `SQLITE_FUNC_EPHEM`.
const FUNC_FLAG_EPHEMERAL: u8 = 0x4;

/// free_ephemeral_function — original: `FUN_082cf358` @ 0x082cf358
/// (20 bytes).
///
/// Free `funcdef` through the tag-57 tracked allocator when, and only
/// when, it is non-NULL and its flags byte at +4 has the ephemeral bit
/// (0x4) set. NULL and borrowed (non-ephemeral) definitions are left
/// exactly as found — the flags byte of a NULL pointer is never read.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn free_ephemeral_function(funcdef: *mut u8) {
    if funcdef.is_null() {
        return;
    }
    if funcdef.add(FUNC_FLAGS_OFFSET).read() & FUNC_FLAG_EPHEMERAL != 0 {
        // Original: `bne sqlite3_free` — a conditional tail call.
        tracked_free(funcdef);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// Every heap free the code under test triggered, in order.
    static mut FREES: Vec<(usize, usize)> = Vec::new();

    unsafe extern "C" fn recording_heap_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(FREES)).push((ptr as usize, tag));
    }

    /// Installs the mock heap and routes frees into the log.
    fn bench() -> MutexGuard<'static, ()> {
        let guard = mock_heap();
        unsafe {
            (*core::ptr::addr_of_mut!(FREES)).clear();
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_heap_free;
        }
        guard
    }

    fn frees() -> Vec<(usize, usize)> {
        unsafe { (*core::ptr::addr_of!(FREES)).clone() }
    }

    /// A hand-built tag-57 tracked block whose payload plays the
    /// `FuncDef` (layout: `heap::tracked`). Raw block at offset 0 of a
    /// 32-aligned buffer, payload at raw + 32, pad word 32 - 8 = 24.
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
        fn set_flags(&mut self, flags: u8) {
            // In-bounds: payload + 4 < raw + 64.
            unsafe { self.payload().add(FUNC_FLAGS_OFFSET).write(flags) };
        }
    }

    #[test]
    fn a_null_funcdef_is_never_read_nor_freed() {
        let _guard = bench();
        unsafe { free_ephemeral_function(core::ptr::null_mut()) };
        assert!(frees().is_empty());
    }

    #[test]
    fn a_non_ephemeral_funcdef_is_left_untouched() {
        let _guard = bench();
        // Every byte value without bit 0x4 set: the definition is
        // borrowed from the function registry.
        for flags in [0x00u8, 0x01, 0x03, 0xfb, 0x7b] {
            let mut block = TrackedBlock::new();
            block.set_flags(flags);
            unsafe { free_ephemeral_function(block.payload()) };
            assert!(frees().is_empty(), "flags {flags:#04x} must not free");
        }
    }

    #[test]
    fn an_ephemeral_funcdef_is_freed_with_tag_fifty_seven() {
        let _guard = bench();
        // Every byte value with bit 0x4 set: the definition is owned.
        for flags in [0x04u8, 0x05, 0x07, 0xff, 0x84] {
            let mut block = TrackedBlock::new();
            let raw = block.raw();
            block.set_flags(flags);
            unsafe { free_ephemeral_function(block.payload()) };
            assert_eq!(
                frees(),
                std::vec![(raw as usize, TAG_TRACKED)],
                "flags {flags:#04x} frees the raw block"
            );
            unsafe { (*core::ptr::addr_of_mut!(FREES)).clear() };
        }
    }

    #[test]
    fn the_default_free_p4_slot_is_this_function() {
        use crate::sqlite::free_p4::DEFAULT_FREE_P4_AUX_OPS;
        assert_eq!(
            DEFAULT_FREE_P4_AUX_OPS.free_ephemeral_function as usize,
            free_ephemeral_function as usize,
            "vdbe_free_p4's -5/-7 branches reach the ported release by default"
        );
    }
}
