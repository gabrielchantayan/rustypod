//! Close eligible cursors in a VDBE's cursor array.
//!
//! RetailOS `FUN_082c387c` at load address `0x082c387c`, 104 bytes:
//! `0x082c387c..0x082c38e3`, followed by a new prologue at `0x082c38e4`.
//! Raw aligned ARM words verify two inbound plain BL sites (0x08044c84,
//! 0x0838b0a8), zero predicated inbound BL sites, and one outbound plain BL
//! at 0x082c38c4 to `vdbe_free_cursor` (zero predicated outbound BLs).
//! Walk signed nCursor at +0x2c and the u32-pointer array at +0x30. Skip NULL
//! entries and, when inVtabMethod (+0x101) is nonzero, cursors with a nonzero
//! virtual-table cursor at +0x60. Release each eligible cursor, then reload
//! the array and clear its slot. Ghidra omits the live r1 cursor argument.
//! No deliberate behavioral deviations; host fixtures retain target-width
//! pointer slots rather than using the host's wider Vdbe field layout.

use crate::sqlite::vdbe::Vdbe;
use crate::sqlite::vdbe_free_cursor::vdbe_free_cursor;

const CURSOR_COUNT: usize = 0x2c;
const CURSOR_ARRAY: usize = 0x30;
const IN_VTAB_METHOD: usize = 0x101;
const VTAB_CURSOR: usize = 0x60;

unsafe fn cursor_array(vdbe: *mut u8) -> *mut u32 {
    unsafe { vdbe.add(CURSOR_ARRAY).cast::<u32>().read() as usize as *mut u32 }
}

/// Close cursors except virtual-table cursors during reentrant vtab dispatch.
///
/// # Safety
/// `vdbe` must have the retail 32-bit layout. Its cursor array and non-NULL
/// cursors must remain valid for the guarded reads and `vdbe_free_cursor`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_close_all_cursors(vdbe: *mut Vdbe) {
    let base = vdbe.cast::<u8>();
    if unsafe { cursor_array(base) }.is_null() {
        return;
    }
    let mut index = 0i32;
    while index < unsafe { base.add(CURSOR_COUNT).cast::<i32>().read() } {
        let cursor = unsafe { cursor_array(base).add(index as usize).read() as usize as *mut u8 };
        if !cursor.is_null() && (unsafe { base.add(IN_VTAB_METHOD).read() } == 0
            || unsafe { cursor.add(VTAB_CURSOR).cast::<u32>().read() } == 0) {
            unsafe { vdbe_free_cursor(vdbe, cursor) };
            unsafe { cursor_array(base).add(index as usize).write(0) };
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn signed_bounds_null_slots_and_reentrant_vtab_preservation() {
        let Some(slab) = try_map_u32_slab(hints::VDBE_CLOSE_ALL_CURSORS, 0x1000) else {
            assert!(note_missing_u32_fixture("sqlite/vdbe_close_all_cursors"));
            return;
        };
        unsafe {
            slab.write_bytes(0, 0x1000);
            let slots = slab.add(0x200).cast::<u32>();
            let ordinary = slab.add(0x300);
            let vtab = slab.add(0x400);
            let trailing = slab.add(0x500);
            slab.add(CURSOR_COUNT).cast::<i32>().write(3);
            // NULL array must return even with a positive count.
            vdbe_close_all_cursors(slab.cast());
            assert_eq!(slab.add(CURSOR_COUNT).cast::<i32>().read(), 3);
            slab.add(CURSOR_ARRAY).cast::<u32>().write(slots as usize as u32);
            slots.write(ordinary as usize as u32);
            slots.add(1).write(0);
            slots.add(2).write(vtab as usize as u32);
            slots.add(3).write(trailing as usize as u32);
            // No owned resources: real release is safe, with no host dispatch.
            ordinary.add(0x1f).write(1);
            trailing.add(0x1f).write(1);
            vtab.add(VTAB_CURSOR).cast::<u32>().write(0x1234);
            slab.add(IN_VTAB_METHOD).write(2);
            for count in [-1, 0] {
                slab.add(CURSOR_COUNT).cast::<i32>().write(count);
                vdbe_close_all_cursors(slab.cast());
                assert_eq!(slots.read(), ordinary as usize as u32);
                assert_eq!(slots.add(2).read(), vtab as usize as u32);
            }
            slab.add(CURSOR_COUNT).cast::<i32>().write(3);
            vdbe_close_all_cursors(slab.cast());
            assert_eq!(slots.read(), 0);
            assert_eq!(slots.add(1).read(), 0);
            assert_eq!(slots.add(2).read(), vtab as usize as u32);
            assert_eq!(slots.add(3).read(), trailing as usize as u32);
            assert_eq!(slab.add(IN_VTAB_METHOD).read(), 2);
            // A zero vtab pointer makes the retained cursor eligible.
            vtab.add(VTAB_CURSOR).cast::<u32>().write(0);
            vtab.add(0x1f).write(1);
            slab.add(IN_VTAB_METHOD).write(0);
            vdbe_close_all_cursors(slab.cast());
            assert_eq!(slots.add(2).read(), 0);
            assert_eq!(slots.add(3).read(), trailing as usize as u32);
        }
    }
}
