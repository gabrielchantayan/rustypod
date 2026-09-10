//! Current-entry accessor for a fixed-matrix cursor.

use crate::util::fixed_matrix_identity::FixedMatrix4x4;

/// Target-width cursor fields read by [`fixed_matrix_cursor_current`].
///
/// The retailOS ABI stores both fields as 32-bit words, even on a host where
/// native pointers are wider.
#[repr(C)]
pub struct FixedMatrixCursor {
    /// +0x00: base address of the first [`FixedMatrix4x4`] entry.
    pub matrix_base: u32,
    /// +0x04: zero-based current entry index.
    pub index: u32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(FixedMatrixCursor, matrix_base)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(FixedMatrixCursor, index)];
const _: [u8; 0x08] = [0; core::mem::size_of::<FixedMatrixCursor>()];

/// fixed_matrix_cursor_current — original: `FUN_08242ec4` @ **0x08242ec4**
/// (20 bytes, `0x08242ec4..0x08242ed4`; raw decoding finds the next separately
/// linked function at `0x08242ed8`). Every ARM B/BL word in `osos.dec` yields
/// **11 direct inbound `bl` sites**, all unconditional: no predicated calls,
/// tail branches, or aligned DATA references name this body.
///
/// Loads the cursor's 32-bit matrix base and index, then returns
/// `matrix_base + index * 0x44`. The two ARM additions implement modulo-$2^{32}$
/// arithmetic, so the Rust port deliberately uses wrapping arithmetic before
/// converting the result to a typed pointer.
///
/// Deliberate deviations: none.
///
/// # Safety
///
/// `cursor` must point to readable, aligned target-width cursor storage. The
/// returned address is not validated or dereferenced; as in retailOS, callers
/// own its validity and alignment.
#[cfg_attr(target_os = "none", link_section = ".text.fixed_matrix_cursor_current")]
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn fixed_matrix_cursor_current(
    cursor: *const FixedMatrixCursor,
) -> *mut FixedMatrix4x4 {
    let matrix_base = (*cursor).matrix_base;
    let index = (*cursor).index;
    matrix_base
        .wrapping_add(index.wrapping_mul(core::mem::size_of::<FixedMatrix4x4>() as u32))
        as usize as *mut FixedMatrix4x4
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{fixed_matrix_cursor_current, FixedMatrixCursor};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const SLAB_LEN: usize = 0x1000;
    const MATRIX_OFFSET: usize = 0x100;

    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::FIXED_MATRIX_CURSOR, SLAB_LEN).map(|pointer| pointer as usize)
    });
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn cursor_fixture(index: u32) -> Option<(*const FixedMatrixCursor, u32)> {
        let base = *SLAB.as_ref()? as *mut u8;
        let matrix_base = unsafe { base.add(MATRIX_OFFSET) } as usize as u32;
        unsafe {
            ptr::write_bytes(base, 0, SLAB_LEN);
            base.cast::<FixedMatrixCursor>().write(FixedMatrixCursor { matrix_base, index });
        }
        Some((base.cast(), matrix_base))
    }

    #[test]
    fn returns_first_and_later_0x44_byte_matrix_entries() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((cursor, matrix_base)) = cursor_fixture(0) else {
            note_missing_u32_fixture("util::fixed_matrix_cursor");
            return;
        };

        unsafe {
            assert_eq!(fixed_matrix_cursor_current(cursor) as usize as u32, matrix_base);
            (*(cursor as *mut FixedMatrixCursor)).index = 7;
            assert_eq!(
                fixed_matrix_cursor_current(cursor) as usize as u32,
                matrix_base.wrapping_add(7 * 0x44),
            );
        }
    }

    #[test]
    fn wraps_target_word_address_for_large_indices() {
        let cursor = FixedMatrixCursor {
            matrix_base: 0xffff_ffc0,
            index: u32::MAX,
        };

        let actual = unsafe { fixed_matrix_cursor_current(&cursor) } as usize as u32;
        assert_eq!(actual, 0xffff_ff7c);
    }
}
