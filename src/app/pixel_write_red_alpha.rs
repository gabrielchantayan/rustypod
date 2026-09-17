//! Writes the red and alpha channels of one RGBA pixel to an output cursor.
//!
//! `pixel_write_red_alpha` — original `FUN_0826041c` @ **0x0826041c**
//! (44 bytes, `0x0826041c..0x08260448`). The next independently linked leaf
//! starts at `0x08260448`. Decoding the eleven ARM words in `osos.dec` finds
//! four inbound plain `bl` calls and no predicated `bl` calls.
//!
//! The leaf obtains the current byte cursor from `output_cursor`, writes
//! `rgba[0]`, then obtains the advanced cursor again and writes `rgba[3]`.
//! It therefore emits red-alpha (GL_LUMINANCE_ALPHA-style) output and advances
//! the cursor by two bytes. Deliberate deviation: volatile accesses preserve
//! the original load/store order and prohibit LLVM from coalescing the two
//! byte stores; the firmware itself uses ordinary memory accesses.

/// Appends the red and alpha bytes of an RGBA pixel to `output_cursor`.
///
/// `output_cursor` is a target-width pointer field, and `rgba` must address
/// at least four readable bytes. Both pointers must be valid for the accesses
/// performed by the retailOS implementation.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pixel_write_red_alpha(
    _context: u32,
    output_cursor: *mut u32,
    rgba: *const u8,
) {
    unsafe {
        let target = core::ptr::read_volatile(output_cursor) as *mut u8;
        let red = core::ptr::read_volatile(rgba);
        core::ptr::write_volatile(output_cursor, target.add(1) as u32);
        core::ptr::write_volatile(target, red);

        let target = core::ptr::read_volatile(output_cursor) as *mut u8;
        let alpha = core::ptr::read_volatile(rgba.add(3));
        core::ptr::write_volatile(output_cursor, target.add(1) as u32);
        core::ptr::write_volatile(target, alpha);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::PIXEL_WRITE_RED_ALPHA, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn appends_red_and_alpha_and_advances_the_target_width_cursor() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/pixel_write_red_alpha"));
            return;
        };
        let base = base as *mut u8;
        let rgba = [0x12, 0x34, 0x56, 0xa1];
        unsafe {
            core::ptr::write_bytes(base, 0xcc, FIXTURE_LEN);
            let mut output_cursor = base.add(0x80) as u32;
            pixel_write_red_alpha(0, &mut output_cursor, rgba.as_ptr());
            assert_eq!(base.add(0x7f).read(), 0xcc);
            assert_eq!(base.add(0x80).read(), 0x12);
            assert_eq!(base.add(0x81).read(), 0xa1);
            assert_eq!(base.add(0x82).read(), 0xcc);
            assert_eq!(output_cursor, base.add(0x82) as u32);
        }
    }

    #[test]
    fn appends_multiple_pixels_without_overwriting_prior_output() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = *FIXTURE else {
            assert!(note_missing_u32_fixture("app/pixel_write_red_alpha"));
            return;
        };
        let base = base as *mut u8;
        let first = [1, 2, 3, 4];
        let second = [0xfe, 0xfd, 0xfc, 0xfb];
        unsafe {
            core::ptr::write_bytes(base, 0, FIXTURE_LEN);
            let mut output_cursor = base.add(0x200) as u32;
            pixel_write_red_alpha(0, &mut output_cursor, first.as_ptr());
            pixel_write_red_alpha(0xffff_ffff, &mut output_cursor, second.as_ptr());
            assert_eq!(&core::slice::from_raw_parts(base.add(0x200), 4), &[1, 4, 0xfe, 0xfb]);
            assert_eq!(output_cursor, base.add(0x204) as u32);
        }
    }
}
