//! Setter for the view transition-mode bits.

use super::view_base::ViewBase;

/// view_set_transition_mode — original: `FUN_0826ddd4` @ `0x0826ddd4` (20 bytes).
///
/// Raw ARM: `ldr r2,[r0,#0x48]; bic r2,r2,#0x1800; orr r1,r2,r1;
/// str r1,[r0,#0x48]; bx lr`. The next real function begins at
/// `0x0826dde8`; raw `osos.dec` decoding finds five unconditional `bl` callers
/// and no predicated `bl` callers. Clears the view's two-bit transition-mode
/// field (bits 11–12), then ORs in the caller-provided mode word. Deliberate
/// deviations: none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_set_transition_mode(view: *mut ViewBase, mode: u32) {
    unsafe {
        (*view).flags = ((*view).flags & !0x1800) | mode;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct ViewStorage([u8; 0x4c]);

    unsafe fn flags(storage: &ViewStorage) -> u32 {
        unsafe { (storage.0.as_ptr().add(0x48) as *const u32).read() }
    }

    #[test]
    fn replaces_only_the_transition_mode_field() {
        for &(initial, mode, expected) in &[
            (0xffff_ffff, 0x800, 0xffff_efff),
            (0xa5a5_0000, 0x1000, 0xa5a5_1000),
            (0x1234_1800, 0, 0x1234_0000),
            (0x0000_0800, 0x4000, 0x0000_4000),
        ] {
            let mut storage = ViewStorage([0; 0x4c]);
            unsafe {
                (storage.0.as_mut_ptr().add(0x48) as *mut u32).write(initial);
                view_set_transition_mode(storage.0.as_mut_ptr().cast(), mode);
            }
            assert_eq!(unsafe { flags(&storage) }, expected);
        }
    }
}
