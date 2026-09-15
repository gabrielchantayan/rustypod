//! Setter for the view interaction-mode bits.

use super::view_base::ViewBase;

/// view_set_interaction_mode — original: `FUN_0826db24` @ `0x0826db24` (20 bytes).
///
/// Raw ARM: `ldr r2,[r0,#0x48]; bic r2,r2,#0x600; orr r1,r2,r1;
/// str r1,[r0,#0x48]; bx lr`. The next real function begins at
/// `0x0826db38`; raw `osos.dec` decoding finds five unconditional `bl` callers
/// and no predicated `bl` callers. Clears the view's two-bit interaction-mode
/// field (bits 9–10), then ORs in the caller-provided mode word. Deliberate
/// deviations: none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_set_interaction_mode(view: *mut ViewBase, mode: u32) {
    unsafe {
        (*view).flags = ((*view).flags & !0x600) | mode;
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
    fn replaces_only_the_interaction_mode_field() {
        for &(initial, mode, expected) in &[
            (0xffff_ffff, 0x200, 0xffff_fbff),
            (0xa5a5_0000, 0x400, 0xa5a5_0400),
            (0x1234_0600, 0, 0x1234_0000),
            (0x0000_0200, 0x4000, 0x0000_4000),
        ] {
            let mut storage = ViewStorage([0; 0x4c]);
            unsafe {
                (storage.0.as_mut_ptr().add(0x48) as *mut u32).write(initial);
                view_set_interaction_mode(storage.0.as_mut_ptr().cast(), mode);
            }
            assert_eq!(unsafe { flags(&storage) }, expected);
        }
    }
}
