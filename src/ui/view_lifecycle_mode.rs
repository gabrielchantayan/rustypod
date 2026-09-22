//! Setter for the view lifecycle-mode bits.

use super::view_base::ViewBase;

/// view_set_lifecycle_mode — original: `FUN_0826db10` @ `0x0826db10` (20 bytes).
///
/// Raw ARM: `ldr r2,[r0,#0x48]; bic r2,r2,#0x6000; orr r1,r2,r1;
/// str r1,[r0,#0x48]; bx lr`. The next real function begins at
/// `0x0826db24`; raw `osos.dec` decoding finds three unconditional `bl` callers
/// and no predicated `bl` callers. Clears the view's two-bit lifecycle-mode
/// field (bits 13–14), then ORs in the caller-provided mode word. Deliberate
/// deviations: none.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn view_set_lifecycle_mode(view: *mut ViewBase, mode: u32) {
    unsafe {
        (*view).flags = ((*view).flags & !0x6000) | mode;
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
    fn replaces_only_the_lifecycle_mode_field() {
        for &(initial, mode, expected) in &[
            (0xffff_ffff, 0x2000, 0xffff_bfff),
            (0xa5a5_0000, 0x4000, 0xa5a5_4000),
            (0x1234_6000, 0, 0x1234_0000),
            (0x0000_2000, 0x0001, 0x0000_0001),
        ] {
            let mut storage = ViewStorage([0; 0x4c]);
            unsafe {
                (storage.0.as_mut_ptr().add(0x48) as *mut u32).write(initial);
                view_set_lifecycle_mode(storage.0.as_mut_ptr().cast(), mode);
            }
            assert_eq!(unsafe { flags(&storage) }, expected);
        }
    }
}
