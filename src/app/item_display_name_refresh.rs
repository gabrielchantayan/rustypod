//! Item display-name refresh adapter — `FUN_081242b0` @ `0x081242b0`.
//!
//! True extent [0x081242b0, 0x081242b8), 8 bytes. The next function begins
//! with push {r4,r5,r6,lr}. Whole-image A32 scan finds two incoming plain
//! BLs (0x0808e544, 0x081b2250), zero predicated BLs; zero outgoing BLs.
//! Words e280202c ea05d1b2 compute r2 = r0 + 0x2c and tail B to 0x08298984.
//! That shared routine clears the embedded string via slot +0xc, generates
//! it for modes 0/1, falls back when empty, and substitutes localized text
//! for special placeholder names. Preserve the full-width mode unchanged.
//! No target behavioral deviations: the unported shared routine remains
//! at its raw-verified retail address. Host execution requires an installed
//! seam; it does not pretend to implement firmware string/localization work.

pub type DisplayNameRefresh = unsafe extern "C" fn(*mut u8, u32, *mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_refresh(_item: *mut u8, _mode: u32, _name: *mut u8) {
    panic!("install item display-name refresh host seam for retail 0x08298984")
}

#[cfg(not(target_os = "none"))]
pub static mut ITEM_DISPLAY_NAME_REFRESH: DisplayNameRefresh = missing_refresh;

/// # Safety
/// `item` must be a live retail object with an embedded string at byte +0x2c,
/// valid for the shared refresh routine. NULL is not a supported object.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn item_display_name_refresh(item: *mut u8, mode: u32) {
    #[cfg(target_os = "none")]
    let refresh: DisplayNameRefresh = core::mem::transmute(0x0829_8984usize);
    #[cfg(not(target_os = "none"))]
    let refresh = core::ptr::addr_of!(ITEM_DISPLAY_NAME_REFRESH).read_volatile();
    refresh(item, mode, item.wrapping_add(0x2c));
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    // A host string fixture using the target's four-byte object fields.
    // Exercise the consumer-visible name update, leaving adjacent fields intact.
    unsafe extern "C" fn regenerate(_item: *mut u8, mode: u32, name: *mut u8) {
        let value = match mode { 0 => 0x6d57, 1 => 0x6d62, _ => 0 };
        name.add(4).cast::<u32>().write(value);
    }

    struct Restore(DisplayNameRefresh);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { ITEM_DISPLAY_NAME_REFRESH = self.0; }
        }
    }

    #[test]
    fn name_updates_preserve_surrounding_target_words_for_all_mode_classes() {
        let _lock = LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        unsafe {
            let _restore = Restore(ITEM_DISPLAY_NAME_REFRESH);
            ITEM_DISPLAY_NAME_REFRESH = regenerate;
            for (mode, expected_name) in [(0, 0x6d57), (1, 0x6d62), (2, 0), (0x100, 0), (u32::MAX, 0)] {
                let mut item = [0xa5a5a5a5u32; 32];
                let mut expected = item;
                expected[0x30 / 4] = expected_name;
                item_display_name_refresh(item.as_mut_ptr().cast(), mode);
                assert_eq!(item, expected, "mode {mode:#x}");
            }
        }
    }
}
