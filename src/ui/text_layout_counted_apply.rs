//! `text_layout_counted_apply` — original: `FUN_082631a4` @ `0x082631a4`
//! (88 bytes, `0x082631a4..0x082631f8`; all code). The separately linked next
//! entry begins with `push {r4, r5, r6, r7, r8, r9, sl, fp, lr}` at
//! `0x082631fc`.
//!
//! A whole-image ARM B/BL-immediate decode finds **four direct `bl` call
//! sites**: `0x081a14cc`, `0x081b31f0`, `0x081eaa44`, and `0x08290b68`; all
//! are unconditional plain `bl`, with no predicated forms. The wrapper counts
//! permissive UTF-8 codepoints in its NUL-terminated text, truncates the result
//! to 16 bits, and forwards that count plus its seven original arguments to the
//! helper at `0x08262d84`, inserting zero for the helper's sixth argument.
//!
//! Deliberate deviation: `0x08262d84` has no established semantic identity or
//! Rust port. Target builds call that exact load address; host tests install a
//! recording seam instead. The wrapper itself has no NULL or bounds guards,
//! matching the retail body and its UTF-8 counter.

use crate::util::utf8_codepoint_count_permissive::utf8_codepoint_count_permissive;

/// ABI of the unported helper at `0x08262d84`.
pub type CountedTextLayoutApply = unsafe extern "C" fn(
    *mut u8,
    *const u8,
    u32,
    *const u8,
    u32,
    u32,
    u32,
    u32,
    u32,
);

#[cfg(any(test, not(target_arch = "arm")))]
unsafe extern "C" fn missing_counted_text_layout_apply(
    _target: *mut u8,
    _text: *const u8,
    _codepoint_count: u32,
    _layout: *const u8,
    _arg4: u32,
    _zero: u32,
    _arg5: u32,
    _arg6: u32,
    _arg7: u32,
) {
    panic!("text layout helper 0x08262d84 is unavailable on the host")
}

/// Host seam for the unported text-layout helper at `0x08262d84`.
#[cfg(any(test, not(target_arch = "arm")))]
pub static mut TEXT_LAYOUT_COUNTED_APPLY: CountedTextLayoutApply = missing_counted_text_layout_apply;

#[inline(always)]
unsafe fn counted_text_layout_apply() -> CountedTextLayoutApply {
    #[cfg(all(target_arch = "arm", not(test)))]
    {
        unsafe { core::mem::transmute(0x0826_2d84usize) }
    }
    #[cfg(any(test, not(target_arch = "arm")))]
    {
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(TEXT_LAYOUT_COUNTED_APPLY)) }
    }
}

/// Counts `text`'s permissive UTF-8 codepoints and passes it to the layout helper.
///
/// # Safety
///
/// `text` must meet [`utf8_codepoint_count_permissive`]'s C-string contract.
/// All remaining arguments must satisfy the unported helper's ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn text_layout_counted_apply(
    target: *mut u8,
    text: *const u8,
    layout: *const u8,
    arg4: u32,
    arg5: u32,
    arg6: u32,
    arg7: u32,
) {
    let codepoint_count = unsafe { utf8_codepoint_count_permissive(text) } & 0xffff;
    unsafe { counted_text_layout_apply()(target, text, codepoint_count, layout, arg4, 0, arg5, arg6, arg7) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALL: (*mut u8, *const u8, u32, *const u8, u32, u32, u32, u32, u32) =
        (core::ptr::null_mut(), core::ptr::null(), 0, core::ptr::null(), 0, 0, 0, 0, 0);

    unsafe extern "C" fn record_apply(
        target: *mut u8,
        text: *const u8,
        codepoint_count: u32,
        layout: *const u8,
        arg4: u32,
        zero: u32,
        arg5: u32,
        arg6: u32,
        arg7: u32,
    ) {
        unsafe { CALL = (target, text, codepoint_count, layout, arg4, zero, arg5, arg6, arg7) };
    }

    #[test]
    fn counts_permissive_utf8_and_forwards_all_arguments() {
        let _lock = TEST_LOCK.lock();
        let previous = unsafe { TEXT_LAYOUT_COUNTED_APPLY };
        unsafe { TEXT_LAYOUT_COUNTED_APPLY = record_apply };

        let mut target = [0u8; 1];
        let layout = [0u8; 1];
        let text = [b'A', 0xc2, 0x00, 0xe2, b'X', b'Y', 0];
        unsafe {
            text_layout_counted_apply(
                target.as_mut_ptr(),
                text.as_ptr(),
                layout.as_ptr(),
                0x11,
                0x22,
                0x33,
                0x44,
            );
            assert_eq!(CALL, (target.as_mut_ptr(), text.as_ptr(), 3, layout.as_ptr(), 0x11, 0, 0x22, 0x33, 0x44));
            TEXT_LAYOUT_COUNTED_APPLY = previous;
        }
    }
}
