//! Reads the context word of the selected UI element.
//!
//! - `ui_selected_element_context` — original: `FUN_08050ac8` @ 0x08050ac8
//!   (24 bytes; 4 direct `bl` call sites, all unconditional).

const SELECTED_ELEMENT_CONTEXT_OFFSET: usize = 0x3c;

type FindSelectedElement = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_find_selected_element(owner: *mut u8) -> *mut u8 {
    let call: FindSelectedElement = core::mem::transmute(0x0805_0c14usize);
    call(owner)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_find_selected_element(_owner: *mut u8) -> *mut u8 { core::ptr::null_mut() }

/// ui_selected_element_context — original: `FUN_08050ac8` @ 0x08050ac8
/// (24 bytes).
///
/// Raw ARM words `e92d4010 eb000050 e3500000 1590003c 03a00000 e8bd8010`
/// establish the exact `0x08050ac8..0x08050ae0` extent: the next separately
/// entered function begins with `stmdb sp!, {r4-r6,lr}` at 0x08050ae0. The
/// body has one plain `bl`, at 0x08050acc to 0x08050c14, and no predicated
/// `bl`; decoding the full image finds four incoming plain `bl` calls at
/// 0x0805ca80, 0x08063548, 0x0806363c, and 0x0806e668.
///
/// Algorithm: find the owner's selected UI element, return zero when no
/// element is selected, otherwise return its aligned word at +0x3c.
///
/// Deliberate deviations: 0x08050c14 has no names.yaml entry, so this port
/// retains it as the narrow fixed-address `retail_find_selected_element`
/// boundary rather than claiming an unrecovered public callee identity. The
/// target-width field is read as `u32`; the opaque owner and element layouts
/// remain unrecovered. LLVM materializes the fixed target in a literal and
/// uses `blx r1`, adding a frame-pointer prologue; match.py confirms the
/// unchanged call, NULL branch, +0x3c load, and return structure.
///
/// # Safety
/// `owner` is passed to the retail selected-element lookup. Its non-NULL
/// result must be readable through the aligned word at +0x3c.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_selected_element_context")]
pub unsafe extern "C" fn ui_selected_element_context(owner: *mut u8) -> u32 {
    ui_selected_element_context_with(owner, retail_find_selected_element)
}

unsafe fn ui_selected_element_context_with(owner: *mut u8, find_selected: FindSelectedElement) -> u32 {
    let selected = find_selected(owner);
    if selected.is_null() {
        0
    } else {
        selected.add(SELECTED_ELEMENT_CONTEXT_OFFSET).cast::<u32>().read()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static SLOT_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EXPECTED_OWNER: *mut u8 = ptr::null_mut();
    static mut SELECTED: *mut u8 = ptr::null_mut();
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn selected_element(owner: *mut u8) -> *mut u8 {
        CALLS += 1;
        assert_eq!(owner, EXPECTED_OWNER);
        SELECTED
    }

    #[test]
    fn returns_zero_when_no_element_is_selected() {
        let _guard = SLOT_TEST_LOCK.lock();
        unsafe {
            EXPECTED_OWNER = 0x1234usize as *mut u8;
            SELECTED = ptr::null_mut();
            CALLS = 0;
            assert_eq!(ui_selected_element_context_with(EXPECTED_OWNER, selected_element), 0);
            assert_eq!(CALLS, 1);
        }
    }

    #[test]
    fn returns_selected_element_context_word() {
        let _guard = SLOT_TEST_LOCK.lock();
        let mut element = [0u32; 16];
        unsafe {
            EXPECTED_OWNER = 0x5678usize as *mut u8;
            SELECTED = element.as_mut_ptr().cast::<u8>();
            SELECTED.add(SELECTED_ELEMENT_CONTEXT_OFFSET).cast::<u32>().write(0xdead_beef);
            CALLS = 0;
            assert_eq!(ui_selected_element_context_with(EXPECTED_OWNER, selected_element), 0xdead_beef);
            assert_eq!(CALLS, 1);
        }
    }
}
