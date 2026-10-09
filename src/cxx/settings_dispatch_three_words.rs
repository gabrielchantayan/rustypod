//! Settings three-word virtual dispatch — FUN_080e2f28 @ 0x080e2f28.
//! True size: 52 bytes; next function starts at 0x080e2f5c. Raw ARM:
//! two plain outgoing BLs to settings_get, zero predicated BLs, then BX ip.
//! Whole-image aligned BL scan: one plain inbound BL at 0x08393620 and
//! one BLNE at 0x0839370c. Acquire settings twice, discard the first result,
//! and dispatch the second object's vtable word 4 with the three input words.
//! Preserve the virtual return word (Ghidra's void signature loses it).
//! Deliberate deviations: native-width host vtable entries retain target word
//! indices; LLVM need not tail-call. The existing settings_get constructor
//! prerequisite applies: its default zeroed object is not hook-ready.
//! No identity or argument interpretation is asserted for the virtual method.

use core::mem::transmute;

#[inline(always)]
unsafe fn dispatch(mut get: impl FnMut() -> *mut u8, first: u32, second: u32, third: u32) -> u32 {
    let _ = get();
    let settings = get();
    let vtable = unsafe { *(settings as *const *const usize) };
    let method: unsafe extern "C" fn(*mut u8, u32, u32, u32) -> u32 =
        unsafe { transmute(*vtable.add(4)) };
    unsafe { method(settings, first, second, third) }
}

/// # Safety
/// The second settings lookup must return a valid object whose vtable word 4
/// accepts these three words. Its method's own argument requirements apply.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn settings_dispatch_three_words(first: u32, second: u32, third: u32) -> u32 {
    unsafe { dispatch(|| crate::cxx::settings::settings_get(), first, second, third) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Store { vtable: *const usize, words: [u32; 3], calls: u32 }

    unsafe extern "C" fn update(store: *mut u8, first: u32, second: u32, third: u32) -> u32 {
        let store = unsafe { &mut *store.cast::<Store>() };
        store.words = [first, second, third];
        store.calls += 1;
        0x80000000 | store.calls
    }

    #[test]
    fn reacquires_after_null_or_different_first_result_and_preserves_words() {
        let mut table = [0usize; 5];
        table[4] = update as *const () as usize;
        let mut ignored = Store { vtable: core::ptr::null(), words: [7; 3], calls: 0 };
        let mut selected = Store { vtable: table.as_ptr(), words: [0; 3], calls: 0 };
        for (index, words) in [[0, 0, 0], [u32::MAX, 0x80000000, 1], [1, 2, 3]].into_iter().enumerate() {
            let mut lookups = 0;
            let result = unsafe { dispatch(|| {
                lookups += 1;
                if lookups == 1 {
                    if index == 0 { core::ptr::null_mut() } else { (&mut ignored as *mut Store).cast() }
                } else { (&mut selected as *mut Store).cast() }
            }, words[0], words[1], words[2]) };
            assert_eq!(lookups, 2);
            assert_eq!(selected.words, words);
            assert_eq!(selected.calls, index as u32 + 1);
            assert_eq!(result, 0x80000000 | selected.calls);
            assert_eq!(ignored.words, [7; 3]);
            assert_eq!(ignored.calls, 0);
        }
    }
}
