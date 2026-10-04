//! Conditional text-key selection update — `FUN_081dccc0` @ `0x081dccc0`.
//! True extent: 56 bytes, [0x081dccc0, 0x081dccf8), ending before the next
//! push. Raw words verify two incoming plain BLs (0x081dc6bc, 0x081dcaf4),
//! one outgoing plain BL (0x081dccd8 -> 0x082a6790), zero predicated BLs,
//! and a conditional tail branch to 0x08140370.
//!
//! If the caller's text predicate is nonzero, look up the key using the
//! source at +0x70. A nonzero result replaces the selection word at +0x2c
//! of the current destination at +0x74; a miss preserves the previous word.
//! The destination is loaded after lookup. The retail lookup passes a
//! four-byte key to source+0x4c's virtual slot +0x44 and returns the found
//! entry's first word, or zero. It remains an unported fixed-address seam.
//! Deviations: inline the verified two-instruction setter at 0x08140370;
//! repr(C) pointer fields use native width on hosts, ARM width on device.

/// Owner prefix through the lookup source and destination pointers.
#[repr(C)]
pub struct TextKeySelectionOwner {
    pub opaque_words: [u32; 28],
    pub source: *mut u8,
    pub destination: *mut TextKeySelection,
}

/// Destination prefix through the selected value at target offset +0x2c.
#[repr(C)]
pub struct TextKeySelection {
    pub opaque_words: [u32; 11],
    pub value: u32,
}

type TextKeyLookup = unsafe extern "C" fn(*mut u8, u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_text_key_lookup(_source: *mut u8, _key: u32) -> u32 {
    panic!("install text-key lookup host seam")
}

#[cfg(not(target_os = "none"))]
pub static mut TEXT_KEY_SELECTION_LOOKUP: TextKeyLookup = missing_text_key_lookup;

#[inline(always)]
unsafe fn lookup_text_key(source: *mut u8, key: u32) -> u32 {
    #[cfg(target_os = "none")]
    { core::mem::transmute::<usize, TextKeyLookup>(0x082a_6790)(source, key) }
    #[cfg(not(target_os = "none"))]
    { core::ptr::addr_of!(TEXT_KEY_SELECTION_LOOKUP).read()(source, key) }
}

/// # Safety
/// For nonzero `has_text`, `owner` and its source must satisfy the retail
/// lookup contract. If lookup succeeds, the current destination must be
/// writable through its value field. A zero predicate dereferences nothing.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn text_key_selection_update(
    owner: *mut TextKeySelectionOwner, has_text: u32, key: u32,
) {
    if has_text == 0 {
        return;
    }
    let value = lookup_text_key((*owner).source, key);
    if value != 0 {
        (*(*owner).destination).value = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    #[repr(C)]
    struct LookupFixture {
        owner: *mut TextKeySelectionOwner,
        replacement: *mut TextKeySelection,
    }

    unsafe extern "C" fn lookup(source: *mut u8, key: u32) -> u32 {
        let fixture = &mut *source.cast::<LookupFixture>();
        if key == 0 {
            return 0;
        }
        (*fixture.owner).destination = fixture.replacement;
        // Nonzero boundary values are valid results, not booleanized.
        key
    }

    #[test]
    fn absent_text_does_not_access_owner() {
        unsafe { text_key_selection_update(ptr::null_mut(), 0, u32::MAX); }
    }

    #[test]
    fn miss_preserves_selection_and_success_uses_post_lookup_destination() {
        let _guard = LOCK.lock();
        let mut original = TextKeySelection { opaque_words: [0xaaaa_aaaa; 11], value: 73 };
        let mut replacement = TextKeySelection { opaque_words: [0xbbbb_bbbb; 11], value: 91 };
        let mut owner = TextKeySelectionOwner {
            opaque_words: [0xcccc_cccc; 28], source: ptr::null_mut(), destination: &mut original,
        };
        let mut fixture = LookupFixture { owner: &mut owner, replacement: &mut replacement };
        owner.source = ptr::addr_of_mut!(fixture).cast();
        unsafe {
            TEXT_KEY_SELECTION_LOOKUP = lookup;
            text_key_selection_update(&mut owner, 1, 0);
            assert_eq!(original.value, 73);
            assert_eq!(replacement.value, 91);
            // On a miss even a NULL destination must not be touched.
            owner.destination = ptr::null_mut();
            text_key_selection_update(&mut owner, u32::MAX, 0);
            for key in [1, 0x8000_0000, u32::MAX] {
                owner.destination = &mut original;
                text_key_selection_update(&mut owner, 0x8000_0000, key);
                assert_eq!(replacement.value, key);
                assert_eq!(original.value, 73);
            }
            TEXT_KEY_SELECTION_LOOKUP = missing_text_key_lookup;
        }
        assert_eq!(original.opaque_words, [0xaaaa_aaaa; 11]);
        assert_eq!(replacement.opaque_words, [0xbbbb_bbbb; 11]);
        assert_eq!(owner.opaque_words, [0xcccc_cccc; 28]);
    }
}
