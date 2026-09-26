use crate::cxx::string_object::{string_object_copy_construct, StringObject};

/// Three opaque words followed by two independently owned StringObjects.
///
/// This is 28 bytes on ARMv5TE: words +0x00..+0x08, then StringObjects at
/// +0x0c and +0x14. `repr(C)` preserves the target ordering while allowing
/// the StringObject fields to use widened host pointers.
#[repr(C)]
pub struct ThreeWordStringPair {
    pub words: [u32; 3],
    pub first: StringObject,
    pub second: StringObject,
}

/// three_word_string_pair_copy_construct — original: `FUN_083d7ee8` @
/// `0x083d7ee8` (68 bytes; true extent `0x083d7ee8..0x083d7f2c`, bounded by
/// the next `push {r2, r3, r4, r5, r6, r7, r8, lr}`). **2 inbound plain `bl`
/// call sites** (`0x083e90dc`, `0x083e964c`) and zero predicated forms,
/// verified by whole-image A32 decoding of `osos.dec`.
///
/// The raw ARM ignores its first ABI argument, returns a NULL destination
/// before reading the source, copies the three raw words, then copy-constructs
/// the StringObjects at +0x0c and +0x14 through `string_object_copy_construct`
/// @ `0x082773e0`. The second constructor is an unconditional tail branch;
/// its returned subobject address is adjusted back by eight bytes, yielding
/// the record destination.
///
/// Deliberate deviations: none. Rust expresses the two target 8-byte string
/// subobjects as fields, so host pointer widening cannot corrupt their
/// offsets.
///
/// # Safety
///
/// When `destination` is non-NULL, it must designate writable uninitialized
/// ThreeWordStringPair storage and `source` must designate a readable record.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn three_word_string_pair_copy_construct(
    _context: *mut u8,
    destination: *mut ThreeWordStringPair,
    source: *const ThreeWordStringPair,
) -> *mut ThreeWordStringPair {
    if destination.is_null() {
        return destination;
    }

    (*destination).words = (*source).words;
    string_object_copy_construct(
        core::ptr::addr_of_mut!((*destination).first),
        core::ptr::addr_of!((*source).first),
    );
    string_object_copy_construct(
        core::ptr::addr_of_mut!((*destination).second),
        core::ptr::addr_of!((*source).second),
    );
    destination
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;

    #[test]
    fn copies_words_and_constructs_both_null_strings() {
        let source = ThreeWordStringPair {
            words: [0x1122_3344, 0x5566_7788, 0x99aa_bbcc],
            first: unsafe { core::mem::zeroed() },
            second: unsafe { core::mem::zeroed() },
        };
        let mut destination = MaybeUninit::<ThreeWordStringPair>::uninit();

        unsafe {
            assert_eq!(
                three_word_string_pair_copy_construct(
                    core::ptr::null_mut(),
                    destination.as_mut_ptr(),
                    &source,
                ),
                destination.as_mut_ptr(),
            );
            let destination = destination.assume_init();
            assert_eq!(destination.words, source.words);
            assert!(!destination.first.vtable.is_null());
            assert!(destination.first.payload.is_null());
            assert!(!destination.second.vtable.is_null());
            assert!(destination.second.payload.is_null());
        }
    }

    #[test]
    fn null_destination_returns_without_reading_source() {
        unsafe {
            assert!(three_word_string_pair_copy_construct(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null(),
            )
            .is_null());
        }
    }
}
