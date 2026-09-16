//! `object_type_tag_is_recognized` — original: `FUN_08382c18` @ `0x08382c18`.
//!
//! True extent: 64 bytes (`0x08382c18..0x08382c58`): 13 ARM instructions end
//! at `bx lr` (`0x08382c4c`), followed by its three literal-pool words; the
//! next distinct function starts at `0x08382c58`. Raw `osos.dec` decoding
//! finds four incoming plain `bl` calls (`0x0838f77c`, `0x0839021c`,
//! `0x08390260`, and `0x083902c8`) and no incoming predicated `bl` calls.
//! The body has no `bl` instructions.
//!
//! A null object is rejected. Otherwise, its aligned word at `+0x40` is
//! accepted only when it equals one of the three literal type tags. Deliberate
//! deviations: the unrecovered tag meanings remain numeric constants.

const TYPE_TAG_OFFSET: usize = 0x40;
const RECOGNIZED_TYPE_TAGS: [u32; 3] = [0x4b77_1290, 0xa029_a697, 0xf03b_7906];

/// Reports whether an object carries one of the retailOS-recognized type tags.
///
/// # Safety
///
/// When `object` is non-null, it must be valid for an aligned `u32` read at
/// offset `+0x40`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_type_tag_is_recognized(object: *const u8) -> u32 {
    if object.is_null() {
        return 0;
    }

    let type_tag = (object.add(TYPE_TAG_OFFSET) as *const u32).read();
    RECOGNIZED_TYPE_TAGS.contains(&type_tag) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_object_is_rejected() {
        unsafe {
            assert_eq!(object_type_tag_is_recognized(core::ptr::null()), 0);
        }
    }

    #[test]
    fn every_retail_type_tag_is_accepted() {
        for type_tag in RECOGNIZED_TYPE_TAGS {
            let mut object = [0u32; 17];
            object[TYPE_TAG_OFFSET / 4] = type_tag;
            unsafe {
                assert_eq!(object_type_tag_is_recognized(object.as_ptr().cast()), 1);
            }
        }
    }

    #[test]
    fn unrecognized_type_tag_is_rejected() {
        let mut object = [0u32; 17];
        object[TYPE_TAG_OFFSET / 4] = 0xfeed_face;
        unsafe {
            assert_eq!(object_type_tag_is_recognized(object.as_ptr().cast()), 0);
        }
    }
}
