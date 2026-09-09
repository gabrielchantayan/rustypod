//! The 'liti' ImageLibrary-database class check.
//!
//! - `image_library_is_liti_class` — original: `FUN_08057c2c` @ 0x08057c2c
//!   (40 bytes; 15 direct `bl` call sites, 0 predicated).

/// The 'liti' class tag: the fourcc stored as a little-endian word whose
/// value is 0x6974696c ('i','t','i','l' MSB to LSB; in-memory bytes
/// "liti"). Held in the original's literal pool at 0x08057c50. The only
/// stamper is the ImageLibrary database constructor at 0x0805e148, which
/// allocates 0x9e0 bytes via calloc_tag4 (0x0805d1dc) and stores the tag
/// at object +0x0 (`ldr r0,=0x6974696c; str r0,[r4]`); its grandcaller
/// 0x08058230 builds the object over the "iPod_Control/Artwork" and
/// "ArtworkDB" paths, so a 'liti'-tagged object is the ImageLibrary
/// (artwork) database.
const LITI_CLASS_TAG: u32 = 0x6974696c;

/// image_library_is_liti_class — original: `FUN_08057c2c` @ 0x08057c2c
/// (40 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/004/08057c2c_FUN_08057c2c.c`;
/// assembly decoded from `work/firmware/osos.dec` @ `0x08057c2c..0x08057c54`:
///
/// ```text
/// 08057c2c  cmp r0, #0
/// 08057c30  beq 08057c48
/// 08057c34  ldr r0, [r0]
/// 08057c38  ldr r1, [pc, #0x10]   ; = 0x6974696c ('liti') @ 0x08057c50
/// 08057c3c  cmp r0, r1
/// 08057c40  moveq r0, #1
/// 08057c44  bxeq lr
/// 08057c48  mov r0, #0
/// 08057c4c  bx lr
/// 08057c50  .word 0x6974696c
/// ```
///
/// Ghidra reports 36 bytes; the true extent is 40 — the trailing
/// literal-pool word at 0x08057c50 belongs to this function (the next
/// function's `push {r3, lr}` prologue starts at 0x08057c54). Call count
/// verified by decoding every B/BL word in osos.dec: 15 unconditional
/// `bl`, zero predicated — the NULL guard inside is what every caller
/// relies on, so none gate the call themselves.
///
/// Algorithm: a NULL-guarded class-tag predicate. Returns 1 when
/// `target` is non-NULL and the word at `target + 0` equals the 'liti'
/// class tag, 0 otherwise. Callers pass either the object directly
/// (0x08063e9c opens the database after the check; the 0x0805df84/
/// 0x0805dfec/0x0805e06c family inserts into its lists) or a pointer
/// pulled from another object's field — the wrapper 0x08057bb4 checks
/// `*(obj + 4)`, 0x08057bdc checks `*(obj + 8)`, 0x081070a0 checks
/// `*(*ref + 4)`. Same predicate shape as the 'plst'/'crts'/'tdat'
/// checks; this one reads the tag at +0x0 rather than +0x4.
///
/// Deviations: none. The read is an aligned word load exactly like the
/// original's `ldr`; the result is a strict 0/1 like the original's
/// `moveq r0, #1` / `mov r0, #0` pair (no boolean coercion of other
/// values). Carries its own `link_section` because sibling tag checks
/// differ only in the tag constant/offset and LLVM's identical-code
/// folding must never collapse hook seams.
///
/// # Safety
///
/// `target` may be NULL (guarded, like the original). When non-NULL it
/// must be readable through offset +0x3.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.image_library_is_liti_class")]
pub unsafe extern "C" fn image_library_is_liti_class(target: *const u8) -> u32 {
    if target.is_null() {
        return 0;
    }
    let tag = target.cast::<u32>().read();
    u32::from(tag == LITI_CLASS_TAG)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// A minimal stand-in object: the tag word at +0x0 and one trailing
    /// word the check must never read.
    fn object_with_tag(tag: u32) -> [u32; 2] {
        [tag, 0xdeadbeef]
    }

    #[test]
    fn null_target_returns_zero() {
        assert_eq!(unsafe { image_library_is_liti_class(core::ptr::null()) }, 0);
    }

    #[test]
    fn liti_tagged_object_returns_one() {
        let object = object_with_tag(LITI_CLASS_TAG);
        assert_eq!(unsafe { image_library_is_liti_class(object.as_ptr().cast()) }, 1);
    }

    #[test]
    fn other_tags_return_zero() {
        // The 'plst' class tag, a zeroed tag word, and the tag with only
        // the low byte flipped all fail the check.
        for tag in [0x706c7374u32, 0, LITI_CLASS_TAG ^ 1, !LITI_CLASS_TAG] {
            let object = object_with_tag(tag);
            assert_eq!(
                unsafe { image_library_is_liti_class(object.as_ptr().cast()) },
                0,
                "tag {tag:#010x} must not match 'liti'"
            );
        }
    }

    #[test]
    fn trailing_word_is_irrelevant() {
        // The original reads only +0x0; garbage after it must not matter.
        let object = [LITI_CLASS_TAG, 0x12345678u32];
        assert_eq!(unsafe { image_library_is_liti_class(object.as_ptr().cast()) }, 1);
    }

    #[test]
    fn result_is_strict_zero_or_one() {
        let object = object_with_tag(LITI_CLASS_TAG);
        let yes = unsafe { image_library_is_liti_class(object.as_ptr().cast()) };
        let no = unsafe { image_library_is_liti_class(core::ptr::null()) };
        assert_eq!((yes, no), (1, 0));
    }
}
