//! The 'plst' UI-element class check.
//!
//! - `ui_element_is_plst_class` — original: `FUN_080613e0` @ 0x080613e0
//!   (40 bytes; 32 direct `bl` call sites, 0 predicated).

/// Byte offset of the class tag word the check compares
/// (`ldr r0,[r0,#0x4]`). 'plst'-class constructors store the tag here:
/// the factory at 0x0805e36c allocates the object from the class
/// descriptor at 0x0805e508 and copies descriptor word +1 (the tag) to
/// object +0x4 (`ldr r0,[0x805e50c]; str r0,[r4,#0x4]`).
const CLASS_TAG_OFFSET: usize = 0x4;

/// The 'plst' class tag: the fourcc stored as a little-endian word whose
/// value is 0x706c7374 ('p','l','s','t' MSB to LSB). Held in the
/// original's literal pool at 0x08061404.
const PLST_CLASS_TAG: u32 = 0x706c7374;

/// ui_element_is_plst_class — original: `FUN_080613e0` @ 0x080613e0
/// (40 bytes).
///
/// Source: `/home/gabe/Programming/ipod-decomp/decomp/c/029/082a6620_FUN_082a6620.c`
/// (call site); assembly decoded from `work/firmware/osos.dec` @
/// `0x080613e0..0x08061408`:
///
/// ```text
/// 080613e0  cmp r0, #0
/// 080613e4  beq 080613fc
/// 080613e8  ldr r0, [r0, #4]
/// 080613ec  ldr r1, [pc, #0x10]   ; = 0x706c7374 ('plst') @ 0x08061404
/// 080613f0  cmp r0, r1
/// 080613f4  moveq r0, #1
/// 080613f8  bxeq lr
/// 080613fc  mov r0, #0
/// 08061400  bx lr
/// 08061404  .word 0x706c7374
/// ```
///
/// Ghidra reports 36 bytes; the true extent is 40 — the trailing
/// literal-pool word at 0x08061404 belongs to this function (the next
/// function's `stmdb sp!` prologue starts at 0x08061408). Call count
/// verified by decoding every B/BL word in osos.dec: 32 unconditional
/// `bl`, zero predicated — the NULL guard inside is what every caller
/// relies on, so none gate the call themselves.
///
/// Algorithm: a NULL-guarded class-tag predicate. Returns 1 when
/// `target` is non-NULL and the word at `target + 4` equals the 'plst'
/// class tag, 0 otherwise. The tag is what the 'plst' element factory
/// (0x0805e36c) stamps at +0x4 from the class descriptor at 0x0805e508
/// (`{size 0x628, tag, vtable-ish words}`), so a 1 means "live object of
/// the 'plst' UI-element class". Callers pass the typed target of a UI
/// element reference — e.g. `ui_element_reference_is_current`
/// (0x082a6620) runs this check on `reference+0x4` before dereferencing
/// the reference's context. The sibling check 0x0806aa3c is byte-shape
/// identical with the 'tdat' tag (0x74646174) instead.
///
/// Deviations: none. The read is an aligned word load exactly like the
/// original's `ldr`; the result is a strict 0/1 like the original's
/// `moveq r0, #1` / `mov r0, #0` pair (no boolean coercion of other
/// values). Carries its own `link_section` because the 'tdat' sibling
/// differs only in the tag constant and LLVM's identical-code folding
/// must never collapse the two hook seams.
///
/// # Safety
///
/// `target` may be NULL (guarded, like the original). When non-NULL it
/// must be readable through offset +0x7.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_element_is_plst_class")]
pub unsafe extern "C" fn ui_element_is_plst_class(target: *const u8) -> u32 {
    if target.is_null() {
        return 0;
    }
    let tag = target.add(CLASS_TAG_OFFSET).cast::<u32>().read();
    u32::from(tag == PLST_CLASS_TAG)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// A minimal stand-in object: word +0x0 (vtable pointer in the real
    /// class, never read by the check) and the tag word at +0x4.
    fn object_with_tag(tag: u32) -> [u32; 2] {
        [0x080d9fb0, tag]
    }

    #[test]
    fn null_target_returns_zero() {
        assert_eq!(unsafe { ui_element_is_plst_class(core::ptr::null()) }, 0);
    }

    #[test]
    fn plst_tagged_object_returns_one() {
        let object = object_with_tag(PLST_CLASS_TAG);
        assert_eq!(unsafe { ui_element_is_plst_class(object.as_ptr().cast()) }, 1);
    }

    #[test]
    fn other_tags_return_zero() {
        // The sibling 'tdat' class tag, a zeroed tag word, and the tag
        // with only the low byte flipped all fail the check.
        for tag in [0x74646174u32, 0, PLST_CLASS_TAG ^ 1, !PLST_CLASS_TAG] {
            let object = object_with_tag(tag);
            assert_eq!(
                unsafe { ui_element_is_plst_class(object.as_ptr().cast()) },
                0,
                "tag {tag:#010x} must not match 'plst'"
            );
        }
    }

    #[test]
    fn first_word_is_irrelevant() {
        // The original reads only +0x4; garbage in +0x0 must not matter.
        let object = [0xdeadbeefu32, PLST_CLASS_TAG];
        assert_eq!(unsafe { ui_element_is_plst_class(object.as_ptr().cast()) }, 1);
    }

    #[test]
    fn result_is_strict_zero_or_one() {
        let object = object_with_tag(PLST_CLASS_TAG);
        let yes = unsafe { ui_element_is_plst_class(object.as_ptr().cast()) };
        let no = unsafe { ui_element_is_plst_class(core::ptr::null()) };
        assert_eq!((yes, no), (1, 0));
    }
}
