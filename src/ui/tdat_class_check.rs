//! The 'tdat' UI-element class check.
//!
//! - `ui_element_is_tdat_class` — original: `FUN_0806aa3c` @ 0x0806aa3c
//!   (40 bytes; 31 direct `bl` call sites, 0 predicated).

/// Byte offset of the class tag word the check compares
/// (`ldr r0,[r0,#0x4]`). 'tdat'-class constructors store the tag here:
/// the factory at 0x08047bfc allocates 0x948 bytes and stores the tag
/// (literal pool word @ 0x08047cbc) to object +0x4 via
/// `stmib r4, {r0, r6}`.
const CLASS_TAG_OFFSET: usize = 0x4;

/// The 'tdat' class tag: the fourcc stored as a little-endian word whose
/// value is 0x74646174 ('t','d','a','t' MSB to LSB). Held in the
/// original's literal pool at 0x0806aa60.
const TDAT_CLASS_TAG: u32 = 0x74646174;

/// ui_element_is_tdat_class — original: `FUN_0806aa3c` @ 0x0806aa3c
/// (40 bytes).
///
/// Assembly decoded from `work/firmware/osos.dec` @
/// `0x0806aa3c..0x0806aa64`:
///
/// ```text
/// 0806aa3c  cmp r0, #0
/// 0806aa40  beq 0806aa58
/// 0806aa44  ldr r0, [r0, #4]
/// 0806aa48  ldr r1, [pc, #0x10]   ; = 0x74646174 ('tdat') @ 0x0806aa60
/// 0806aa4c  cmp r0, r1
/// 0806aa50  moveq r0, #1
/// 0806aa54  bxeq lr
/// 0806aa58  mov r0, #0
/// 0806aa5c  bx lr
/// 0806aa60  .word 0x74646174
/// ```
///
/// Ghidra reports 36 bytes; the true extent is 40 — the trailing
/// literal-pool word at 0x0806aa60 belongs to this function (the next
/// function's `push {r4, lr}` prologue starts at 0x0806aa64). Call count
/// verified by decoding every B/BL word in osos.dec: 31 unconditional
/// `bl`, zero predicated — the NULL guard inside is what every caller
/// relies on, so none gate the call themselves.
///
/// Algorithm: a NULL-guarded class-tag predicate. Returns 1 when
/// `target` is non-NULL and the word at `target + 4` equals the 'tdat'
/// class tag, 0 otherwise. The tag is what the 'tdat' element factory
/// (0x08047bfc) stamps at +0x4 of the 0x948-byte object it allocates,
/// so a 1 means "live object of the 'tdat' UI-element class". Callers
/// immediately dereference class fields past the check — e.g. the
/// sibling wrapper at 0x0806aa64 reads a halfword at +0x40, and
/// 0x0806aaac bumps the counter at +0x40 — so the predicate gates real
/// object access. The sibling check 0x080613e0 is byte-shape identical
/// with the 'plst' tag (0x706c7374) instead.
///
/// Deviations: none. The read is an aligned word load exactly like the
/// original's `ldr`; the result is a strict 0/1 like the original's
/// `moveq r0, #1` / `mov r0, #0` pair (no boolean coercion of other
/// values). Carries its own `link_section` because the 'plst' sibling
/// differs only in the tag constant and LLVM's identical-code folding
/// must never collapse the two hook seams.
///
/// # Safety
///
/// `target` may be NULL (guarded, like the original). When non-NULL it
/// must be readable through offset +0x7.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_element_is_tdat_class")]
pub unsafe extern "C" fn ui_element_is_tdat_class(target: *const u8) -> u32 {
    if target.is_null() {
        return 0;
    }
    let tag = target.add(CLASS_TAG_OFFSET).cast::<u32>().read();
    u32::from(tag == TDAT_CLASS_TAG)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    /// A minimal stand-in object: word +0x0 (vtable pointer in the real
    /// class, never read by the check) and the tag word at +0x4.
    fn object_with_tag(tag: u32) -> [u32; 2] {
        [0x080dadc8, tag]
    }

    #[test]
    fn null_target_returns_zero() {
        assert_eq!(unsafe { ui_element_is_tdat_class(core::ptr::null()) }, 0);
    }

    #[test]
    fn tdat_tagged_object_returns_one() {
        let object = object_with_tag(TDAT_CLASS_TAG);
        assert_eq!(unsafe { ui_element_is_tdat_class(object.as_ptr().cast()) }, 1);
    }

    #[test]
    fn other_tags_return_zero() {
        // The sibling 'plst' class tag, a zeroed tag word, and the tag
        // with only the low byte flipped all fail the check.
        for tag in [0x706c7374u32, 0, TDAT_CLASS_TAG ^ 1, !TDAT_CLASS_TAG] {
            let object = object_with_tag(tag);
            assert_eq!(
                unsafe { ui_element_is_tdat_class(object.as_ptr().cast()) },
                0,
                "tag {tag:#010x} must not match 'tdat'"
            );
        }
    }

    #[test]
    fn first_word_is_irrelevant() {
        // The original reads only +0x4; garbage in +0x0 must not matter.
        let object = [0xdeadbeefu32, TDAT_CLASS_TAG];
        assert_eq!(unsafe { ui_element_is_tdat_class(object.as_ptr().cast()) }, 1);
    }

    #[test]
    fn result_is_strict_zero_or_one() {
        let object = object_with_tag(TDAT_CLASS_TAG);
        let yes = unsafe { ui_element_is_tdat_class(object.as_ptr().cast()) };
        let no = unsafe { ui_element_is_tdat_class(core::ptr::null()) };
        assert_eq!((yes, no), (1, 0));
    }
}
