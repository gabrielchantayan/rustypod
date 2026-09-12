//! Querying a UI element's shown state from its flag word.
//!
//! - `ui_element_is_fully_shown` — original: `FUN_082a26a8` @ 0x082a26a8
//!   (32 bytes; 8 direct, unconditional `bl` call sites, no data-word
//!   references — verified by decoding every B/BL word and scanning every
//!   word of osos.dec, so the helper is never dispatched virtually).
//! - `ui_element_is_shown` — original: `FUN_082a26c8` @ 0x082a26c8
//!   (24 bytes; 32 direct `bl` call sites, none predicated, no data-word
//!   references — verified by decoding every B/BL word and scanning every
//!   word of osos.dec, so the helper is never dispatched virtually).
//!
//! Bits 11–12 of the element flag word at +0x48 form a two-bit shown-state
//! field. The setter at 0x0811e294 assigns the field with
//! `bic 0x1800; orr 0x800` (value 1 of 3) when its state argument is
//! non-zero and then notifies vtable +0xa8; the sibling setter at
//! 0x0811e2f8 does the same for the two-bit field at bits 9–10 (0x600).
//! Value 1 (0x800) is the state in which an element participates in redraw:
//! `ui_element_invalidate`'s region form (0x0826ec14) gates dirty-rect
//! accumulation on this exact test, and 0x0816e5bc early-outs when it
//! fails. The compound sibling query at 0x082a26a8 additionally requires
//! bits 9–10 == 0x200.

/// Byte offset of a UI element's flag word (`ldr r0,[r0,#0x48]`). The
/// same `flags_48` word [`crate::ui::invalidate`] documents.
const FLAGS_OFFSET: usize = 0x48;

/// Mask selecting the two-bit shown-state field, bits 11–12
/// (`and r0, r0, #0x1800`).
const SHOWN_STATE_MASK: u32 = 0x1800;

/// Field value meaning "shown" (`cmp r0, #0x800`).
const SHOWN_STATE_SHOWN: u32 = 0x800;

/// Mask selecting the sibling two-bit state field, bits 9–10
/// (`and r1, r0, #0x600`).
const AUXILIARY_STATE_MASK: u32 = 0x600;

/// Sibling state value required for an element to be fully shown
/// (`cmp r1, #0x200`).
const AUXILIARY_STATE_SHOWN: u32 = 0x200;

/// ui_element_is_shown — original: `FUN_082a26c8` @ 0x082a26c8
/// (24 bytes, extent binary-verified: the sibling flag query opens at
/// 0x082a26a8 before it and the next function's `push {r4, lr}` opens at
/// 0x082a26e0 right after its `bx lr`).
///
/// ```text
/// 082a26c8  ldr    r0, [r0, #0x48]   @ flags_48
/// 082a26cc  and    r0, r0, #0x1800   @ shown-state field
/// 082a26d0  cmp    r0, #0x800
/// 082a26d4  movne  r0, #0
/// 082a26d8  moveq  r0, #1
/// 082a26dc  bx     lr
/// ```
///
/// Returns 1 when the shown-state field (bits 11–12 of `flags_48`) holds
/// the value "shown" (0x800), 0 for the other three states. A pure leaf
/// with no NULL guard: all 32 call sites are unconditional `bl`, and
/// callers pass a live element pointer (several — e.g. 0x0810aedc,
/// 0x0811e294 — dereference `element` before or right after the call).
///
/// The field is a plain word four-byte aligned in the 32-bit retailOS
/// layout, so both device and host forms use one aligned `ldr` — no
/// host/device split is needed (unlike the pointer-sized fields in
/// [`crate::ui::render_context`]).
///
/// # Deliberate deviations
///
/// None. The port is statement-for-statement the original's
/// `(flags_48 & 0x1800) == 0x800`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_is_shown(element: *const u8) -> u32 {
    let flags = element.add(FLAGS_OFFSET).cast::<u32>().read();
    (flags & SHOWN_STATE_MASK == SHOWN_STATE_SHOWN) as u32
}

/// ui_element_is_fully_shown — original: `FUN_082a26a8` @ 0x082a26a8
/// (32 bytes, extent binary-verified: this leaf begins immediately after
/// the preceding function's `pop {r4, pc}` at 0x082a26a4 and the distinct
/// sibling [`ui_element_is_shown`] begins at 0x082a26c8).
///
/// ```text
/// 082a26a8  ldr    r0, [r0, #0x48]   @ flags_48
/// 082a26ac  and    r1, r0, #0x600    @ sibling state field
/// 082a26b0  cmp    r1, #0x200
/// 082a26b4  andeq  r0, r0, #0x1800   @ shown-state field
/// 082a26b8  cmpeq  r0, #0x800
/// 082a26bc  movne  r0, #0
/// 082a26c0  moveq  r0, #1
/// 082a26c4  bx     lr
/// ```
///
/// Returns 1 only if both two-bit fields in `flags_48` hold their shown
/// values: bits 9–10 are `0x200` and bits 11–12 are `0x800`; otherwise
/// returns 0. It is a pure, unguarded leaf. Decoding every ARM B/BL word in
/// osos.dec finds exactly eight direct callers — all unconditional plain
/// `bl` at 0x081575bc, 0x08158704, 0x0815c1e4, 0x0815c4f0, 0x081b83ec,
/// 0x081b88c8, 0x0829bafc, and 0x082a24cc — and no data word contains its
/// address, so it is not virtually dispatched.
///
/// # Algorithm
///
/// Load the aligned flag word at `element + 0x48`, then compare its two
/// adjacent two-bit state fields with their shown encodings.
///
/// # Deliberate deviations
///
/// None. This is the original's predicated
/// `(flags_48 & 0x600) == 0x200 && (flags_48 & 0x1800) == 0x800`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_element_is_fully_shown(element: *const u8) -> u32 {
    let flags = element.add(FLAGS_OFFSET).cast::<u32>().read();
    ((flags & AUXILIARY_STATE_MASK == AUXILIARY_STATE_SHOWN)
        && (flags & SHOWN_STATE_MASK == SHOWN_STATE_SHOWN)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scratch element: byte array large enough to hold `flags_48`,
    /// aligned to four bytes so the aligned word read is sound on host
    /// exactly as it is on device.
    #[repr(align(4))]
    struct Element {
        bytes: [u8; FLAGS_OFFSET + 4],
    }

    impl Element {
        fn with_flags(flags: u32) -> Self {
            let mut element = Self { bytes: [0; FLAGS_OFFSET + 4] };
            element.bytes[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&flags.to_le_bytes());
            element
        }

        fn ptr(&self) -> *const u8 {
            self.bytes.as_ptr()
        }
    }

    fn is_shown(flags: u32) -> u32 {
        let element = Element::with_flags(flags);
        unsafe { ui_element_is_shown(element.ptr()) }
    }

    fn is_fully_shown(flags: u32) -> u32 {
        let element = Element::with_flags(flags);
        unsafe { ui_element_is_fully_shown(element.ptr()) }
    }

    #[test]
    fn fully_shown_requires_both_shown_states() {
        assert_eq!(is_fully_shown(0x200 | 0x800), 1);

        // Each field independently rejects its other three encodings.
        for auxiliary in [0u32, 0x400, 0x600] {
            assert_eq!(is_fully_shown(auxiliary | 0x800), 0, "auxiliary={auxiliary:#05x}");
        }
        for shown in [0u32, 0x1000, 0x1800] {
            assert_eq!(is_fully_shown(0x200 | shown), 0, "shown={shown:#06x}");
        }
    }

    #[test]
    fn fully_shown_matches_predicated_arm_comparisons() {
        // `andeq` and `cmpeq` mean the second field matters only after the
        // first equality succeeds; the final truth table is the conjunction.
        for auxiliary in 0u32..4 {
            for shown in 0u32..4 {
                let flags = (auxiliary << 9) | (shown << 11) | 0xffff_e1ff;
                let want = (auxiliary == 1 && shown == 1) as u32;
                assert_eq!(is_fully_shown(flags), want, "flags={flags:#010x}");
            }
        }
    }

    #[test]
    fn fully_shown_reads_the_same_aligned_flag_word() {
        let mut element = Element::with_flags(0x200 | 0x800);
        for byte in &mut element.bytes[..FLAGS_OFFSET] {
            *byte = 0xaa;
        }
        assert_eq!(unsafe { ui_element_is_fully_shown(element.ptr()) }, 1);
        element.bytes[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&0x200u32.to_le_bytes());
        assert_eq!(unsafe { ui_element_is_fully_shown(element.ptr()) }, 0);
    }

    #[test]
    fn shown_state_yields_one() {
        assert_eq!(is_shown(0x800), 1);
    }

    #[test]
    fn other_states_yield_zero() {
        for flags in [0x0000u32, 0x1000, 0x1800] {
            assert_eq!(is_shown(flags), 0, "flags={flags:#06x}");
        }
    }

    #[test]
    fn bits_outside_the_field_are_ignored() {
        // Every other flag bit, including the sibling bits 9-10 field,
        // must not perturb the result.
        // Field holds 0x800 with every other bit set (bit 12 clear).
        assert_eq!(is_shown(0xffff_efff), 1);
        // Field holds 0x1000 with every other bit set (bit 11 clear).
        assert_eq!(is_shown(0xffff_f7ff), 0);
        // Field holds 0 with every other bit set (bits 11-12 clear).
        assert_eq!(is_shown(0xffff_e7ff), 0);
        assert_eq!(is_shown(0x0600 | 0x0800), 1);
        assert_eq!(is_shown(0x0600), 0);
    }

    #[test]
    fn matches_reference_for_all_field_and_neighbour_combinations() {
        // Reference: `and r0, flags, #0x1800; cmp r0, #0x800` — 1 iff the
        // two-bit field equals 1.
        for field in 0u32..4 {
            for low in [0u32, 0x200, 0x600, 0x7ff] {
                let flags = (field << 11) | low | 0xe000_0000;
                let want = (field == 1) as u32;
                assert_eq!(is_shown(flags), want, "flags={flags:#010x}");
            }
        }
    }

    #[test]
    fn reads_only_the_word_at_offset_48() {
        // Neighbouring bytes stay hot; only the four bytes at +0x48 may
        // decide the result.
        let mut element = Element::with_flags(0x800);
        for byte in &mut element.bytes[..FLAGS_OFFSET] {
            *byte = 0xaa;
        }
        assert_eq!(unsafe { ui_element_is_shown(element.ptr()) }, 1);
        element.bytes[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        assert_eq!(unsafe { ui_element_is_shown(element.ptr()) }, 0);
    }
}
