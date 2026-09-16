//! The 'tdat' UI element's linked-'plst' lookup by persistent identifier.
//!
//! - `ui_plst_find_by_persistent_id` — original: `FUN_08050ae0` @
//!   0x08050ae0 (88 bytes; 5 direct `bl` call sites, 0 predicated,
//!   verified by decoding every B/BL word in `osos.dec`).

use crate::ui::plst_next::ui_plst_next;
use crate::ui::tdat_first_plst::ui_tdat_first_plst;

/// Byte offset of the linked 'plst' element's 64-bit persistent
/// identifier, read as a pair (`ldrd r0,r1,[r4,#0x30]`): low half at
/// +0x30, high half at +0x34. Matches the offset used by
/// `ui_element_reference_target_persistent_id` (0x082a6524).
const PERSISTENT_ID_OFFSET: usize = 0x30;

/// ui_plst_find_by_persistent_id — original: `FUN_08050ae0` @
/// 0x08050ae0 (88 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @
/// `0x08050ae0..0x08050b38`; the next function's `push {r4,r6,lr}`
/// prologue at 0x08050b38 confirms Ghidra's 88-byte extent exactly:
///
/// ```text
/// 08050ae0  push {r4, r5, r6, lr}
/// 08050ae4  mov r5, r2            ; id_low
/// 08050ae8  mov r4, r0            ; tdat element
/// 08050aec  subs r6, r3, #0       ; id_high
/// 08050af0  mov r0, r5
/// 08050af4  mov r2, #0
/// 08050af8  cmpeq r0, r2          ; id_high==0 && id_low==0?
/// 08050afc  beq 0x08050b30        ;   -> return 0
/// 08050b00  mov r0, r4
/// 08050b04  bl 0x080522d4         ; ui_tdat_first_plst
/// 08050b08  b 0x08050b28
/// 08050b0c  ldrd r0, r1, [r4, #0x30]   ; <- loop: persistent id pair
/// 08050b10  mov r2, r5
/// 08050b14  cmp r1, r6            ; high half first
/// 08050b18  cmpeq r0, r2          ; then low half
/// 08050b1c  mov r0, r4
/// 08050b20  popeq {r4, r5, r6, pc}     ; match -> return element
/// 08050b24  bl 0x08053bd0         ; ui_plst_next
/// 08050b28  movs r4, r0
/// 08050b2c  bne 0x08050b0c
/// 08050b30  mov r0, #0
/// 08050b34  pop {r4, r5, r6, pc}
/// ```
///
/// Algorithm: locate the linked 'plst' element of a 'tdat' UI element
/// whose 64-bit persistent identifier equals `{id_high, id_low}`. A
/// zero identifier (both halves zero) matches nothing and short-
/// circuits to 0 without touching the element. Otherwise the walk
/// starts at the element's first linked 'plst' (`ui_tdat_first_plst` @
/// 0x080522d4, the word at element+0x34) and steps through the
/// successor selector (`ui_plst_next` @ 0x08053bd0), comparing each
/// candidate's +0x30/+0x34 doubleword — high half first, exactly like
/// the original's `cmp r1,r6` / `cmpeq r0,r2` — and returning the
/// first exact match, or 0 at the end of the sequence.
///
/// The original's r1 argument is never read (the `ldrd` overwrites r1
/// unconditionally); it is kept in the signature as `_reserved` so the
/// export's AAPCS lane assignment matches the stock callers that load
/// r2/r3. Callers of the original (0x08054330, 0x080947f8, 0x080ab2e8,
/// 0x080df42c, 0x080e5bc0) feed the resulting 'plst' element pointer
/// to index lookups and flag reads.
///
/// Call count verified by decoding every B/BL word in osos.dec: 5
/// unconditional `bl` sites (0x08054340, 0x08094800, 0x080ab2f0,
/// 0x080df434, 0x080e5bc8), zero predicated; the body contains exactly
/// two `bl` instructions (the two callees above), both unconditional.
///
/// Deviations: the `ldrd` doubleword load is split into two aligned
/// `u32` reads in the original's comparison order (high half, then low
/// half); LLVM on ARMv5 is free to fuse them back into an `ldrd`, and
/// the observable behavior is identical because a 'plst' element is at
/// least 0x38 bytes. The port calls the already-ported callees
/// directly instead of branching to their stock addresses.
///
/// # Safety
///
/// `element` may be NULL or non-'tdat' (guarded by
/// `ui_tdat_first_plst`). Every 'plst'-tagged element reached through
/// the sequence must be readable through +0x37 for the identifier
/// pair, and through +0x27 for the successor selection in
/// `ui_plst_next`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ui_plst_find_by_persistent_id")]
pub unsafe extern "C" fn ui_plst_find_by_persistent_id(
    element: *const u8,
    _reserved: u32,
    id_low: u32,
    id_high: u32,
) -> u32 {
    if id_high == 0 && id_low == 0 {
        return 0;
    }
    let mut plst = ui_tdat_first_plst(element);
    while plst != 0 {
        let candidate = plst as *const u8;
        let high = candidate.add(PERSISTENT_ID_OFFSET + 4).cast::<u32>().read();
        let low = candidate.add(PERSISTENT_ID_OFFSET).cast::<u32>().read();
        if high == id_high && low == id_low {
            return plst;
        }
        plst = ui_plst_next(candidate);
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;

    // The slab hint is shared by every fixture test in this module and
    // mappings are never unmapped; serialize so concurrent tests cannot
    // clobber each other's chains.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    // Slab layout: 'tdat' element @ +0x0000, up to three 'plst'
    // elements at +0x1000 strides of 0x100. All target-pointer fields
    // hold real 32-bit addresses of this slab (host pointers are 8
    // bytes; the slab round-trips through u32).
    const TDAT_OFF: usize = 0x0000;
    const PLST_REGION: usize = 0x1000;
    const PLST_STRIDE: usize = 0x100;

    const CLASS_TAG_OFFSET: usize = 0x4;
    const TDAT_CLASS_TAG: u32 = 0x7464_6174;
    const PLST_CLASS_TAG: u32 = 0x706c_7374;

    // ui_tdat_first_plst's first-link word at +0x34; ui_plst_next's
    // explicit successor word at +0x24.
    const FIRST_PLST_OFFSET: usize = 0x34;
    const SUCCESSOR_OFFSET: usize = 0x24;

    unsafe fn word(base: *mut u8, off: usize) -> *mut u32 {
        base.add(off).cast::<u32>()
    }

    unsafe fn write_word(base: *mut u8, off: usize, value: u32) {
        word(base, off).write(value);
    }

    /// Builds a 'tdat' element plus `ids.len()` 'plst' elements chained
    /// through each element's +0x24 successor word, each carrying the
    /// given `{low, high}` identifier at +0x30/+0x34. Returns the slab
    /// and the address of plst element `n`.
    unsafe fn build_chain(
        slab: *mut u8,
        ids: &[(u32, u32)],
    ) -> impl Fn(usize) -> u32 {
        let plst_addr = move |n: usize| (slab as usize + PLST_REGION + n * PLST_STRIDE) as u32;
        write_word(slab, TDAT_OFF + CLASS_TAG_OFFSET, TDAT_CLASS_TAG);
        write_word(slab, TDAT_OFF + FIRST_PLST_OFFSET, plst_addr(0));
        for (n, &(low, high)) in ids.iter().enumerate() {
            let element = slab.add(PLST_REGION + n * PLST_STRIDE);
            write_word(element, CLASS_TAG_OFFSET, PLST_CLASS_TAG);
            write_word(element, PERSISTENT_ID_OFFSET, low);
            write_word(element, PERSISTENT_ID_OFFSET + 4, high);
            let next = if n + 1 < ids.len() { plst_addr(n + 1) } else { 0 };
            write_word(element, SUCCESSOR_OFFSET, next);
        }
        plst_addr
    }

    #[test]
    fn zero_identifier_matches_nothing_without_touching_element() {
        // NULL element, zero id: the original short-circuits before the
        // first-plst call, so a NULL element must be safe here.
        assert_eq!(
            unsafe { ui_plst_find_by_persistent_id(core::ptr::null(), 0, 0, 0) },
            0
        );
        assert_eq!(
            unsafe { ui_plst_find_by_persistent_id(core::ptr::null(), 0xdead_beef, 0, 0) },
            0
        );
    }

    #[test]
    fn null_element_with_nonzero_id_returns_zero() {
        assert_eq!(
            unsafe { ui_plst_find_by_persistent_id(core::ptr::null(), 0, 1, 2) },
            0
        );
    }

    #[test]
    fn finds_first_middle_and_last_chain_elements() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::UI_PLST_FIND_BY_PERSISTENT_ID, 0x2000) else {
            assert!(note_missing_u32_fixture("ui/plst_find_by_persistent_id"));
            return;
        };
        unsafe {
            let ids = [(0x1111_0001, 0x2222_0001), (0xaaaa_bbbb, 0xcccc_dddd), (0, 0xdead_0009)];
            let plst_addr = build_chain(slab, &ids);
            let element = slab.add(TDAT_OFF) as *const u8;
            for (n, &(low, high)) in ids.iter().enumerate() {
                assert_eq!(
                    ui_plst_find_by_persistent_id(element, 0, low, high),
                    plst_addr(n),
                    "id {low:#x}/{high:#x} must select chain element {n}"
                );
            }
            // A zero low half is a legitimate match key: element 2
            // carries it (covered above). A zero high half with a
            // nonzero low half must not short-circuit either - and
            // matches nothing here since no element pairs that low
            // half with a zero high half.
            assert_eq!(ui_plst_find_by_persistent_id(element, 0, 0x1111_0001, 0), 0);
        }
    }

    #[test]
    fn unmatched_identifier_returns_zero() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::UI_PLST_FIND_BY_PERSISTENT_ID, 0x2000) else {
            return; // already noted by the chain test on this host
        };
        unsafe {
            let ids = [(1, 2), (3, 4)];
            build_chain(slab, &ids);
            let element = slab.add(TDAT_OFF) as *const u8;
            // Low half matches element 0 but the high half does not.
            assert_eq!(ui_plst_find_by_persistent_id(element, 0, 1, 4), 0);
            // High half matches element 1 but the low half does not.
            assert_eq!(ui_plst_find_by_persistent_id(element, 0, 2, 4), 0);
            // Neither half matches anything.
            assert_eq!(
                ui_plst_find_by_persistent_id(element, 0, 0xffff_ffff, 0xffff_ffff),
                0
            );
        }
    }

    #[test]
    fn reserved_argument_is_ignored() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::UI_PLST_FIND_BY_PERSISTENT_ID, 0x2000) else {
            return;
        };
        unsafe {
            let ids = [(0x1234_5678, 0x9abc_def0)];
            let plst_addr = build_chain(slab, &ids);
            let element = slab.add(TDAT_OFF) as *const u8;
            for reserved in [0, 1, 0xdead_beef, u32::MAX] {
                assert_eq!(
                    ui_plst_find_by_persistent_id(element, reserved, 0x1234_5678, 0x9abc_def0),
                    plst_addr(0)
                );
            }
        }
    }
}
