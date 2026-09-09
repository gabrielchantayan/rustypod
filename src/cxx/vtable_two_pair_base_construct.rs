//! `vtable_two_pair_base_construct` — original: `FUN_0811050c` @ 0x0811050c
//! (40 bytes).
//!
//! # Extent and reachability, binary-verified
//!
//! The raw ARM body is ten words from 0x0811050c through 0x08110530; the
//! literal-pool vtable word at 0x08110534 belongs to the function and the
//! next separately linked function begins at 0x08110538. Decoding every ARM
//! B/BL word in `osos.dec` finds exactly 14 direct call sites
//! (0x08103e14, 0x0812bdd8, 0x0812e8ec, 0x0812ea1c, 0x081558f0, 0x0815f1d0,
//! 0x0815fbdc, 0x0816de28, 0x081baaec, 0x081d0d9c, 0x081e8794, 0x081fadcc,
//! 0x08203274, 0x0820443c): all are unconditional `bl`; there are no
//! predicated calls, no plain-`b` tail calls, and an aligned whole-image
//! word scan finds no data reference to 0x0811050c, so the constructor is
//! statically bound by its derived wrappers only.
//!
//! # Algorithm
//!
//! Construct the 20-byte vtable-backed base object at `this`:
//!
//! ```text
//! str  VTABLE, [r0], #4      @ this[0] = 0x08981718
//! bl   0x081bb6a4            @ pair_copy(this + 4,  src_a): two ordered words
//! add  r0, r0, #8            @ pair_copy preserves r0 -> this + 12
//! bl   0x081bb6a4            @ pair_copy(this + 12, src_b): two ordered words
//! sub  r0, r0, #12           @ return this
//! ```
//!
//! The shared two-word copy at 0x081bb6a4 (`ldr/str; ldr #4/str #4; bx lr`,
//! r0 preserved) is inlined per project precedent: each pair is copied as
//! two ordered word loads/stores, so a source aliasing an earlier
//! destination word observes the store (the vtable store precedes the first
//! pair load). The original has no null or alignment guard.
//!
//! # Behavioural notes
//!
//! All 14 callers are derived-class constructors of the form
//! `push {r4,lr}; bl 0x0811050c; ldr r1, =derived_vtable; str r1, [r0]`
//! that never set r1/r2 — the pair sources are stale registers left by the
//! grandcaller, so on device the pair fields transiently hold whatever the
//! two leftover pointers reference until later initialization. Ghidra's C
//! drops all three arguments (callers show `FUN_0811050c()`); the asm
//! passes (this, src_a, src_b) in r0-r2. The vtable region 0x08981718 does
//! not decode as an ARM/Thumb code or a table of code pointers in osos.dec;
//! the consumer at 0x08103dc8 still dispatches through `[vtable + 8]`, so
//! the region is presumably rewritten at runtime. Documented as an anomaly,
//! not resolved here.
//!
//! Deliberate deviations: the 0x081bb6a4 pair copy is inlined with volatile
//! ordered loads/stores (no seam for an already-inlined helper); the Rust
//! signature takes the two pair sources as typed const pointers.

/// The literal-pool vtable installed by the ARM constructor.
pub const VTABLE_ADDRESS: u32 = 0x0898_1718;

/// Constructs the common 20-byte vtable-backed base object and returns
/// `this`.
///
/// # Safety
///
/// `this` must point to at least 20 writable bytes and be 4-byte aligned
/// for the word stores. `src_pair_at_4` and `src_pair_at_12` must each be
/// readable for 8 bytes and 4-byte aligned; the original dereferences all
/// three without a null check.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_two_pair_base_construct")]
#[inline(never)]
pub unsafe extern "C" fn vtable_two_pair_base_construct(
    this: *mut u8,
    src_pair_at_4: *const u8,
    src_pair_at_12: *const u8,
) -> *mut u8 {
    unsafe {
        this.cast::<u32>().write_volatile(VTABLE_ADDRESS);
        let word = src_pair_at_4.cast::<u32>().read_volatile();
        this.add(4).cast::<u32>().write_volatile(word);
        let word = src_pair_at_4.add(4).cast::<u32>().read_volatile();
        this.add(8).cast::<u32>().write_volatile(word);
        let word = src_pair_at_12.cast::<u32>().read_volatile();
        this.add(12).cast::<u32>().write_volatile(word);
        let word = src_pair_at_12.add(4).cast::<u32>().read_volatile();
        this.add(16).cast::<u32>().write_volatile(word);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4))]
    struct AlignedBytes([u8; 28]);

    unsafe fn word_at(bytes: *const u8, offset: usize) -> u32 {
        unsafe { bytes.add(offset).cast::<u32>().read() }
    }

    #[test]
    fn installs_vtable_copies_both_pairs_and_returns_this() {
        let mut storage = AlignedBytes([0xa5; 28]);
        let object = storage.0.as_mut_ptr().wrapping_add(4);
        let pair_a: [u32; 2] = [0xdead_beef, 0x0bad_f00d];
        let pair_b: [u32; 2] = [0x1234_5678, 0x9abc_def0];

        let returned = unsafe {
            vtable_two_pair_base_construct(
                object,
                pair_a.as_ptr().cast(),
                pair_b.as_ptr().cast(),
            )
        };

        assert_eq!(returned, object);
        assert_eq!(unsafe { word_at(object, 0) }, VTABLE_ADDRESS);
        assert_eq!(unsafe { word_at(object, 4) }, 0xdead_beef);
        assert_eq!(unsafe { word_at(object, 8) }, 0x0bad_f00d);
        assert_eq!(unsafe { word_at(object, 12) }, 0x1234_5678);
        assert_eq!(unsafe { word_at(object, 16) }, 0x9abc_def0);
        assert_eq!(&storage.0[..4], &[0xa5; 4]);
        assert_eq!(&storage.0[24..], &[0xa5; 4]);
    }

    #[test]
    fn vtable_store_is_visible_to_an_overlapping_first_pair_source() {
        // ARM order: vtable store, then the first pair's ordered loads.
        // With src_pair_at_4 == this - 4 the first copied word is the
        // pre-existing fill and the second is the freshly stored vtable,
        // proving the vtable store is ordered before the pair loads.
        let mut storage = AlignedBytes([0x3c; 28]);
        let object = storage.0.as_mut_ptr().wrapping_add(4);
        let pair_b: [u32; 2] = [0x1234_5678, 0x9abc_def0];

        let returned = unsafe {
            vtable_two_pair_base_construct(
                object,
                storage.0.as_ptr(),
                pair_b.as_ptr().cast(),
            )
        };

        assert_eq!(returned, object);
        assert_eq!(unsafe { word_at(object, 0) }, VTABLE_ADDRESS);
        assert_eq!(unsafe { word_at(object, 4) }, 0x3c3c_3c3c);
        assert_eq!(unsafe { word_at(object, 8) }, VTABLE_ADDRESS);
        assert_eq!(unsafe { word_at(object, 12) }, 0x1234_5678);
        assert_eq!(unsafe { word_at(object, 16) }, 0x9abc_def0);
    }

    #[test]
    fn second_pair_source_observes_the_first_pair_store() {
        // src_pair_at_12 == this + 4 aliases the first pair's destination:
        // its loads see the words pair_copy deposited there.
        let mut storage = AlignedBytes([0x3c; 28]);
        let object = storage.0.as_mut_ptr().wrapping_add(4);
        let pair_a: [u32; 2] = [0xaaaa_0001, 0xbbbb_0002];

        unsafe {
            vtable_two_pair_base_construct(
                object,
                pair_a.as_ptr().cast(),
                object.wrapping_add(4),
            )
        };

        assert_eq!(unsafe { word_at(object, 4) }, 0xaaaa_0001);
        assert_eq!(unsafe { word_at(object, 8) }, 0xbbbb_0002);
        assert_eq!(unsafe { word_at(object, 12) }, 0xaaaa_0001);
        assert_eq!(unsafe { word_at(object, 16) }, 0xbbbb_0002);
    }
}
