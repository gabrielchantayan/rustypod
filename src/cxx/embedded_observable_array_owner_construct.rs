//! `embedded_observable_array_owner_construct` — `FUN_0820b884` @ 0x0820b884.
//!
//! True extent: 44 bytes (40 executable bytes and the vtable literal at
//! 0x0820b8ac), before the next function at 0x0820b8b0. Whole-image aligned
//! A32 decoding finds two inbound plain BLs (0x081dcddc, 0x081dce90), zero
//! predicated BLs; the body contains three plain BLs and no predicated BLs.
//!
//! Construct the two-pair metadata base with metadata zero, install vtable
//! 0x08992200, clear the three words at +0x48, then construct the observable
//! array at +0x54. Return its receiver minus 0x54. Deliberate deviations:
//! inline the verified three-word initializer at 0x081ee300 (five A32 words,
//! including bx lr, preserving r0); use the existing Rust constructor ports.
//! ARM match review: LLVM retains two constructor calls, inlines the three
//! zero stores, and proves both constructor returns equal their receivers,
//! eliminating the final subtraction. No identical-body folding observed.

use super::embedded_observable_array_owner_destruct::EmbeddedObservableArrayOwner;
use super::observable_array::{observable_array_construct, ObservableArray};
use super::vtable_two_pair_metadata_construct::vtable_two_pair_metadata_construct;

/// Construct a 100-byte owner from two source pairs.
///
/// # Safety
/// `this` must be aligned and writable for 100 bytes. Both source pairs must
/// satisfy the base constructor's aligned eight-byte readable contract;
/// aliasing is permitted and observes the base constructor's store order.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn embedded_observable_array_owner_construct(
    this: *mut EmbeddedObservableArrayOwner,
    src_pair_at_4: *const u8,
    src_pair_at_12: *const u8,
) -> *mut EmbeddedObservableArrayOwner {
    let base = vtable_two_pair_metadata_construct(this.cast(), src_pair_at_4, src_pair_at_12, 0);
    let words = base.cast::<u32>();
    words.write_volatile(0x0899_2200);
    words.add(18).write_volatile(0);
    words.add(19).write_volatile(0);
    words.add(20).write_volatile(0);
    let array = observable_array_construct(base.add(0x54).cast::<ObservableArray>());
    array.cast::<u8>().sub(0x54).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::observable_array::OBSERVABLE_ARRAY_VTABLE;

    #[test]
    fn initializes_complete_owner_and_preserves_guards() {
        for pair in [[0, 0], [u32::MAX, 0x8000_0000]] {
            let mut words = [0xa5a5_a5a5u32; 27];
            let owner = unsafe { words.as_mut_ptr().add(1).cast() };
            let other = [0x1234_5678u32, 0x8765_4321];
            let result = unsafe { embedded_observable_array_owner_construct(
                owner, pair.as_ptr().cast(), other.as_ptr().cast(),
            ) };
            assert_eq!(result, owner);
            assert_eq!(words[0], 0xa5a5_a5a5);
            assert_eq!(words[26], 0xa5a5_a5a5);
            assert_eq!(words[1..26], [
                0x0899_2200, pair[0], pair[1], other[0], other[1],
                0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0,
                0x0010_b6c3, 0x0001_5180, 0, 0, 0,
                OBSERVABLE_ARRAY_VTABLE, 0, 0, 0,
            ]);
        }
    }

    #[test]
    fn aliased_sources_observe_base_initialization_order() {
        let mut words = [0xdead_beefu32; 25];
        let owner = words.as_mut_ptr().cast();
        unsafe { embedded_observable_array_owner_construct(
            owner, words.as_ptr().cast(), words.as_ptr().add(1).cast(),
        ); }
        assert_eq!(words[1..5], [0x0898_1718; 4]);
        assert_eq!(words[0], 0x0899_2200);
        assert_eq!(words[18..21], [0; 3]);
        assert_eq!(words[21..25], [OBSERVABLE_ARRAY_VTABLE, 0, 0, 0]);
    }
}
