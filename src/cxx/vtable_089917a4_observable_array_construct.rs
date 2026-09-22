//! Construct the vtable-0x089917a4 observable-array temporary.
//!
//! `vtable_089917a4_observable_array_construct` — original: `FUN_08204434` @
//! **0x08204434**.
//!
//! **44 bytes**, `0x08204434..0x08204460`; the literal-pool vtable word is at
//! `0x08204460`, and the next separately linked function begins at
//! `0x08204464`. Raw ARM words contain **1 plain `bl`** (to the ported
//! [`super::vtable_two_pair_base_construct::vtable_two_pair_base_construct`])
//! and no predicated `bl`; decoding every ARM B/BL word in `osos.dec` finds
//! **3 plain `bl` callers** (`0x081dcd98`, `0x081dce58`, `0x0820fe50`) and no
//! predicated callers.
//!
//! # Algorithm
//!
//! Construct the 20-byte shared two-pair base from the two source pairs, then
//! install vtable `0x089917a4`, clear the owned observable-array word at
//! `+0x14`, set byte `+0x18`, and store the low 16 bits of `mode` at `+0x1a`.
//! The paired getter at `0x0820440c` consumes the owned array word and the
//! destructor at `0x08204464` releases it.
//!
//! Deliberate deviation: this takes raw byte pointers rather than a Rust
//! structure. The target's owned-array field is a four-byte word, while host
//! pointers are wider; raw target offsets preserve the ARM layout in host
//! tests without pretending those layouts are identical.

use super::vtable_two_pair_base_construct::vtable_two_pair_base_construct;

const VTABLE_089917A4: u32 = 0x0899_17a4;
const OWNED_ARRAY_OFFSET: usize = 0x14;
const FLAG_OFFSET: usize = 0x18;
const MODE_OFFSET: usize = 0x1a;

/// Constructs an observable-array temporary and returns the base constructor's
/// result.
///
/// # Safety
///
/// `storage` must be writable for 28 bytes and four-byte aligned. Both source
/// pairs must be readable for eight bytes and four-byte aligned. The retailOS
/// implementation dereferences all three pointers without NULL or alignment
/// guards.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_089917a4_observable_array_construct(
    storage: *mut u8,
    first_pair: *const u8,
    second_pair: *const u8,
    mode: u32,
) -> *mut u8 {
    let this = unsafe { vtable_two_pair_base_construct(storage, first_pair, second_pair) };
    unsafe {
        this.cast::<u32>().write_volatile(VTABLE_089917A4);
        this.add(OWNED_ARRAY_OFFSET).cast::<u32>().write_volatile(0);
        this.add(FLAG_OFFSET).write_volatile(1);
        this.add(MODE_OFFSET).cast::<u16>().write_volatile(mode as u16);
    }
    this
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(4))]
    struct AlignedBytes([u8; 36]);

    unsafe fn word_at(bytes: *const u8, offset: usize) -> u32 {
        unsafe { bytes.add(offset).cast::<u32>().read() }
    }

    #[test]
    fn constructs_base_and_initializes_all_derived_fields() {
        let mut storage = AlignedBytes([0xa5; 36]);
        let object = unsafe { storage.0.as_mut_ptr().add(4) };
        let first_pair = [0xdead_beef, 0x0bad_f00d];
        let second_pair = [0x1234_5678, 0x9abc_def0];

        let returned = unsafe {
            vtable_089917a4_observable_array_construct(
                object,
                first_pair.as_ptr().cast(),
                second_pair.as_ptr().cast(),
                0xcafe_002c,
            )
        };

        assert_eq!(returned, object);
        assert_eq!(unsafe { word_at(object, 0) }, VTABLE_089917A4);
        assert_eq!(unsafe { word_at(object, 4) }, first_pair[0]);
        assert_eq!(unsafe { word_at(object, 8) }, first_pair[1]);
        assert_eq!(unsafe { word_at(object, 12) }, second_pair[0]);
        assert_eq!(unsafe { word_at(object, 16) }, second_pair[1]);
        assert_eq!(unsafe { word_at(object, OWNED_ARRAY_OFFSET) }, 0);
        assert_eq!(unsafe { object.add(FLAG_OFFSET).read() }, 1);
        assert_eq!(unsafe { object.add(MODE_OFFSET).cast::<u16>().read() }, 0x002c);
        assert_eq!(&storage.0[..4], &[0xa5; 4]);
        assert_eq!(&storage.0[32..], &[0xa5; 4]);
    }

    #[test]
    fn base_return_is_the_object_receiving_derived_writes() {
        let mut storage = AlignedBytes([0; 36]);
        let first_pair = [1, 2];
        let second_pair = [3, 4];

        let returned = unsafe {
            vtable_089917a4_observable_array_construct(
                storage.0.as_mut_ptr(),
                first_pair.as_ptr().cast(),
                second_pair.as_ptr().cast(),
                0xffff_003b,
            )
        };

        assert_eq!(returned, storage.0.as_mut_ptr());
        assert_eq!(unsafe { returned.add(FLAG_OFFSET).read() }, 1);
        assert_eq!(unsafe { returned.add(MODE_OFFSET).cast::<u16>().read() }, 0x003b);
    }
}
