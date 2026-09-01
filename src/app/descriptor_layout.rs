//! Descriptor-layout initialization shared by retailOS command builders.
//!
//! `descriptor_layout_initialize` — original `FUN_082a4680` @ `0x082a4680`
//! (**180 bytes, `0x082a4680..0x082a4734`**). Ghidra's 176-byte extent omits
//! the final `0x4e6f6e65` (`"None"`) literal at `0x082a4730`; the next
//! separately linked function begins at `0x082a4734`. Decoding every ARM
//! B/BL word in `osos.dec` finds **25 direct call sites**, all unconditional
//! plain `bl`; there are no predicated BL or plain-B callers.
//!
//! # Algorithm
//!
//! Initializes the fixed portion of a command-builder descriptor layout:
//!
//! - stores the `None` token, the source's current value twice, and `-1`;
//! - derives the layout flags from source flag bits 1 and 2, plus the fixed
//!   `0x200` bit;
//! - copies optional metadata at source words 13 and 14 when word 13 is
//!   nonzero, with source flag bit 0 adding bit 1 to the output state byte;
//! - invokes the real descriptor-field mapper four times for source triples
//!   in the original order `(1, 0, 2, 3)`.
//!
//! The nested triple format is not yet identified. `FUN_08270f84` is a real,
//! separate function entry (not a guessed identity), but is not ported, so
//! the target default calls it at its fixed firmware address and host tests
//! install a recorder. This is the only deliberate deviation: the four calls
//! dispatch through the mapper seam rather than directly encoding the helper
//! address; LLVM retains the fourth as an indirect tail branch.

use core::ptr::addr_of_mut;

/// The word written at layout word 1 by `ldr r0,[pc,#160]`.
pub const NONE_TOKEN: u32 = 0x4e6f_6e65;

/// Source record is readable through this word, whose low byte is its flags.
pub const DESCRIPTOR_SOURCE_WORDS: usize = 19;
/// Layout record is written through this final word.
pub const DESCRIPTOR_LAYOUT_WORDS: usize = 22;

const SOURCE_CURRENT_VALUE: usize = 12;
const SOURCE_OPTIONAL_VALUE: usize = 13;
const SOURCE_OPTIONAL_METADATA: usize = 14;
const SOURCE_FLAGS: usize = 18;

const LAYOUT_NONE_TOKEN: usize = 1;
const LAYOUT_CURRENT_VALUE: usize = 2;
const LAYOUT_SENTINEL: usize = 3;
const LAYOUT_CURRENT_VALUE_DUPLICATE: usize = 4;
const LAYOUT_FLAGS: usize = 6;
const LAYOUT_FIRST_FIELD: usize = 7;
const LAYOUT_SECOND_FIELD: usize = 10;
const LAYOUT_THIRD_FIELD: usize = 13;
const LAYOUT_FOURTH_FIELD: usize = 16;
const LAYOUT_OPTIONAL_STATE: usize = 19;
const LAYOUT_OPTIONAL_METADATA: usize = 20;
const LAYOUT_OPTIONAL_VALUE: usize = 21;

/// The unported triple mapper `FUN_08270f84` @ `0x08270f84`.
#[derive(Clone, Copy)]
pub struct DescriptorLayoutOps {
    /// Maps one three-word source field into its three-word layout field.
    pub copy_field: unsafe extern "C" fn(source: *const u32, destination: *mut u32),
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_copy_descriptor_field(source: *const u32, destination: *mut u32) {
    let copy: unsafe extern "C" fn(*const u32, *mut u32) = unsafe {
        core::mem::transmute(0x0827_0f84usize)
    };
    unsafe { copy(source, destination) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_copy_descriptor_field(_source: *const u32, _destination: *mut u32) {
    panic!("descriptor_layout_initialize requires descriptor mapper 0x08270f84")
}

/// Active mapper. The device calls the stock mapper until it receives its own
/// port; host tests substitute a deterministic recorder.
#[cfg(target_os = "none")]
pub static mut DESCRIPTOR_LAYOUT_OPS: DescriptorLayoutOps = DescriptorLayoutOps {
    copy_field: firmware_copy_descriptor_field,
};

/// Host default rejects accidental calls that have not installed a mapper.
#[cfg(not(target_os = "none"))]
pub static mut DESCRIPTOR_LAYOUT_OPS: DescriptorLayoutOps = DescriptorLayoutOps {
    copy_field: missing_copy_descriptor_field,
};

/// Initializes a command-builder descriptor layout from its source record.
///
/// # Safety
///
/// `source` must address `DESCRIPTOR_SOURCE_WORDS` readable words and
/// `layout` must address `DESCRIPTOR_LAYOUT_WORDS` writable words. The flags
/// word is read only as its low byte and the optional state is written only as
/// its low byte, exactly like the retailOS `ldrb`/`strb` instructions. Neither
/// pointer is NULL-checked by the original.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn descriptor_layout_initialize(source: *const u32, layout: *mut u32) {
    unsafe {
        layout.add(LAYOUT_NONE_TOKEN).write_volatile(NONE_TOKEN);

        let current_value = source.add(SOURCE_CURRENT_VALUE).read_volatile();
        layout.add(LAYOUT_CURRENT_VALUE).write_volatile(current_value);
        layout.add(LAYOUT_SENTINEL).write_volatile(u32::MAX);
        layout.add(LAYOUT_CURRENT_VALUE_DUPLICATE).write_volatile(current_value);

        let source_flags = source.add(SOURCE_FLAGS).cast::<u8>().read_volatile();
        let layout_flags = 0x200 | ((source_flags & 2) as u32 >> 1)
            | if source_flags & 4 != 0 { 0x800 } else { 0 };
        layout.add(LAYOUT_FLAGS).write_volatile(layout_flags);

        let optional_value = source.add(SOURCE_OPTIONAL_VALUE).read_volatile();
        let optional_state = u8::from(optional_value != 0);
        let optional_state_ptr = layout.add(LAYOUT_OPTIONAL_STATE).cast::<u8>();
        optional_state_ptr.write_volatile(optional_state);
        layout.add(LAYOUT_OPTIONAL_METADATA).write_volatile(if optional_value != 0 {
            source.add(SOURCE_OPTIONAL_METADATA).read_volatile()
        } else {
            0
        });
        layout.add(LAYOUT_OPTIONAL_VALUE).write_volatile(optional_value);
        if source_flags & 1 != 0 {
            optional_state_ptr.write_volatile(optional_state_ptr.read_volatile() | 2);
        }

        let copy = addr_of_mut!(DESCRIPTOR_LAYOUT_OPS.copy_field).read_volatile();
        copy(source.add(3), layout.add(LAYOUT_FIRST_FIELD));
        copy(source, layout.add(LAYOUT_SECOND_FIELD));
        copy(source.add(6), layout.add(LAYOUT_THIRD_FIELD));
        copy(source.add(9), layout.add(LAYOUT_FOURTH_FIELD));
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::{addr_of, addr_of_mut};
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut COPY_CALLS: Vec<(usize, usize)> = Vec::new();
    static mut SOURCE: [u32; DESCRIPTOR_SOURCE_WORDS] = [0; DESCRIPTOR_SOURCE_WORDS];
    static mut LAYOUT: [u32; DESCRIPTOR_LAYOUT_WORDS] = [0; DESCRIPTOR_LAYOUT_WORDS];

    unsafe extern "C" fn recording_copy(source: *const u32, destination: *mut u32) {
        unsafe {
            (*addr_of_mut!(COPY_CALLS)).push((source as usize, destination as usize));
            for word in 0..3 {
                destination.add(word).write_volatile(source.add(word).read_volatile());
            }
        }
    }

    fn install_mapper() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            DESCRIPTOR_LAYOUT_OPS = DescriptorLayoutOps { copy_field: recording_copy };
            (*addr_of_mut!(COPY_CALLS)).clear();
            (*addr_of_mut!(SOURCE)).fill(0);
            (*addr_of_mut!(LAYOUT)).fill(0xdead_beef);
        }
        guard
    }

    fn restore_mapper(guard: MutexGuard<'static, ()>) {
        unsafe {
            DESCRIPTOR_LAYOUT_OPS = DescriptorLayoutOps {
                copy_field: missing_copy_descriptor_field,
            };
        }
        drop(guard);
    }

    fn source() -> *const u32 {
        unsafe { addr_of!(SOURCE) as *const u32 }
    }

    fn layout() -> *mut u32 {
        unsafe { addr_of_mut!(LAYOUT) as *mut u32 }
    }

    fn seed_fields() {
        unsafe {
            for field in 0..4 {
                for word in 0..3 {
                    (*addr_of_mut!(SOURCE))[field * 3 + word] =
                        0x1000_0000 | ((field as u32) << 8) | word as u32;
                }
            }
            (*addr_of_mut!(SOURCE))[SOURCE_CURRENT_VALUE] = 0x0bad_c0de;
        }
    }

    #[test]
    fn initializes_required_words_and_maps_fields_in_retail_order() {
        let guard = install_mapper();
        seed_fields();
        unsafe {
            (*addr_of_mut!(SOURCE))[SOURCE_FLAGS] = 6;
            descriptor_layout_initialize(source(), layout());

            assert_eq!((*addr_of!(LAYOUT))[0], 0xdead_beef, "word zero is caller-owned");
            assert_eq!((*addr_of!(LAYOUT))[LAYOUT_NONE_TOKEN], NONE_TOKEN);
            assert_eq!((*addr_of!(LAYOUT))[LAYOUT_CURRENT_VALUE], 0x0bad_c0de);
            assert_eq!((*addr_of!(LAYOUT))[LAYOUT_SENTINEL], u32::MAX);
            assert_eq!((*addr_of!(LAYOUT))[LAYOUT_CURRENT_VALUE_DUPLICATE], 0x0bad_c0de);
            assert_eq!((*addr_of!(LAYOUT))[LAYOUT_FLAGS], 0x0a01, "source bits 2 and 1 map independently");
            assert_eq!((*addr_of!(LAYOUT))[LAYOUT_OPTIONAL_STATE] & 0xff, 0);
            assert_eq!((*addr_of!(LAYOUT))[LAYOUT_OPTIONAL_METADATA], 0);
            assert_eq!((*addr_of!(LAYOUT))[LAYOUT_OPTIONAL_VALUE], 0);

            for (field, layout_word) in [
                (1, LAYOUT_FIRST_FIELD),
                (0, LAYOUT_SECOND_FIELD),
                (2, LAYOUT_THIRD_FIELD),
                (3, LAYOUT_FOURTH_FIELD),
            ] {
                for word in 0..3 {
                    assert_eq!(
                        (*addr_of!(LAYOUT))[layout_word + word],
                        (*addr_of!(SOURCE))[field * 3 + word],
                    );
                }
            }
            assert_eq!(
                *addr_of!(COPY_CALLS),
                std::vec![
                    (source().add(3) as usize, layout().add(LAYOUT_FIRST_FIELD) as usize),
                    (source() as usize, layout().add(LAYOUT_SECOND_FIELD) as usize),
                    (source().add(6) as usize, layout().add(LAYOUT_THIRD_FIELD) as usize),
                    (source().add(9) as usize, layout().add(LAYOUT_FOURTH_FIELD) as usize),
                ],
                "the final retail tail branch maps source field three last",
            );
        }
        restore_mapper(guard);
    }

    #[test]
    fn optional_metadata_and_state_byte_follow_the_low_three_source_flags() {
        let guard = install_mapper();
        seed_fields();
        unsafe {
            (*addr_of_mut!(SOURCE))[SOURCE_OPTIONAL_VALUE] = 0x1234_5678;
            (*addr_of_mut!(SOURCE))[SOURCE_OPTIONAL_METADATA] = 0x89ab_cdef;
            (*addr_of_mut!(SOURCE))[SOURCE_FLAGS] = 0xab00_0007;
            descriptor_layout_initialize(source(), layout());

            assert_eq!((*addr_of!(LAYOUT))[LAYOUT_FLAGS], 0x0a01);
            assert_eq!((*addr_of!(LAYOUT))[LAYOUT_OPTIONAL_STATE] & 0xff, 3);
            assert_eq!((*addr_of!(LAYOUT))[LAYOUT_OPTIONAL_METADATA], 0x89ab_cdef);
            assert_eq!((*addr_of!(LAYOUT))[LAYOUT_OPTIONAL_VALUE], 0x1234_5678);
        }
        restore_mapper(guard);
    }
}
