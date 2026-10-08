//! `vtable_flag_payload_construct` — original: `FUN_081b6968` @
//! **0x081b6968** (28 instruction bytes, followed by its four-byte
//! literal-pool vtable word at 0x081b6984; 32 bytes through the next function).
//!
//! # Extent and reachability, binary-verified
//!
//! Raw ARM runs from `mov r2,r1` at 0x081b6968 through `pop {pc}` at
//! 0x081b6980. The following pool word is `0x0898c2a4`; the distinct next
//! function starts at 0x081b6988 (`cmp r0,#0`). Decoding every ARM B/BL
//! immediate in `osos.dec` finds exactly ten inbound calls, all unconditional
//! `bl` (0x08135ba8, 0x0813ee48, 0x08143a6c, 0x08148790, 0x08177f0c,
//! 0x08187080, 0x0819cd3c, 0x081ba988, 0x081deb68, and 0x0820b210). There
//! are no predicated calls or plain-`b` transfers to the entry.
//!
//! # Algorithm
//!
//! Call the shared base constructor at 0x08135788 with `this`, retain the
//! incoming payload across that call, replace the base vtable on its returned
//! pointer with `0x0898c2a4`, store the payload at +8, and return that pointer.
//! The decoded base constructor installs `0x08984948` at +0 and clears byte
//! +4. No argument, NULL, or alignment guard exists.
//!
//! # Deliberate deviations
//!
//! None. Call the verified direct Rust base constructor; no wider class
//! identity is inferred.

use super::vtable_flag_base_construct::vtable_flag_base_construct;
/// Derived vtable literal at 0x081b6984.
pub const VTABLE_FLAG_PAYLOAD_VTABLE_ADDRESS: u32 = 0x0898_c2a4;

/// The initialized prefix shared by the base and derived constructor.
#[repr(C)]
pub struct VtableFlagPayloadPrefix {
    /// +0x00: base vtable, then [`VTABLE_FLAG_PAYLOAD_VTABLE_ADDRESS`].
    pub vtable: u32,
    /// +0x04: zeroed by the base constructor.
    pub flag: u8,
    /// +0x05..+0x07: not touched by either decoded constructor.
    pub unresolved_05: [u8; 3],
    /// +0x08: incoming payload retained across the base call.
    pub payload: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x00] = [0; core::mem::offset_of!(VtableFlagPayloadPrefix, vtable)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(VtableFlagPayloadPrefix, flag)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(VtableFlagPayloadPrefix, payload)];

/// Constructs the observed vtable/flag/payload prefix and returns the base
/// constructor's result.
///
/// # Safety
///
/// `this`, and the pointer returned by the installed base constructor, must
/// point to at least 12 writable bytes and be four-byte aligned for the word
/// stores. The retail function dereferences both without a NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.vtable_flag_payload_construct")]
#[inline(never)]
pub unsafe extern "C" fn vtable_flag_payload_construct(
    this: *mut u8,
    payload: u32,
) -> *mut u8 {
    let constructed = unsafe { vtable_flag_base_construct(this) };
    unsafe {
        constructed
            .cast::<u32>()
            .write_volatile(VTABLE_FLAG_PAYLOAD_VTABLE_ADDRESS);
        constructed.add(8).cast::<u32>().write_volatile(payload);
    }
    constructed
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    #[repr(C, align(4))]
    struct AlignedBytes([u8; 20]);

    unsafe fn word_at(bytes: *const u8, offset: usize) -> u32 {
        unsafe { bytes.add(offset).cast::<u32>().read() }
    }

    #[test]
    fn default_base_initializes_prefix_and_payload_without_touching_padding() {
        let mut storage = AlignedBytes([0xa5; 20]);
        let object = unsafe { storage.0.as_mut_ptr().add(4) };

        let returned = unsafe { vtable_flag_payload_construct(object, u32::MAX) };

        assert_eq!(returned, object);
        assert_eq!(unsafe { word_at(object, 0) }, VTABLE_FLAG_PAYLOAD_VTABLE_ADDRESS);
        assert_eq!(unsafe { object.add(4).read() }, 0);
        assert_eq!(unsafe { &*object.add(5).cast::<[u8; 3]>() }, &[0xa5; 3]);
        assert_eq!(unsafe { word_at(object, 8) }, u32::MAX);
        assert_eq!(&storage.0[..4], &[0xa5; 4]);
        assert_eq!(&storage.0[16..], &[0xa5; 4]);
    }

    #[test]
    fn byte_derived_constructor_preserves_padding_for_all_state_bytes() {
        use super::super::vtable_flag_payload_byte_construct::{
            vtable_flag_payload_byte_construct, VTABLE_FLAG_PAYLOAD_BYTE_VTABLE_ADDRESS,
        };
        for state in 0..=u8::MAX {
            for payload in [0, u32::MAX, 0x1357_9bdf] {
                let mut storage = AlignedBytes([0xa5; 20]);
                let object = unsafe { storage.0.as_mut_ptr().add(4) };
                let returned = unsafe {
                    vtable_flag_payload_byte_construct(object, payload, state)
                };
                let mut expected = [0xa5; 20];
                expected[4..8].copy_from_slice(
                    &VTABLE_FLAG_PAYLOAD_BYTE_VTABLE_ADDRESS.to_le_bytes(),
                );
                expected[8] = 0;
                expected[12..16].copy_from_slice(&payload.to_le_bytes());
                expected[16] = state;
                assert_eq!(returned, object);
                assert_eq!(storage.0, expected);
            }
        }
    }

}
