//! Constructing a StringObject through an opaque vtable slot.
//!
//! - `string_construct_from_vtable_slot_50` — original: `FUN_082a37a4` @
//!   `0x082a37a4` (**36 bytes**, exact: nine ARM instructions through
//!   `0x082a37c4`; the separately linked sibling begins at `0x082a37c8`).
//!   **8 direct `bl` call sites**, all unconditional plain `bl`, with zero
//!   predicated forms and zero direct `b` references, verified by decoding
//!   every ARM immediate `B`/`BL` word in `osos.dec`.
//!
//! Default-constructs `out` with `string_default_construct`, then tail-dispatches
//! `source` through its vtable's opaque `+0x50` slot as `slot(source, out)`.
//! There is no NULL guard. The slot's concrete identity and return value are not
//! established; every direct caller discards the wrapper's return register, so
//! this port preserves the observed void interface without naming the callee.
//!
//! # Deliberate deviations
//!
//! On the 64-bit host, the vtable's opaque words and slot are native-width so a
//! fixture can call the slot directly. `repr(C)` makes their spacing exactly
//! one target word on the 32-bit firmware. The virtual method remains a raw
//! dispatch rather than a speculative semantic seam.

use crate::cxx::string_object::{string_default_construct, StringObject};

/// Opaque `+0x50` string-writing virtual method.
pub type StringSlot50Write = unsafe extern "C" fn(*mut StringSlot50Source, *mut StringObject);

/// Vtable prefix consumed by [`string_construct_from_vtable_slot_50`].
///
/// The function only reads its word at `+0x50`; the preceding entries remain
/// intentionally unnamed.
#[repr(C)]
pub struct StringSlot50SourceVtable {
    /// `+0x00..+0x4c`: opaque virtual entries.
    pub opaque_00_4c: [usize; 20],
    /// `+0x50`: writes a representation of `source` into `out`.
    pub write_string: StringSlot50Write,
}

/// Vtable-headed object accepted by the wrapper.
#[repr(C)]
pub struct StringSlot50Source {
    /// `+0x00`: pointer to [`StringSlot50SourceVtable`].
    pub vtable: *const StringSlot50SourceVtable,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x50] = [0; core::mem::offset_of!(StringSlot50SourceVtable, write_string)];

/// string_construct_from_vtable_slot_50 — original: `FUN_082a37a4` @
/// `0x082a37a4` (36 bytes, exact extent `0x082a37a4..0x082a37c4`; 8 direct
/// unconditional `bl` callers, binary-verified).
///
/// Constructs `out`, then invokes `source`'s opaque vtable slot `+0x50` as
/// `slot(source, out)`. Both pointers are dereferenced without validation,
/// matching the original. The branch to the virtual method is a tail branch;
/// its return register is unobserved by all direct callers.
///
/// # Safety
///
/// `out` must designate writable [`StringObject`] storage. `source` must point
/// to an object with a readable vtable and a callable `+0x50` slot. The slot
/// owns any further validity requirements for `source` and `out`.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.string_construct_from_vtable_slot_50")]
#[inline(never)]
pub unsafe extern "C" fn string_construct_from_vtable_slot_50(
    out: *mut StringObject,
    source: *mut StringSlot50Source,
) {
    let out = string_default_construct(out);
    let write_string = (*(*source).vtable).write_string;
    write_string(source, out);
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;

    static mut SLOT_CALLS: usize = 0;
    static mut OBSERVED_SOURCE: *mut StringSlot50Source = ptr::null_mut();
    static mut PAYLOAD_BYTE: u8 = 0;

    unsafe extern "C" fn recording_write_string(
        source: *mut StringSlot50Source,
        out: *mut StringObject,
    ) {
        SLOT_CALLS += 1;
        OBSERVED_SOURCE = source;
        assert!(core::ptr::eq((*out).vtable, &STRING_OBJECT_VTABLE));
        assert!((*out).payload.is_null(), "construction precedes virtual dispatch");
        (*out).payload = ptr::addr_of_mut!(PAYLOAD_BYTE);
    }

    static SOURCE_VTABLE: StringSlot50SourceVtable = StringSlot50SourceVtable {
        opaque_00_4c: [0xdead_beef; 20],
        write_string: recording_write_string,
    };

    #[test]
    fn constructs_before_dispatching_the_exact_slot() {
        let mut out = StringObject {
            vtable: ptr::null(),
            payload: ptr::dangling_mut(),
        };
        let mut source = StringSlot50Source { vtable: &SOURCE_VTABLE };

        unsafe {
            SLOT_CALLS = 0;
            OBSERVED_SOURCE = ptr::null_mut();
            string_construct_from_vtable_slot_50(&mut out, &mut source);
            assert_eq!(SLOT_CALLS, 1, "the +0x50 slot runs exactly once");
            assert!(core::ptr::eq(OBSERVED_SOURCE, &mut source));
            assert_eq!(out.payload, ptr::addr_of_mut!(PAYLOAD_BYTE));
        }
    }
}
