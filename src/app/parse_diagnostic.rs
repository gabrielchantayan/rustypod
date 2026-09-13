//! `parse_diagnostic_construct` — original: `FUN_0826fcf4` @ **0x0826fcf4**
//! (28 bytes, `0x0826fcf4..0x0826fd10`; the separately linked destructor
//! starts at `0x0826fd10`).
//!
//! Decoding every ARM `B`/`BL` immediate in `osos.dec` finds six direct inbound
//! `bl` sites — all unconditional: `0x08119300`, `0x081196bc`, `0x08119724`,
//! `0x08119b18`, `0x08119b58`, and `0x0812e070`; no direct tail `b` reaches
//! this constructor. The call sites build parse diagnostics for malformed data,
//! oversized notes, undefined anchors, and incomplete tags.
//!
//! # Algorithm
//!
//! Store the diagnostic kind byte, source start, and source end. Then
//! default-construct the embedded [`StringObject`] message at word three and
//! return the original diagnostic pointer. The three bytes after `kind` are
//! deliberately untouched, matching the stock `strb` followed by `stmib`.
//!
//! # Deliberate deviations
//!
//! None. `message` is raw two-word `StringObject` storage rather than a nested
//! [`StringObject`], so this target-layout record remains 20 bytes on hosts
//! where Rust pointers are wider than retailOS pointers.

use crate::cxx::string_object::{string_default_construct, StringObject};

/// Target-layout parser diagnostic. The embedded message is a two-word
/// [`StringObject`] at +0x0c on retailOS.
#[repr(C)]
pub struct ParseDiagnostic {
    /// +0x00 — diagnostic category used to select the displayed error text.
    pub kind: u8,
    /// +0x01..+0x03 — untouched by the constructor.
    pub padding: [u8; 3],
    /// +0x04 — start of the source span.
    pub start: u32,
    /// +0x08 — end of the source span.
    pub end: u32,
    /// +0x0c — raw storage for the diagnostic's `StringObject` message.
    pub message: [u32; 2],
}

const _: [(); 20] = [(); core::mem::size_of::<ParseDiagnostic>()];

/// Initializes a parser diagnostic and its embedded empty message.
///
/// # Safety
///
/// `out` must point to a writable, 20-byte target-layout [`ParseDiagnostic`].
/// The embedded message storage must be valid for [`string_default_construct`].
/// As in retailOS, `out` is dereferenced without a NULL guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parse_diagnostic_construct(
    out: *mut ParseDiagnostic,
    kind: u8,
    start: u32,
    end: u32,
) -> *mut ParseDiagnostic {
    core::ptr::addr_of_mut!((*out).kind).write(kind);
    core::ptr::addr_of_mut!((*out).start).write(start);
    core::ptr::addr_of_mut!((*out).end).write(end);
    let message = core::ptr::addr_of_mut!((*out).message).cast::<StringObject>();
    string_default_construct(message).cast::<u32>().sub(3).cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::string_object::STRING_OBJECT_VTABLE;

    #[repr(align(8))]
    struct Fixture([u8; 40]);

    #[test]
    fn initializes_a_diagnostic_without_touching_its_padding() {
        // Offset +4 makes the diagnostic word-aligned while its +12 message is
        // 8-aligned for the host's wider StringObject pointers.
        let mut fixture = Fixture([0xa5; 40]);
        let out = unsafe { fixture.0.as_mut_ptr().add(4).cast::<ParseDiagnostic>() };
        unsafe {
            out.write(ParseDiagnostic {
                kind: 0xff,
                padding: [0x11, 0x22, 0x33],
                start: u32::MAX,
                end: 0,
                message: [u32::MAX; 2],
            });
        }

        let returned = unsafe {
            parse_diagnostic_construct(out, 0x14, 0x0123_4567, 0x89ab_cdef)
        };

        assert_eq!(returned, out, "the stock constructor rebases r0 after the message ctor");
        assert_eq!(fixture.0[4], 0x14, "kind is the lone byte store");
        assert_eq!(&fixture.0[5..8], &[0x11, 0x22, 0x33], "padding survives the stores");
        assert_eq!(&fixture.0[8..12], &0x0123_4567u32.to_le_bytes());
        assert_eq!(&fixture.0[12..16], &0x89ab_cdefu32.to_le_bytes());

        let message = unsafe { fixture.0.as_ptr().add(16).cast::<StringObject>() };
        assert!(core::ptr::eq(unsafe { (*message).vtable }, &STRING_OBJECT_VTABLE));
        assert!(unsafe { (*message).payload }.is_null());
        assert_eq!(fixture.0[32..], [0xa5; 8], "the host fixture has no overrun");
    }

    #[test]
    fn accepts_error_callsite_values_and_reinitializes_the_message() {
        let mut fixture = Fixture([0; 40]);
        let out = unsafe { fixture.0.as_mut_ptr().add(4).cast::<ParseDiagnostic>() };
        unsafe {
            out.write(ParseDiagnostic {
                kind: 0,
                padding: [0xa1, 0xb2, 0xc3],
                start: 0,
                end: 0,
                message: [0; 2],
            });
            parse_diagnostic_construct(out, 0x13, 0, 0);
        }

        assert_eq!(unsafe { (*out).kind }, 0x13, "Bad data call site category");
        assert_eq!(unsafe { (*out).start }, 0);
        assert_eq!(unsafe { (*out).end }, 0);
        assert_eq!(unsafe { (*out).padding }, [0xa1, 0xb2, 0xc3]);
        let message = unsafe { fixture.0.as_ptr().add(16).cast::<StringObject>() };
        assert!(core::ptr::eq(unsafe { (*message).vtable }, &STRING_OBJECT_VTABLE));
        assert!(unsafe { (*message).payload }.is_null());
    }
}
