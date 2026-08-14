//! The 92-byte retailOS event source object: construction and its kind byte.
//!
//! [`crate::app::event_list`] ports the lazily-built event tree that lives
//! at +0x38 of this object. This module ports the rest of the object: the
//! accessor for its kind byte, and (next) its constructor.
//!
//! # Where the object comes from
//!
//! The factory @ 0x081472b0 is what pins the layout down. Given the view's
//! source registry it queries the application registry (0x0819fe10) for the
//! registry's own id under the ADS key `'SLst'` (0x534c7374 @ 0x0814735c),
//! and for every declaration in the resulting collection it does:
//!
//! ```text
//!     mov  r0, #92          ; operator new(0x5c)  <- the object size
//!     bl   0x082aadd4
//!     ldr  r1, [sp]         ; id          = declaration[0]
//!     and  r2, r1, #255     ; kind        = declaration[1] & 0xff
//!     mov  r3, r4           ; declaration
//!     bl   0x081e0bac       ; the constructor @ 0x081e0bac
//!     str  r6, [r0, #88]    ; source->+0x58 = the owning registry
//!     add  r0, r6, #12      ; registry map, keyed by the same id
//! ```
//!
//! So the constructor's three arguments are the declaration's id word, the
//! low byte of the declaration's second word, and the declaration pointer
//! itself; the caller — not the constructor — fills in +0x58.
//!
//! # Layout
//!
//! | offset | contents |
//! |--------|----------|
//! | +0x00  | vtable pointer, always [`EVENT_SOURCE_VTABLE`] |
//! | +0x04  | declaration pointer (constructor argument 3) |
//! | +0x08  | id / registry lookup value (constructor argument 1) |
//! | +0x0c  | kind byte (constructor argument 2) |
//! | +0x10  | declaration vector: begin / end / capacity |
//! | +0x1c  | 28-byte child collection |
//! | +0x38  | the event tree of [`crate::app::event_list`] |
//! | +0x54  | "event tree is built" flag |
//! | +0x58  | owning source registry |
//! | +0x5c  | end of object |
//!
//! The +0x08 id doubles as the value [`crate::app::event_list`] resolves
//! under `'SEVT'`, which is why that module calls it the primary event.

/// Byte size of the object, from the `operator new(92)` @ 0x081472fc that
/// precedes every heap construction of it.
pub const EVENT_SOURCE_SIZE: usize = 0x5c;

/// The vtable the constructor installs, from its literal pool word at
/// 0x081e0c30 — the word Ghidra drops from the function's extent.
pub const EVENT_SOURCE_VTABLE: u32 = 0x0898_ecb4;

/// Byte offset of the declaration the source was built from.
pub const EVENT_SOURCE_DECLARATION_OFFSET: usize = 0x04;

/// Byte offset of the kind byte returned by [`event_source_kind`].
pub const EVENT_SOURCE_KIND_OFFSET: usize = 0x0c;

/// Byte offset of the 28-byte child collection constructed at +0x1c.
pub const EVENT_SOURCE_CHILDREN_OFFSET: usize = 0x1c;

/// event_source_kind — original: `FUN_081e0ba4` @ 0x081e0ba4 (8 bytes,
/// 52 `bl` call sites, no `b` tail calls; verified by decoding every
/// branch word in osos.dec).
///
/// `ldrb r0, [r0, #12]; bx lr` — the whole function. Not a veneer: a
/// veneer is `ldr pc, [pc, #-4]` plus a target word.
///
/// Returns the kind byte the constructor @ 0x081e0bac stores at +0x0c. Call
/// sites treat it as a small enumeration: the transition state machine @
/// 0x0817f7c0 compares two sources' kinds against 1, 5, 6, 9 and 10 to
/// decide whether a view change animates.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_source_kind(source: *const u8) -> u8 {
    unsafe { source.add(EVENT_SOURCE_KIND_OFFSET).read() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_reads_only_the_byte_at_0x0c() {
        for kind in [0u8, 1, 5, 6, 9, 10, 0xff] {
            let mut source = [0u8; EVENT_SOURCE_SIZE];
            source[EVENT_SOURCE_KIND_OFFSET] = kind;
            source[EVENT_SOURCE_KIND_OFFSET + 1] = !kind;
            assert_eq!(unsafe { event_source_kind(source.as_ptr()) }, kind);
        }
    }
}
