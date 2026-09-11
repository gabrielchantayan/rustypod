//! `tagged_payload_address` — original: `FUN_082b513c` @ `0x082b513c`
//! (24 bytes; `0x082b513c..0x082b5154`).
//!
//! Raw ARM is `ldr r2,[r1]; tst r2,#0x400; ldreq r0,[r0]; ldreq r1,[r1,#8];
//! addeq r0,r0,r1; bx lr`. The descriptor's bit `0x400` selects the address
//! of the context slot itself; otherwise this leaf loads the context slot's
//! payload base and adds the descriptor's +0x08 payload offset. There are no
//! NULL guards in either path. The next separately linked function begins at
//! `0x082b5154`, so the 24-byte extent is exact.
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds exactly nine inbound
//! direct calls, all unconditional plain `bl` (0x0803ac8c, 0x0803ae54,
//! 0x0803afc0, 0x0803b19c, 0x0803b2b4, 0x0803b348, 0x080c86b0,
//! 0x080c879c, and 0x080d3c30); there are no predicated calls and no aligned
//! image data word references. No deliberate deviations.

/// Descriptor fields read by [`tagged_payload_address`].
///
/// Only `flags` (+0x00) and `payload_offset` (+0x08) are touched. The middle
/// word exists to preserve the firmware layout.
#[repr(C)]
pub struct TaggedPayloadDescriptor {
    pub flags: u32,
    pub unknown_04: u32,
    pub payload_offset: u32,
}

/// Bit selecting the context-slot address rather than its relative payload.
pub const TAGGED_PAYLOAD_CONTEXT_SLOT: u32 = 0x400;

/// tagged_payload_address — original: `FUN_082b513c` @ `0x082b513c`
/// (24 bytes; 9 direct plain-`bl` call sites).
///
/// Returns `context_slot` when `descriptor->flags` has bit `0x400`; otherwise
/// returns `*context_slot + descriptor->payload_offset`. The flagged path
/// deliberately does not dereference `context_slot`, exactly as the ARM
/// predicated loads skip both `ldr`s.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_payload_address")]
#[inline(never)]
pub unsafe extern "C" fn tagged_payload_address(
    context_slot: *mut *mut u8,
    descriptor: *const TaggedPayloadDescriptor,
) -> *mut u8 {
    if (*descriptor).flags & TAGGED_PAYLOAD_CONTEXT_SLOT != 0 {
        context_slot.cast()
    } else {
        (*context_slot).wrapping_add((*descriptor).payload_offset as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_the_context_slot_for_the_tagged_form_without_reading_its_payload() {
        let descriptor = TaggedPayloadDescriptor {
            flags: TAGGED_PAYLOAD_CONTEXT_SLOT | 0x23,
            unknown_04: 0xa5a5_a5a5,
            payload_offset: 0xffff_ffff,
        };
        let context_slot = 0x1234_5678usize as *mut *mut u8;

        assert_eq!(
            unsafe { tagged_payload_address(context_slot, &descriptor) },
            context_slot.cast(),
        );
    }

    #[test]
    fn returns_the_relative_payload_for_every_non_tagged_flag_pattern() {
        let mut payload = [0u8; 32];
        let mut base = payload.as_mut_ptr();

        for (flags, payload_offset) in [(0, 0), (1, 3), (0x800, 17), (u32::MAX & !0x400, 31)] {
            let descriptor = TaggedPayloadDescriptor { flags, unknown_04: 0, payload_offset };
            assert_eq!(
                unsafe { tagged_payload_address(&mut base, &descriptor) },
                payload.as_mut_ptr().wrapping_add(payload_offset as usize),
                "flags={flags:#x}",
            );
        }
    }
}
