//! `message_payload_buffer` — original: `FUN_08257bc4` @ 0x08257bc4
//! (8 bytes; true extent 0x08257bc4..0x08257bcb; the next independently
//! entered function starts with `push {r4,r5,r6,lr}` @ 0x08257bcc). Three
//! plain `bl` call sites (0x081d7210, 0x081d7228, 0x081d7ebc), zero
//! predicated `bl` call sites, verified by decoding every aligned A32 branch
//! instruction in `osos.dec`.
//!
//! Returns the payload-buffer word at offset `+0x0c` of the 16-byte nested
//! UI-message payload constructed by `FUN_08257bcc`: that constructor stores
//! zero for an empty payload or the allocated, copied byte buffer otherwise.
//! The retail body is exactly `ldr r0,[r0,#0xc]; bx lr`. The API returns the
//! target word as `u32`, rather than a host pointer, so the ARM field layout is
//! preserved on 64-bit host tests. No deliberate behavioral deviations.

/// Reads the nested UI-message payload's owned byte-buffer word.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn message_payload_buffer(payload: *const u32) -> u32 {
    *payload.add(3)
}

#[cfg(test)]
mod tests {
    use super::message_payload_buffer;

    #[test]
    fn message_payload_buffer_reads_offset_0xc_for_empty_and_allocated_payloads() {
        for buffer in [0u32, 1, 0x0800_0000, 0x2200_0000, 0xffff_ffff] {
            let payload = [0x0898_0744, 0x500, 0x10, buffer];
            assert_eq!(unsafe { message_payload_buffer(payload.as_ptr()) }, buffer);
        }
    }

    #[test]
    fn message_payload_buffer_ignores_preceding_payload_fields() {
        let mut payload = [0u32, 0, 0, 0x1234_5678];
        assert_eq!(unsafe { message_payload_buffer(payload.as_ptr()) }, 0x1234_5678);
        payload[..3].copy_from_slice(&[0xffff_ffff, 0x501, 0xffff_ffff]);
        assert_eq!(unsafe { message_payload_buffer(payload.as_ptr()) }, 0x1234_5678);
    }
}
