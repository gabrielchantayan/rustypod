//! Controller context notification byte — `FUN_080515f4` @ `0x080515f4`.
//!
//! True extent: 12 bytes, `0x080515f4..0x08051600`. Raw A32 words are
//! e5900f00 (ldr r0,[r0,#0xf00]), e5d00b78 (ldrb r0,[r0,#0xb78]),
//! e12fff1e (bx lr); the next function begins with e92d4fff (push).
//! Whole-image aligned decoding finds two plain inbound BLs at 0x08173504
//! and 0x08173518, zero predicated inbound BLs, and zero outgoing calls.
//! Load the controller's four-byte context pointer and return its unsigned
//! byte at +0xb78. The notification consumer caches it at +0x8c and notifies
//! on change; finer byte semantics are unknown. Deliberate deviations: none.
//! Stored pointers retain target width on hosts; neither pointer is guarded.

/// Return the context byte observed by the controller notification consumer.
///
/// # Safety
/// `controller` must be aligned and readable at +0xf00. That u32 must encode
/// a valid context pointer with a readable byte at +0xb78.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn controller_context_notification_byte(controller: *const u32) -> u32 {
    let context = unsafe { controller.add(0xf00 / 4).read() };
    unsafe { (context as usize as *const u8).add(0xb78).read() as u32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_extends_every_byte_follows_context_and_preserves_storage() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::CONTROLLER_CONTEXT_NOTIFICATION_BYTE, 8192,
        ) else {
            crate::testing::note_missing_u32_fixture("app::controller_context_notification_byte");
            return;
        };
        let mut controller = [0xa5a5_a5a5u32; 0xf08 / 4];
        unsafe {
            let contexts = core::slice::from_raw_parts_mut(slab, 8192);
            contexts.fill(0xff);
            for value in 0..=255u32 {
                let offset = (value as usize % 2) * 4096;
                contexts[offset + 0xb78] = value as u8;
                // The other context must not accidentally satisfy the assertion.
                contexts[(4096 - offset) + 0xb78] = !value as u8;
                controller[0xf00 / 4] = slab.add(offset) as usize as u32;
                let controller_before = controller;
                let contexts_before = contexts.to_vec();
                assert_eq!(controller_context_notification_byte(controller.as_ptr()), value);
                assert_eq!(controller, controller_before);
                assert_eq!(contexts, contexts_before.as_slice());
            }
        }
    }
}
