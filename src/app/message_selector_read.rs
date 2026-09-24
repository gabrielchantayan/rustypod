//! `message_selector_read` — original: `FUN_080f68e8` @ `0x080f68e8`.
//!
//! **12 bytes** (`0x080f68e8..0x080f68f3`); `push {r4-r10,lr}` at
//! `0x080f68f4` begins the next real function. Raw A32 has no outbound plain
//! or predicated `bl`. Decoding every A32 direct-call word finds three inbound
//! plain `bl` calls at `0x081d6788`, `0x081d7114`, and `0x081d7164`, and zero
//! predicated `bl` calls.
//!
//! # Algorithm
//!
//! Read the 32-bit target pointer from `message + 4`, then return the first
//! 32-bit word at that target.
//!
//! Deliberate deviations: none. The pointer field remains a target-width
//! `u32`, independent of host pointer width; retailOS does not check either
//! pointer for null or alignment.

/// Read a message's selector word through its target-width pointer field.
///
/// # Safety
///
/// `message + 4` must be readable and four-byte aligned, and its `u32` value
/// must identify another readable, four-byte-aligned word. Neither pointer may
/// be null.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn message_selector_read(message: *const u8) -> u32 {
    let selector = unsafe { message.add(4).cast::<u32>().read() } as usize as *const u32;
    unsafe { selector.read() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn reads_each_selector_value_through_the_word_sized_pointer_field() {
        let Some(slab) = try_map_u32_slab(hints::MESSAGE_SELECTOR_READ, 16) else {
            if note_missing_u32_fixture("app/message_selector_read") {
                return;
            }
            unreachable!();
        };
        let selector = unsafe { slab.add(8).cast::<u32>() };
        unsafe {
            slab.add(4).cast::<u32>().write(selector as usize as u32);
            selector.write(0);
        }
        assert_eq!(unsafe { message_selector_read(slab) }, 0);

        unsafe { selector.write(u32::MAX) };
        assert_eq!(unsafe { message_selector_read(slab) }, u32::MAX);
    }
}
