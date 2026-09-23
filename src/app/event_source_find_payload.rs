//! `event_source_find_payload` — original: `FUN_081e04e4` @ `0x081e04e4`
//! (100 bytes; 1 outbound plain `bl`, 0 predicated outbound `bl` instructions).
//!
//! Raw ARM establishes the extent `0x081e04e4..0x081e0547`: the literal
//! `0x000003f1` at `0x081e0548` follows the final return, and `push {r4,lr}`
//! at `0x081e054c` starts the next function. The sole outbound call is the
//! checked vector accessor `FUN_08184f98` / [`ptr_vector_at`].
//!
//! # Algorithm
//!
//! Scans `entries[0..count)`. An entry matches only when its word at `+4` is
//! the literal tag `0x3f1` and its payload's word at `+0` equals `key`; on a
//! match, writes the payload word at `+4` to `out`. The unused first argument
//! is retained for the retail ABI.
//!
//! # Deliberate deviations
//!
//! The verified vector accessor is called directly through its existing Rust
//! port rather than through a new address seam. The stock `lsl #16; asr #16`
//! index conversion is expressed as an `i16` round-trip.

use crate::util::ptr_vector::ptr_vector_at;

const EVENT_SOURCE_TAG: u32 = 0x3f1;
const ENTRY_TAG_OFFSET: usize = 4;
const ENTRY_PAYLOAD_OFFSET: usize = 8;
const PAYLOAD_KEY_OFFSET: usize = 0;
const PAYLOAD_VALUE_OFFSET: usize = 4;

/// Finds the tagged entry with `key` and writes its payload value to `out`.
///
/// # Safety
///
/// `entries` must be a valid vector owner for [`ptr_vector_at`]. Every
/// inspected entry must be readable through `+8`, and its payload must be
/// readable through `+4`. `out` must be writable when a match exists.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn event_source_find_payload(
    _unused: *const u8,
    entries: *const u8,
    count: u32,
    key: u32,
    out: *mut u32,
) {
    let mut index = 0u32;
    while index < count {
        let entry = ptr_vector_at(entries, (index as i16 as i32) as u32);
        if entry.add(ENTRY_TAG_OFFSET).cast::<u32>().read() == EVENT_SOURCE_TAG {
            let payload = entry.add(ENTRY_PAYLOAD_OFFSET).cast::<u32>().read() as usize as *const u8;
            if payload.add(PAYLOAD_KEY_OFFSET).cast::<u32>().read() == key {
                out.write(payload.add(PAYLOAD_VALUE_OFFSET).cast::<u32>().read());
                return;
            }
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};

    const SLAB_LEN: usize = 0x1000;
    const VECTOR_OFFSET: usize = 0x100;
    const FIRST_ENTRY_OFFSET: usize = 0x200;
    const SECOND_ENTRY_OFFSET: usize = 0x240;
    const FIRST_PAYLOAD_OFFSET: usize = 0x300;
    const SECOND_PAYLOAD_OFFSET: usize = 0x320;

    unsafe fn word(base: *mut u8, offset: usize, value: u32) {
        base.add(offset).cast::<u32>().write(value);
    }

    #[test]
    fn selects_only_a_tagged_entry_with_the_requested_key() {
        let Some(base) = try_map_u32_slab(hints::EVENT_SOURCE_FIND_PAYLOAD, SLAB_LEN) else { return; };
        unsafe {
            base.write_bytes(0, SLAB_LEN);
            let first_entry = base.add(FIRST_ENTRY_OFFSET);
            let second_entry = base.add(SECOND_ENTRY_OFFSET);
            let first_payload = base.add(FIRST_PAYLOAD_OFFSET);
            let second_payload = base.add(SECOND_PAYLOAD_OFFSET);
            base.add(VECTOR_OFFSET).cast::<*mut u8>().write(first_entry);
            base.add(VECTOR_OFFSET + core::mem::size_of::<*mut u8>()).cast::<*mut u8>().write(second_entry);
            word(first_entry, ENTRY_TAG_OFFSET, EVENT_SOURCE_TAG - 1);
            word(first_entry, ENTRY_PAYLOAD_OFFSET, first_payload as u32);
            word(first_payload, PAYLOAD_KEY_OFFSET, 7);
            word(first_payload, PAYLOAD_VALUE_OFFSET, 0x1111_1111);
            word(second_entry, ENTRY_TAG_OFFSET, EVENT_SOURCE_TAG);
            word(second_entry, ENTRY_PAYLOAD_OFFSET, second_payload as u32);
            word(second_payload, PAYLOAD_KEY_OFFSET, 7);
            word(second_payload, PAYLOAD_VALUE_OFFSET, 0x2222_2222);
            let begin = base.add(VECTOR_OFFSET);
            let end = begin.add(2 * core::mem::size_of::<*mut u8>());
            let mut owner = [0u8; 0x24];
            core::ptr::write_unaligned(owner.as_mut_ptr().add(0x14).cast::<*mut u8>(), begin);
            core::ptr::write_unaligned(owner.as_mut_ptr().add(0x1c).cast::<*mut u8>(), end);
            let mut out = 0;
            event_source_find_payload(core::ptr::null(), owner.as_ptr(), 2, 7, &mut out);
            assert_eq!(out, 0x2222_2222);
        }
    }

    #[test]
    fn leaves_output_unchanged_when_no_entry_matches() {
        let Some(base) = try_map_u32_slab(hints::EVENT_SOURCE_FIND_PAYLOAD_NO_MATCH, SLAB_LEN) else { return; };
        unsafe {
            base.write_bytes(0, SLAB_LEN);
            let entry = base.add(FIRST_ENTRY_OFFSET);
            base.add(VECTOR_OFFSET).cast::<*mut u8>().write(entry);
            let payload = base.add(FIRST_PAYLOAD_OFFSET);
            word(entry, ENTRY_TAG_OFFSET, EVENT_SOURCE_TAG);
            word(entry, ENTRY_PAYLOAD_OFFSET, payload as u32);
            word(payload, PAYLOAD_KEY_OFFSET, 8);
            word(payload, PAYLOAD_VALUE_OFFSET, 0x1111_1111);

            let mut owner = [0u8; 0x24];
            let begin = base.add(VECTOR_OFFSET);
            let end = begin.add(core::mem::size_of::<*mut u8>());
            core::ptr::write_unaligned(owner.as_mut_ptr().add(0x14).cast::<*mut u8>(), begin);
            core::ptr::write_unaligned(owner.as_mut_ptr().add(0x1c).cast::<*mut u8>(), end);
            let mut out = 0xa5a5_a5a5;
            event_source_find_payload(core::ptr::null(), owner.as_ptr(), 1, 7, &mut out);
            assert_eq!(out, 0xa5a5_a5a5);
        }
    }
}
