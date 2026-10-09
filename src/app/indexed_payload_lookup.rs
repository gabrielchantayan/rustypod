//! Indexed payload lookup and record adapters.

use crate::util::crts_tag::crts_has_tag;
use crate::util::pool_entry_is_live::pool_entry_is_live;
use crate::util::string_pool::PoolEntry;

/// indexed_payload_lookup_backend — `FUN_080d6d94` @ `0x080d6d94`.
///
/// True size: 188 bytes, ending at the next function's push at 0x080d6e50.
/// Raw words verify two unconditional outbound BLs (crts_has_tag and
/// pool_entry_is_live), two inbound plain BLs, and no predicated BLs.
/// Clears length then payload, validates the crts tag and word-12-or-mode,
/// accepts zero as an empty lookup, then checks the signed one-based index
/// against word 7. A live entry supplies blob base plus offset and encoded
/// length; invalid lookups return -50.
///
/// Deliberate deviations: target pointer fields remain u32 on hosts, while
/// payload outputs use native pointers. Address addition wraps at 32 bits.
///
/// # Safety
/// Non-NULL index must be aligned and readable through word 12 if tagged.
/// Word 2 and word 4 hold target addresses of table/blob address handles.
/// These handles and the selected entry must be readable on paths using them.
/// Optional outputs must be writable and not alias input storage.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_payload_lookup_backend(
    index: *mut u8,
    entry: u32,
    mode: u32,
    payload_out: *mut *mut u8,
    encoded_length_out: *mut u32,
) -> u32 {
    if !encoded_length_out.is_null() { encoded_length_out.write(0); }
    if !payload_out.is_null() { payload_out.write(core::ptr::null_mut()); }
    let words = index.cast::<u32>();
    if crts_has_tag(words) == 0 || (words.add(12).read() | mode) == 0 {
        return (-50i32) as u32;
    }
    if entry == 0 { return 0; }
    if (entry as i32) < 0 || (entry as i32) > words.add(7).read() as i32 {
        return (-50i32) as u32;
    }
    let handle = words.add(2).read() as usize as *const u32;
    let table = handle.read() as usize as *const PoolEntry;
    let selected = table.add((entry - 1) as usize);
    if pool_entry_is_live(selected) == 0 { return (-50i32) as u32; }
    if !payload_out.is_null() {
        let blob = words.add(4).read() as usize as *const u32;
        payload_out.write(blob.read().wrapping_add((*selected).blob_offset) as usize as *mut u8);
    }
    if !encoded_length_out.is_null() { encoded_length_out.write((*selected).length as u32); }
    0
}

/// indexed_payload_lookup — original: `FUN_0809e3d0` @ `0x0809e3d0` (24 bytes).
/// Calls the ported backend with mode zero; its original single BL and ABI
/// argument shuffle are represented by a direct five-argument call.
///
/// Looks up `entry` through `index` with the backend's mode forced to zero.
/// `payload_out`, `encoded_length_out`, and the backend status are forwarded
/// unchanged.
///
/// # Safety
///
/// The backend owns all pointer validity requirements. This function has no
/// NULL guards; its output pointers may be NULL only if the backend accepts
/// NULL output pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_payload_lookup(
    index: *mut u8,
    entry: u32,
    payload_out: *mut *mut u8,
    encoded_length_out: *mut u32,
) -> u32 {
    indexed_payload_lookup_backend(index, entry, 0, payload_out, encoded_length_out)
}

/// indexed_payload_equals — `FUN_080ce690` @ `0x080ce690` (76 bytes).
///
/// Raw ARM ends at the next function's push at 0x080ce6dc. Two outbound
/// plain BLs call indexed_payload_lookup and byte_ranges_equal; no predicated
/// BLs. Two inbound plain BLs occur in the indexed candidate search.
/// Returns one only for a successful lookup whose encoded length equals
/// `len` and whose bytes equal `bytes`. Length is not shifted or decoded.
///
/// Deliberate deviations: output locals use native host pointer width.
/// No algorithmic deviations; failed lookup and unequal length skip all
/// comparison reads, and entry zero with length zero compares no bytes.
///
/// # Safety
/// `index` must satisfy indexed_payload_lookup's input requirements.
/// On successful equal-length lookup, `bytes` and the returned payload
/// must be readable for `len` bytes; NULL is allowed when len is zero.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_payload_equals(
    index: *mut u8,
    entry: u32,
    bytes: *const u8,
    len: u32,
) -> u32 {
    let mut payload = core::ptr::null_mut();
    let mut encoded_length = len;
    if indexed_payload_lookup(index, entry, &mut payload, &mut encoded_length) != 0
        || encoded_length != len {
        return 0;
    }
    u32::from(crate::libc::byte_ranges_equal::byte_ranges_equal(bytes, payload, len) != 0)
}
/// `record_metadata_lookup` — original: `FUN_0805572c` @ `0x0805572c` (56 bytes).
///
/// Raw ARM establishes the exact extent `0x0805572c..0x08055764`: the next
/// `mov r2, r1` at `0x08055764` begins the separately entered wrapper. Four
/// inbound direct calls are unconditional plain `bl`; none are predicated.
///
/// # Algorithm
///
/// Load the record's index pointer from word 0 and its metadata entry from
/// word 11, look up that entry at index offset `0x118`, then halve the
/// optional encoded-length result in place. The backend status remains in
/// `r0` and is returned unchanged.
///
/// # Deliberate deviations
///
/// The record's target ABI fields are read as 32-bit words rather than host
/// pointers, preserving their four-byte offsets on 64-bit host tests. The
/// ported [`indexed_payload_lookup`] backend supplies the lookup.
///
/// # Safety
///
/// `record` must point to at least twelve readable target words and word zero
/// must be a valid index base for the backend. Optional output pointers obey
/// the backend's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_metadata_lookup(
    record: *const u32,
    payload_out: *mut *mut u8,
    encoded_length_out: *mut u32,
) -> u32 {
    let index_base = core::ptr::read(record) as usize as *mut u8;
    let entry = core::ptr::read(record.add(11));
    let status = indexed_payload_lookup(index_base.add(0x118), entry, payload_out, encoded_length_out);

    if !encoded_length_out.is_null() {
        encoded_length_out.write(encoded_length_out.read() >> 1);
    }

    status
}
/// `record_indexed_payload_lookup_at_0x118_word15` — original:
/// `FUN_08055810` @ `0x08055810` (56 bytes).
///
/// Raw ARM establishes the exact extent `0x08055810..0x08055848`: the next
/// `mov r2, r1` at `0x08055848` begins a separately entered wrapper. Three
/// inbound direct calls are unconditional plain `bl`; none are predicated.
///
/// # Algorithm
///
/// Load the record's index pointer from word 0 and entry from word 15, look
/// up that entry at index offset `0x118`, then halve the optional
/// encoded-length result in place. The backend status remains in `r0` and is
/// returned unchanged.
///
/// # Deliberate deviations
///
/// The record's target ABI fields are read as 32-bit words rather than host
/// pointers, preserving their four-byte offsets on 64-bit host tests. The
/// ported [`indexed_payload_lookup`] backend supplies the lookup.
///
/// # Safety
///
/// `record` must point to at least sixteen readable target words and word
/// zero must be a valid index base for the backend. Optional output pointers
/// obey the backend's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_indexed_payload_lookup_at_0x118_word15(
    record: *const u32,
    payload_out: *mut *mut u8,
    encoded_length_out: *mut u32,
) -> u32 {
    let index_base = core::ptr::read(record) as usize as *mut u8;
    let entry = core::ptr::read(record.add(15));
    let status = indexed_payload_lookup(index_base.add(0x118), entry, payload_out, encoded_length_out);

    if !encoded_length_out.is_null() {
        encoded_length_out.write(encoded_length_out.read() >> 1);
    }

    status
}


/// `record_indexed_payload_lookup_at_0x1c8` — original: `FUN_080556e0` @
/// `0x080556e0` (56 bytes).
///
/// Raw ARM establishes the exact extent `0x080556e0..0x08055718`: the next
/// `mov r2, r1` starts a separately entered wrapper. The target has four
/// inbound direct calls, all unconditional plain `bl`; there are no
/// predicated calls.
///
/// # Algorithm
///
/// Load the record's index pointer from word 0 and entry from word 13, look up
/// that entry at index offset `0x1c8`, then halve the optional encoded-length
/// result in place. The backend status remains in `r0` and is returned
/// unchanged.
///
/// # Deliberate deviations
///
/// The record's target ABI fields are read as 32-bit words rather than host
/// pointers, preserving their four-byte offsets on 64-bit host tests. The
/// ported [`indexed_payload_lookup`] backend supplies the lookup.
///
/// # Safety
///
/// `record` must point to at least fourteen readable target words and word
/// zero must be a valid index base for the backend. Optional output pointers
/// obey the backend's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_indexed_payload_lookup_at_0x1c8(
    record: *const u32,
    payload_out: *mut *mut u8,
    encoded_length_out: *mut u32,
) -> u32 {
    let index_base = core::ptr::read(record) as usize as *mut u8;
    let entry = core::ptr::read(record.add(13));
    let status = indexed_payload_lookup(index_base.add(0x1c8), entry, payload_out, encoded_length_out);

    if !encoded_length_out.is_null() {
        encoded_length_out.write(encoded_length_out.read() >> 1);
    }

    status
}
/// `record_indexed_payload_lookup_at_0x278` — original: `FUN_080559c0` @
/// `0x080559c0` (56 bytes).
///
/// Raw ARM establishes the exact extent `0x080559c0..0x080559f8`: the next
/// `mov r2, r1` at `0x080559f8` starts a separately entered wrapper. Three
/// inbound direct calls are unconditional plain `bl`; none are predicated.
///
/// # Algorithm
///
/// Load the record's index pointer from word 0 and its metadata entry from
/// word 16, look up that entry at index offset `0x278`, then halve the
/// optional encoded-length result in place. The backend status remains in
/// `r0` and is returned unchanged.
///
/// # Deliberate deviations
///
/// The record's target ABI fields are read as 32-bit words rather than host
/// pointers, preserving their four-byte offsets on 64-bit host tests. The
/// ported [`indexed_payload_lookup`] backend supplies the lookup.
///
/// # Safety
///
/// `record` must point to at least seventeen readable target words and word
/// zero must be a valid index base for the backend. Optional output pointers
/// obey the backend's contract.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_indexed_payload_lookup_at_0x278(
    record: *const u32,
    payload_out: *mut *mut u8,
    encoded_length_out: *mut u32,
) -> u32 {
    let index_base = core::ptr::read(record) as usize as *mut u8;
    let entry = core::ptr::read(record.add(16));
    let status = indexed_payload_lookup(index_base.add(0x278), entry, payload_out, encoded_length_out);

    if !encoded_length_out.is_null() {
        encoded_length_out.write(encoded_length_out.read() >> 1);
    }

    status
}



/// indexed_payload_lookup_mode_one — original: `FUN_080d6e50` @ `0x080d6e50`
/// (24 bytes).
///
/// Raw ARM establishes the exact extent `0x080d6e50..0x080d6e68`; the
/// following `push {r4-r8,lr}` begins a separate function. The wrapper is:
///
/// ```text
/// 080d6e50  push {r3, lr}
/// 080d6e54  str  r3, [sp]
/// 080d6e58  mov  r3, r2
/// 080d6e5c  mov  r2, #1
/// 080d6e60  bl   0x080d6d94
/// 080d6e64  pop  {ip, pc}
/// ```
///
/// Decoding every ARM B/BL immediate in `osos.dec` finds exactly six inbound
/// direct call sites, all unconditional plain `bl` at `0x0804437c`,
/// `0x080443d0`, `0x08044448`, `0x0804449c`, `0x080444f0`, and
/// `0x083d64b8`; there are no predicated calls or tail branches.
///
/// # Algorithm
///
/// Move the third ABI argument to the fourth argument register, put the
/// original fourth argument in the fifth stack slot, force the third argument
/// of `0x080d6d94` to one, then return that backend's status unchanged.
///
/// # Deliberate deviations
///
/// Calls the ported backend directly; the ABI shuffle becomes a Rust call.
///
/// # Safety
///
/// The backend owns all pointer validity requirements. This function has no
/// NULL guards; its output pointers may be NULL only if the backend accepts
/// NULL output pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_payload_lookup_mode_one(
    index: *mut u8,
    entry: u32,
    payload_out: *mut *mut u8,
    encoded_length_out: *mut u32,
) -> u32 {
    indexed_payload_lookup_backend(index, entry, 1, payload_out, encoded_length_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use crate::util::crts_tag::CRTS_TAG;
    use core::ptr;


    #[test]
    fn equality_requires_success_exact_encoded_length_and_all_bytes() {
        unsafe {
            let Some(slab) = try_map_u32_slab(hints::INDEXED_PAYLOAD_EQUALS, 4096) else {
                note_missing_u32_fixture("indexed_payload_equals");
                return;
            };
            let w = slab.cast::<u32>();
            ptr::write_bytes(w, 0, 1024);
            w.write(CRTS_TAG);
            w.add(2).write(w.add(16) as usize as u32);
            w.add(4).write(w.add(17) as usize as u32);
            w.add(7).write(1);
            w.add(12).write(1);
            w.add(16).write(w.add(32) as usize as u32);
            w.add(17).write(slab.add(256) as usize as u32);
            w.add(32).write(0);
            w.add(33).write(4);
            ptr::copy_nonoverlapping([7u8, 0, 9, 255].as_ptr(), slab.add(256), 4);
            let index = slab;
            let mut candidate = [7u8, 0, 9, 255];
            assert_eq!(indexed_payload_equals(index, 1, candidate.as_ptr(), 4), 1);
            for i in 0..4 {
                candidate[i] ^= 1;
                assert_eq!(indexed_payload_equals(index, 1, candidate.as_ptr(), 4), 0);
                candidate[i] ^= 1;
            }
            // Unreadable comparison input proves both short-circuit paths.
            for len in [0, 2, 3, 5, u32::MAX] {
                assert_eq!(indexed_payload_equals(index, 1, ptr::null(), len), 0);
            }
            for entry in [2, u32::MAX, 0x8000_0000] {
                assert_eq!(indexed_payload_equals(index, entry, ptr::null(), 4), 0);
            }
            assert_eq!(indexed_payload_equals(index, 0, ptr::null(), 0), 1);
            assert_eq!(indexed_payload_equals(index, 0, ptr::null(), 1), 0);
            w.add(33).write(0);
            assert_eq!(indexed_payload_equals(index, 1, ptr::null(), 0), 0);
            w.add(33).write(4);
            w.add(32).write(0x8000_0000);
            assert_eq!(indexed_payload_equals(index, 1, ptr::null(), 4), 0);
            w.write(0);
            assert_eq!(indexed_payload_equals(index, 0, ptr::null(), 0), 0);
            assert_eq!(indexed_payload_equals(ptr::null_mut(), 0, ptr::null(), 0), 0);
        }
    }
    #[test]
    fn signed_indices_modes_live_entries_and_optional_outputs() {
        unsafe {
            let Some(slab) = try_map_u32_slab(hints::INDEXED_PAYLOAD_BACKEND, 4096) else {
                note_missing_u32_fixture("indexed_payload_lookup_backend");
                return;
            };
            let w = slab.cast::<u32>();
            ptr::write_bytes(w, 0, 1024);
            w.write(CRTS_TAG);
            w.add(2).write(w.add(16) as usize as u32);
            w.add(4).write(w.add(17) as usize as u32);
            w.add(7).write(2);
            w.add(12).write(1);
            w.add(16).write(w.add(32) as usize as u32);
            w.add(17).write(0xffff_fff0);
            w.add(32).write(0x30);
            w.add(33).write(7);
            w.add(34).write(0);
            w.add(35).write(1);
            let index = w.cast::<u8>();
            for (entry, status, address, length) in [
                (0, 0, 0, 0), (1, 0, 0x20, 7), (2, 0, 0xffff_fff0, 1),
                (3, 0xffff_ffce, 0, 0), (u32::MAX, 0xffff_ffce, 0, 0),
                (0x8000_0000, 0xffff_ffce, 0, 0),
            ] {
                let mut payload = 1usize as *mut u8;
                let mut len = 99;
                assert_eq!(indexed_payload_lookup(index, entry, &mut payload, &mut len), status);
                assert_eq!(payload as usize, address);
                assert_eq!(len, length);
            }
            for (offset, length) in [(0x8000_0000, 1), (0, 0), (0, u32::MAX)] {
                w.add(32).write(offset);
                w.add(33).write(length);
                let mut payload = 1usize as *mut u8;
                let mut len = 99;
                assert_eq!(indexed_payload_lookup(index, 1, &mut payload, &mut len), 0xffff_ffce);
                assert!(payload.is_null());
                assert_eq!(len, 0);
            }
            w.add(12).write(0);
            assert_eq!(indexed_payload_lookup(index, 0, ptr::null_mut(), ptr::null_mut()), 0xffff_ffce);
            assert_eq!(indexed_payload_lookup_mode_one(index, 0, ptr::null_mut(), ptr::null_mut()), 0);
            w.add(32).write(0);
            w.add(33).write(1);
            w.add(4).write(0); // Omitted payload must not read the blob handle.
            let mut len = 99;
            assert_eq!(indexed_payload_lookup_backend(index, 1, 0x8000_0000, ptr::null_mut(), &mut len), 0);
            assert_eq!(len, 1);
            w.add(7).write(u32::MAX);
            assert_eq!(indexed_payload_lookup_mode_one(index, 1, ptr::null_mut(), ptr::null_mut()), 0xffff_ffce);
            w.write(0);
            assert_eq!(indexed_payload_lookup_mode_one(index, 0, ptr::null_mut(), ptr::null_mut()), 0xffff_ffce);
            let mut payload = 1usize as *mut u8;
            assert_eq!(indexed_payload_lookup_mode_one(ptr::null_mut(), 0, &mut payload, &mut len), 0xffff_ffce);
            assert!(payload.is_null());
            assert_eq!(len, 0);
        }
    }
}
