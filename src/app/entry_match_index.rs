//! Index word of a matchable entry on a `'liti'`-holding container.
//!
//! - `entry_match_index` — original: `FUN_08051400` @ 0x08051400
//!   (32 bytes; 5 direct `bl` call sites, 0 predicated BL, 0 plain-`b`
//!   tail callers, verified by decoding every B/BL word in `osos.dec`).

/// Byte offset of the per-entry index word (`ldrne r0,[r0,#0xc]`).
const INDEX_OFFSET: usize = 0xc;

/// Error code returned for a NULL entry (`mvneq r0,#0xbf`).
const ERR_NULL_ENTRY: u32 = 0xbf;

/// entry_match_index — original: `FUN_08051400` @ 0x08051400 (32 bytes).
///
/// Raw ARM decoded from `work/firmware/osos.dec` @
/// `0x08051400..0x08051420`; the next function begins with the same
/// `cmp r0, #0; mvneq r0, #0xbf` prologue at `0x08051420`, confirming
/// Ghidra's 32-byte extent:
///
/// ```text
/// 08051400  cmp r0, #0
/// 08051404  mvneq r0, #0xbf
/// 08051408  bxeq lr
/// 0805140c  cmp r1, #0
/// 08051410  ldrne r0, [r0, #0xc]
/// 08051414  strne r0, [r1, #0x0]
/// 08051418  mov r0, #0
/// 0805141c  bx lr
/// ```
///
/// Algorithm: NULL `entry` returns error `0xbf` and leaves `out_index`
/// untouched. Otherwise, when `out_index` is non-NULL, store the entry's
/// word at +0x0c through it; return zero either way. The +0x0c word is the
/// entry's matchable-list index: caller 0x0826f8f0 iterates while the
/// fetched word is at most a caller bound, 0x0826f998 selects the first
/// entry whose word exceeds a bound, 0x0826fa6c collects the words into a
/// vector, and 0x081a8cf4 continues its walk while the container's word at
/// +0x18 equals the fetched word plus one (consecutive indices).
///
/// Call sites: 5 unconditional `bl` (0x081a8d2c, 0x081a8e80, 0x0826f938,
/// 0x0826f9e4, 0x0826faf8). Deliberate deviations: none. Ghidra's reference
/// C shows the NULL-entry return as `0xffffff40`; the raw word is
/// `mov r0, #0xbf` (0x03e000bf, plain MOV), so the port returns 191.
///
/// # Safety
///
/// `entry` may be NULL. A non-NULL pointer must be four-byte aligned and
/// readable through +0x0f. `out_index` may be NULL; a non-NULL pointer must
/// be valid for a four-byte aligned write.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.entry_match_index")]
pub unsafe extern "C" fn entry_match_index(entry: *const u8, out_index: *mut u32) -> u32 {
    if entry.is_null() {
        return ERR_NULL_ENTRY;
    }
    if !out_index.is_null() {
        unsafe { out_index.write(entry.add(INDEX_OFFSET).cast::<u32>().read()) };
    }
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn null_entry_returns_error_and_leaves_out_untouched() {
        let mut out = 0xdead_beefu32;
        assert_eq!(unsafe { entry_match_index(core::ptr::null(), &mut out) }, ERR_NULL_ENTRY);
        assert_eq!(out, 0xdead_beef);
        assert_eq!(
            unsafe { entry_match_index(core::ptr::null(), core::ptr::null_mut()) },
            ERR_NULL_ENTRY
        );
    }

    #[test]
    fn null_out_returns_zero_without_reading_past_the_entry() {
        // A one-word entry: index at +0xc is word 3, outside this object.
        // NULL out must not touch it, so the read is never performed.
        let entry = [0u32; 1];
        assert_eq!(
            unsafe { entry_match_index(entry.as_ptr().cast(), core::ptr::null_mut()) },
            0
        );
    }

    #[test]
    fn fetches_index_word_and_returns_zero() {
        let entry = [0x11u32, 0x22, 0x33, 0x44];
        for index in [0, 1, 0x0804_7bfc, u32::MAX] {
            let mut entry = entry;
            entry[INDEX_OFFSET / core::mem::size_of::<u32>()] = index;
            let mut out = 0u32;
            assert_eq!(unsafe { entry_match_index(entry.as_ptr().cast(), &mut out) }, 0);
            assert_eq!(out, index);
        }
    }
}
