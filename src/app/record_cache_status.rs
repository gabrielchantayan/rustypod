//! `record_cache_status` — `FUN_08284348` at load address `0x08284348`.
//! True size: 64 bytes (`0x08284348..0x08284388`); the next real function
//! is the independent STRB/BX flag setter. Whole-image ARM word decoding
//! verifies two inbound plain BLs (0x081a1ad8, 0x081a1f4c), zero predicated
//! BLs, and one outbound plain BL at 0x08284364 to 0x081c3894.
//!
//! Return 1 for a null provider, 2 when the provider lacks the selected
//! record, otherwise 3 for a zero cache flag and 4 for any nonzero flag.
//! The selector is loaded unsigned here, then sign-extended by the callee.
//! Raw 0x081c3894 reads the list at provider +0x1b0 and tails to 0x081c8a20,
//! which normalizes list_find_by_id16's result. Selectors 0 and -1 therefore
//! accept any nonempty list; other negative selectors cannot match u16 IDs.
//!
//! Deliberate deviation: ARM calls the unported predicate at its original
//! address. Host builds use its raw-code equivalent with native IdNode
//! pointers, while the source retains its existing target-width layout.

use crate::app::opaque_record_source_item_count::OpaqueRecordSource;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn provider_has_selected_record(provider: u32, selector: u16) -> u32 {
    let predicate: unsafe extern "C" fn(*const u8, u32) -> u32 =
        core::mem::transmute(0x081c_3894usize);
    predicate(provider as usize as *const u8, selector as u32)
}

#[cfg(not(target_os = "none"))]
unsafe fn provider_has_selected_record(provider: u32, selector: u16) -> u32 {
    use crate::util::list_find::{list_find_by_id16, IdNode};
    let head = ((provider as usize as *const u8).add(0x1b0)
        as *const *mut IdNode).read();
    (!list_find_by_id16(head, selector as i16 as i32 as u32).is_null()) as u32
}

/// Classifies the source's provider/selector and cache byte without mutation.
///
/// # Safety
/// `source` must be aligned readable source storage. A nonzero provider must
/// be valid for retailOS 0x081c3894 (host: native list pointer at +0x1b0).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn record_cache_status(source: *const OpaqueRecordSource) -> u32 {
    let provider = (*source).provider;
    if provider == 0 {
        return 1;
    }
    if provider_has_selected_record(provider, (*source).selector as u16) == 0 {
        return 2;
    }
    if (*source).opaque_18 == 0 { 3 } else { 4 }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use crate::util::list_find::IdNode;

    #[test]
    fn status_precedence_and_signed_selector_boundaries() {
        let mut source = OpaqueRecordSource {
            provider: 0, opaque_04_to_14: [0xa5a5_a5a5; 5],
            opaque_18: 0xff, opaque_19: 0x77, selector: -1,
        };
        assert_eq!(unsafe { record_cache_status(&source) }, 1);
        let Some(provider) = try_map_u32_slab(hints::RECORD_CACHE_STATUS, 0x1000) else {
            assert!(note_missing_u32_fixture("app::record_cache_status"));
            return;
        };
        source.provider = provider as usize as u32;
        let head_slot = unsafe { provider.add(0x1b0).cast::<*mut IdNode>() };
        let mut tail = IdNode { next: core::ptr::null_mut(), id: 0x7fff };
        let mut head = IdNode { next: &mut tail, id: 0xffff };
        for has_list in [false, true] {
            unsafe { head_slot.write(if has_list { &mut head } else { core::ptr::null_mut() }); }
            for (selector, matches) in [(0, true), (-1, true), (0x7fff, true),
                                       (1, false), (i16::MIN, false), (-2, false)] {
                source.selector = selector;
                for flag in [0, 1, 0x80, 0xff] {
                    source.opaque_18 = flag;
                    let expected = if !has_list || !matches { 2 }
                                   else if flag == 0 { 3 } else { 4 };
                    assert_eq!(unsafe { record_cache_status(&source) }, expected,
                               "list={has_list}, selector={selector}, flag={flag}");
                    assert_eq!(source.opaque_04_to_14, [0xa5a5_a5a5; 5]);
                    assert_eq!(source.opaque_19, 0x77);
                }
            }
        }
    }
}
