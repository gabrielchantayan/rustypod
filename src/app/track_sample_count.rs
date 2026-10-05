//! Selected track sample count — FUN_081c1ee0 at 0x081c1ee0.
//! True size: 28 bytes [0x081c1ee0, 0x081c1efc); the next function
//! starts with PUSH at 0x081c1efc. Raw whole-image scan: two inbound
//! plain BLs (0x082842c0, 0x082843a8), zero predicated inbound BLs;
//! zero outbound BLs, one conditional tail B to 0x081c8a04.
//!
//! Read the provider's list at +0x1b0, sign-extend the 16-bit selector,
//! and find its track. Return zero for an empty list or missing track;
//! otherwise return the sample-table count at *(track +0x7c) +4.
//! Selectors 0 and -1 fall back to the head on a miss; other negative
//! selectors cannot match the unsigned track IDs.
//!
//! Deliberate deviations: inline the raw-verified tail helper at
//! 0x081c8a04 rather than introduce an unported seam. Reuse the ported
//! list_find_by_id16. Native pointer fields widen host fixtures; target
//! offsets are asserted. No extra null checks for provider/sample table.

use crate::app::track_list_clear::TrackListProvider;
use crate::util::list_find::{list_find_by_id16, IdNode};

#[repr(C)]
pub struct TrackSampleTable {
    pub uniform_sample_size: u32,
    pub sample_count: u32,
}

#[repr(C)]
pub struct SampleCountTrack {
    pub link: IdNode,
    pub opaque_08_to_78: [u32; 29],
    pub sample_table: *const TrackSampleTable,
}

#[cfg(target_os = "none")]
const _: () = {
    assert!(core::mem::offset_of!(TrackListProvider, head) == 0x1b0);
    assert!(core::mem::offset_of!(SampleCountTrack, sample_table) == 0x7c);
    assert!(core::mem::offset_of!(TrackSampleTable, sample_count) == 4);
};

/// # Safety
/// `provider` must be readable, its list must be finite and contain valid
/// track nodes, and a selected node must have a readable sample table.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn track_sample_count(provider: *const TrackListProvider, selector: i16) -> u32 {
    let head = (*provider).head.cast::<IdNode>();
    if head.is_null() { return 0; }
    let track = list_find_by_id16(head, selector as i32 as u32).cast::<SampleCountTrack>();
    if track.is_null() { return 0; }
    (*(*track).sample_table).sample_count
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn selection_and_signed_fallbacks() {
        let tables = [
            TrackSampleTable { uniform_sample_size: 0, sample_count: 17 },
            TrackSampleTable { uniform_sample_size: 99, sample_count: u32::MAX },
            TrackSampleTable { uniform_sample_size: 1, sample_count: 0 },
        ];
        let mut tracks = [
            SampleCountTrack { link: IdNode { next: ptr::null_mut(), id: 7 }, opaque_08_to_78: [0; 29], sample_table: &tables[0] },
            SampleCountTrack { link: IdNode { next: ptr::null_mut(), id: 0 }, opaque_08_to_78: [0; 29], sample_table: &tables[1] },
            SampleCountTrack { link: IdNode { next: ptr::null_mut(), id: 0xffff }, opaque_08_to_78: [0; 29], sample_table: &tables[2] },
        ];
        tracks[0].link.next = &mut tracks[1].link;
        tracks[1].link.next = &mut tracks[2].link;
        let mut provider = TrackListProvider {
            opaque_00: [0; 0x1b0], head: tracks.as_mut_ptr().cast(),
            opaque_after_head: [0; 0x2ba - 0x1b0 - core::mem::size_of::<*mut crate::app::track_list_clear::TrackNode>()],
            selector: 0,
        };
        unsafe {
            assert_eq!(track_sample_count(&provider, 7), 17);
            assert_eq!(track_sample_count(&provider, 0), u32::MAX);
            assert_eq!(track_sample_count(&provider, -1), 17);
            for selector in [1, 8, i16::MAX, i16::MIN, -2] {
                assert_eq!(track_sample_count(&provider, selector), 0);
            }
            tracks[0].link.next = &mut tracks[2].link;
            assert_eq!(track_sample_count(&provider, 0), 17);
            tracks[2].link.id = 9;
            assert_eq!(track_sample_count(&provider, 9), 0);
            provider.head = ptr::null_mut();
            for selector in [0, -1, 7, i16::MIN] {
                assert_eq!(track_sample_count(&provider, selector), 0);
            }
        }
    }
}
