//! `video_engine_record_upload` — retailOS `FUN_081bb6f4` @ `0x081bb6f4`.
//! True body: 148 bytes through `0x081bb784`; 12 bytes of literals follow,
//! then the next real function starts at `0x081bb794` (160-byte extent).
//! Verified calls: two plain outbound BLs and two predicated BLs (BLEQ to
//! 0x082d1438, BLNE to 0x082d0cb8); two plain inbound BLs at 0x0828ca9c
//! and 0x0828cb00, no predicated inbound BLs.
//!
//! Initialize a zero word-0 handle through the existing opaque dispatcher,
//! reload it, and bind selector 0x8892 only when its cached handle changes.
//! Upload count * words_per_item * 4 bytes with wrapping target arithmetic:
//! equal old/new count uses the offset-zero dispatcher, otherwise the other
//! dispatcher receives usage word 0x88e4. Clear record word 1 and store count
//! and words_per_item in words 2 and 3 after dispatch. Word 4 is untouched.
//!
//! Deliberate deviations: resident operations retain their existing opaque
//! identities; no allocation or graphics API meaning is invented. Host builds
//! replace the firmware cache at 0x089d00c4 with a private word. Rust uses
//! explicit volatile word accesses across opaque callbacks and ignores the
//! incidental final r0 = 0, consistent with the callers' void contract.

use super::video_engine::video_engine_set_selector_value;
use super::video_engine_dispatch_opaque_two_words_d0e4::video_engine_dispatch_opaque_two_words_d0e4;
use super::video_engine_dispatch_opaque_four_words::video_engine_dispatch_opaque_four_words;
use super::video_engine_dispatch_opaque_four_words_ce14::video_engine_dispatch_opaque_four_words_ce14;

#[cfg(not(target_os = "none"))]
static mut LAST_HANDLE: u32 = 0;

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn video_engine_record_upload(
    record: *mut u32, data: *const u32, count: u32, words_per_item: u32,
) {
    if record.read_volatile() == 0 {
        video_engine_dispatch_opaque_two_words_d0e4(1, record as usize as u32);
    }
    #[cfg(target_os = "none")]
    let last_handle = 0x089d_00c4 as *mut u32;
    #[cfg(not(target_os = "none"))]
    let last_handle = core::ptr::addr_of_mut!(LAST_HANDLE);
    let handle = record.read_volatile();
    if handle != last_handle.read_volatile() {
        last_handle.write_volatile(handle);
        video_engine_set_selector_value(0x8892, handle);
    }
    let bytes = count.wrapping_mul(words_per_item).wrapping_mul(4);
    let data = data as usize as u32;
    if record.add(2).read_volatile() == count {
        video_engine_dispatch_opaque_four_words(0x8892, 0, bytes, data);
    } else {
        video_engine_dispatch_opaque_four_words_ce14(0x8892, bytes, data, 0x88e4);
    }
    record.add(1).write_volatile(0);
    record.add(2).write_volatile(count);
    record.add(3).write_volatile(words_per_item);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use super::super::video_engine::{LOCK, set_mock_instance, set_mock_set_selector_value};
    use super::super::video_engine_dispatch_opaque_two_words_d0e4::set_mock_dispatch as set_init;
    use super::super::video_engine_dispatch_opaque_four_words::set_mock_dispatch as set_update;
    use super::super::video_engine_dispatch_opaque_four_words_ce14::set_mock_dispatch as set_replace;

    static mut RECORD: *mut u32 = core::ptr::null_mut();
    static mut EVENTS: std::vec::Vec<(u32, u32)> = std::vec::Vec::new();
    static mut EXPECTED: (u32, u32, u32) = (0, 0, 0);

    unsafe extern "C" fn initialize(_: *mut u8, count: u32, address: u32) {
        assert_eq!((count, address), (1, RECORD as usize as u32));
        (*core::ptr::addr_of_mut!(EVENTS)).push((0, 0));
        RECORD.write(0x1234);
    }
    unsafe extern "C" fn bind(_: *mut u8, selector: u32, handle: u32) {
        assert_eq!((selector, handle), (0x8892, RECORD.read()));
        assert_eq!(LAST_HANDLE, handle); // Cache is committed before dispatch.
        (*core::ptr::addr_of_mut!(EVENTS)).push((1, handle));
    }
    unsafe fn uploaded(kind: u32, bytes: u32, data: u32) {
        assert_eq!((bytes, data), (EXPECTED.0, EXPECTED.1));
        assert_eq!(RECORD.add(1).read(), 0xdead_beef); // Not cleared early.
        assert_eq!(RECORD.add(2).read(), EXPECTED.2);
        (*core::ptr::addr_of_mut!(EVENTS)).push((kind, bytes));
        RECORD.add(1).write(99);
        RECORD.add(2).write(99);
        RECORD.add(3).write(99);
    }
    unsafe extern "C" fn update(_: *mut u8, selector: u32, offset: u32, bytes: u32, data: u32) {
        assert_eq!((selector, offset), (0x8892, 0));
        uploaded(2, bytes, data);
    }
    unsafe extern "C" fn replace(_: *mut u8, selector: u32, bytes: u32, data: u32, usage: u32) {
        assert_eq!((selector, usage), (0x8892, 0x88e4));
        uploaded(3, bytes, data);
    }

    #[test]
    fn initialization_cache_count_selection_and_wrapping_size() {
        let _guard = LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::VIDEO_ENGINE_RECORD_UPLOAD, 0x1000) else { return; };
        let mut engine = [0u8; 16];
        unsafe {
            RECORD = slab.cast();
            set_mock_instance(engine.as_mut_ptr());
            set_init(Some(initialize));
            set_mock_set_selector_value(Some(bind));
            set_update(Some(update));
            set_replace(Some(replace));
            LAST_HANDLE = 0;
            // Count equality alone selects update, even when words/item changes.
            // Overflow and zero dimensions must not panic or bypass dispatch.
            for (handle, old_count, count, words, events) in [
                (0, 0, 4u32, 2u32, std::vec![(0, 0), (1, 0x1234), (3, 32)]),
                (0x1234, 4, 4, 3, std::vec![(2, 48)]),
                (0x5678, 4, 0, 7, std::vec![(1, 0x5678), (3, 0)]),
                (0x5678, 0, 0x8000_0001, 3, std::vec![(3, 12)]),
                (0x5678, 5, 5, 0, std::vec![(2, 0)]),
            ] {
                RECORD.write(handle);
                RECORD.add(1).write(0xdead_beef);
                RECORD.add(2).write(old_count);
                RECORD.add(3).write(77);
                RECORD.add(4).write(0xcafe);
                (*core::ptr::addr_of_mut!(EVENTS)).clear();
                EXPECTED = (count.wrapping_mul(words).wrapping_mul(4), 0x1234_5678, old_count);
                video_engine_record_upload(RECORD, 0x1234_5678usize as *const u32, count, words);
                assert_eq!(&*core::ptr::addr_of!(EVENTS), &events);
                assert_eq!(RECORD.read(), if handle == 0 { 0x1234 } else { handle });
                assert_eq!(core::slice::from_raw_parts(RECORD.add(1), 4), &[0, count, words, 0xcafe]);
            }
            set_init(None);
            set_mock_set_selector_value(None);
            set_update(None);
            set_replace(None);
            set_mock_instance(core::ptr::null_mut());
        }
    }
}
