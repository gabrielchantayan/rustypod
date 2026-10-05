//! `opaque_owned_record_cleanup` — retailOS `FUN_081bb7a8` @ `0x081bb7a8`.
//!
//! True extent: 36 bytes, ending at `0x081bb7cc`, the next function's push.
//! Verified calls: two inbound plain BLs, no inbound predicated BLs; zero
//! outbound plain BLs and one BLNE to `0x082d110c`. Other callers tail-branch.
//! If the record's first word is nonzero, dispatch one record address through
//! the existing video-engine two-word dispatcher; always return the original
//! record pointer, including when the dispatcher changes the record.
//! Deliberate deviations: express ARM predication as an ordinary conditional.
//! The dispatcher remains opaque; no resource identity is inferred from C.

use crate::util::video_engine_dispatch_opaque_two_words_ffb4::video_engine_dispatch_opaque_two_words_ffb4;

/// # Safety
/// `record` must point to a readable aligned target-width record, valid for
/// the resident dispatcher when its first word is nonzero. On target its
/// address must fit in a 32-bit word.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn opaque_owned_record_cleanup(record: *mut u32) -> *mut u32 {
    if record.read() != 0 {
        video_engine_dispatch_opaque_two_words_ffb4(1, record as usize as u32);
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use crate::util::video_engine::{LOCK, set_mock_instance};
    use crate::util::video_engine_dispatch_opaque_two_words_ffb4::set_mock_dispatch;

    unsafe extern "C" fn clear_record(_engine: *mut u8, count: u32, address: u32) {
        assert_eq!(count, 1);
        (address as usize as *mut u32).write(0);
    }

    #[test]
    fn zero_skips_dispatch_and_nonzero_preserves_dispatcher_mutation() {
        let _guard = LOCK.lock();
        let record = try_map_u32_slab(hints::OPAQUE_OWNED_RECORD_CLEANUP, 0x1000)
            .expect("cleanup fixture must fit in a target word").cast::<u32>();
        let mut engine = [0u8; 16];
        unsafe {
            set_mock_instance(engine.as_mut_ptr());
            set_mock_dispatch(None);
            record.write(0);
            record.add(1).write(0x1234_5678);
            assert_eq!(opaque_owned_record_cleanup(record), record);
            assert_eq!(record.read(), 0);
            set_mock_dispatch(Some(clear_record));
            for value in [1, 0x8000_0000, u32::MAX] {
                record.write(value);
                assert_eq!(opaque_owned_record_cleanup(record), record);
                assert_eq!(record.read(), 0);
                assert_eq!(record.add(1).read(), 0x1234_5678);
            }
            set_mock_instance(core::ptr::null_mut());
            record.write(u32::MAX);
            assert_eq!(opaque_owned_record_cleanup(record), record);
            assert_eq!(record.read(), u32::MAX);
            set_mock_dispatch(None);
        }
    }
}
