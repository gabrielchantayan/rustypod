//! `current_record_handle` — original: `FUN_0829e1b4` @ `0x0829e1b4`
//! (**36 bytes**, `0x0829e1b4..0x0829e1d8`; the next separately linked function
//! begins at `0x0829e1d8`).
//!
//! Raw ARM decoding establishes the following body:
//!
//! ```text
//! 0829e1b4  mov   r2, r0
//! 0829e1b8  ldr   r1, [r2, #8]
//! 0829e1bc  mov   r0, #0
//! 0829e1c0  cmn   r1, #1
//! 0829e1c4  ldrne r0, [r2, #4]
//! 0829e1c8  addne r1, r1, r1, lsl #2
//! 0829e1cc  addne r0, r0, r1, lsl #2
//! 0829e1d0  ldrne r0, [r0, #4]
//! 0829e1d4  bx    lr
//! ```
//!
//! Decoding every ARM B/BL immediate in `osos.dec` finds eight inbound direct
//! `bl` calls, all unconditional (at `0x081af640`, `0x081c836c`,
//! `0x081c84f4`, `0x081c857c`, `0x081c85fc`, `0x081c86e8`, `0x081c8820`, and
//! `0x081c8908`), with no predicated `bl` calls. `0x0829dd2c` is one direct
//! unconditional tail `b`: its preceding `add r0, r0, #4` adapts a containing
//! object to this cursor layout. No aligned DATA word names this entry.
//!
//! # Algorithm
//!
//! Return zero when `current_index` is the sentinel `-1`; otherwise return the
//! word at `records + current_index * 0x14 + 4`. The index multiplication and
//! address addition use target-width wrapping arithmetic, exactly like the
//! ARM `add` instructions. There is deliberately no cursor, records, or bounds
//! guard: callers only receive a zero result for the `-1` sentinel.

/// The recovered three-word cursor prefix. `records` is a target-width pointer
/// to 20-byte records, so it remains `u32` even on 64-bit host tests.
#[repr(C)]
pub struct CurrentRecordCursor {
    pub opaque_00: u32,
    pub records: u32,
    pub current_index: i32,
}

const _: [u8; 0x00] = [0; core::mem::offset_of!(CurrentRecordCursor, opaque_00)];
const _: [u8; 0x04] = [0; core::mem::offset_of!(CurrentRecordCursor, records)];
const _: [u8; 0x08] = [0; core::mem::offset_of!(CurrentRecordCursor, current_index)];
const _: [u8; 0x0c] = [0; core::mem::size_of::<CurrentRecordCursor>()];

/// The containing object accepted by `current_record_handle_from_owner`.
///
/// The initial word is opaque to the accessor. Its only purpose here is to
/// retain the target's `add r0, r0, #4` adaptation to the embedded cursor.
#[repr(C)]
pub struct CurrentRecordCursorOwner {
    pub opaque_00: u32,
    pub cursor: CurrentRecordCursor,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(CurrentRecordCursorOwner, cursor)];
const _: [u8; 0x10] = [0; core::mem::size_of::<CurrentRecordCursorOwner>()];

/// A recovered 20-byte record. Only its word at `+0x04` is observed here.
#[repr(C)]
pub struct CurrentRecord {
    pub opaque_00: u32,
    pub handle: u32,
    pub opaque_08: u32,
    pub opaque_0c: u32,
    pub opaque_10: u32,
}

const _: [u8; 0x04] = [0; core::mem::offset_of!(CurrentRecord, handle)];
const _: [u8; 0x14] = [0; core::mem::size_of::<CurrentRecord>()];

/// current_record_handle — original: `FUN_0829e1b4` @ `0x0829e1b4` (36 bytes;
/// eight unconditional direct `bl` call sites, binary-scanned).
///
/// Returns the selected 20-byte record's `+0x04` handle, or zero when the
/// cursor's current index is `-1`.
///
/// # Safety
///
/// `cursor` must identify readable, aligned [`CurrentRecordCursor`] storage.
/// Unless `current_index` is `-1`, its `records` word must identify a readable,
/// aligned 32-bit word at `records + current_index * 0x14 + 4`. As in
/// retailOS, no bounds or NULL checks are performed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn current_record_handle(cursor: *const CurrentRecordCursor) -> u32 {
    let index = (*cursor).current_index;
    if index == -1 {
        return 0;
    }

    let record = (*cursor)
        .records
        .wrapping_add((index as u32).wrapping_mul(0x14));
    (record.wrapping_add(4) as usize as *const u32).read()
}

/// current_record_handle_from_owner — original: `FUN_0829dd28` @ `0x0829dd28`
/// (8 bytes; the separately linked next function begins at `0x0829dd30`).
///
/// Raw ARM is `add r0, r0, #4; b 0x0829e1b4`: adapt an owner to its embedded
/// [`CurrentRecordCursor`] and tail-dispatch to [`current_record_handle`].
/// Decoding every immediate ARM branch in `osos.dec` finds seven direct
/// callers, all unconditional `bl` at `0x0820cf6c`, `0x0820d0c8`,
/// `0x0820d390`, `0x0820d41c`, `0x0820d4b0`, `0x0820d5b8`, and `0x0820d610`;
/// no predicated direct call, tail branch, or aligned DATA word names this
/// entry. It returns the embedded cursor's selected handle, or zero for its
/// `-1` index sentinel. No deliberate semantic deviations; the release archive
/// retains a tail branch after the pointer adaptation.
///
/// # Safety
///
/// `owner` must identify readable, aligned [`CurrentRecordCursorOwner`]
/// storage. The embedded cursor inherits [`current_record_handle`]'s records
/// and index validity requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn current_record_handle_from_owner(
    owner: *const CurrentRecordCursorOwner,
) -> u32 {
    current_record_handle(core::ptr::addr_of!((*owner).cursor))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_LEN: usize = 0x1000;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::CURRENT_RECORD_HANDLE, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn records() -> Option<*mut CurrentRecord> {
        let base = (*FIXTURE)? as *mut u8;
        unsafe {
            ptr::write_bytes(base, 0, FIXTURE_LEN);
            Some(base.cast::<CurrentRecord>())
        }
    }

    #[test]
    fn sentinel_index_returns_zero_without_reading_records() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let cursor = CurrentRecordCursor {
            opaque_00: 0,
            records: 0,
            current_index: -1,
        };

        assert_eq!(unsafe { current_record_handle(&cursor) }, 0);
    }

    #[test]
    fn returns_handle_from_selected_twenty_byte_record() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(records) = records() else {
            assert!(note_missing_u32_fixture("app::current_record_handle"));
            return;
        };
        unsafe {
            records.add(0).write(CurrentRecord {
                opaque_00: 0x1111_1111,
                handle: 0xaaaa_aaaa,
                opaque_08: 0,
                opaque_0c: 0,
                opaque_10: 0,
            });
            records.add(2).write(CurrentRecord {
                opaque_00: 0x2222_2222,
                handle: 0xbbbb_bbbb,
                opaque_08: 0,
                opaque_0c: 0,
                opaque_10: 0,
            });
            let cursor = CurrentRecordCursor {
                opaque_00: 0,
                records: records as usize as u32,
                current_index: 2,
            };

            assert_eq!(current_record_handle(&cursor), 0xbbbb_bbbb);
        }
    }

    #[test]
    fn rereads_current_index_and_only_returns_word_at_offset_four() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(records) = records() else {
            assert!(note_missing_u32_fixture("app::current_record_handle"));
            return;
        };
        unsafe {
            records.add(0).write(CurrentRecord {
                opaque_00: 0xaaaa_aaaa,
                handle: 0x0102_0304,
                opaque_08: 0xffff_ffff,
                opaque_0c: 0xfeed_face,
                opaque_10: 0x5555_5555,
            });
            records.add(1).write(CurrentRecord {
                opaque_00: 0xbbbb_bbbb,
                handle: 0x1122_3344,
                opaque_08: 0xeeee_eeee,
                opaque_0c: 0xc001_d00d,
                opaque_10: 0x6666_6666,
            });
            let mut cursor = CurrentRecordCursor {
                opaque_00: 0,
                records: records as usize as u32,
                current_index: 0,
            };

            assert_eq!(current_record_handle(&cursor), 0x0102_0304);
            cursor.current_index = 1;
            assert_eq!(current_record_handle(&cursor), 0x1122_3344);
        }
    }

    #[test]
    fn owner_adapter_preserves_the_sentinel_without_reading_records() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let owner = CurrentRecordCursorOwner {
            opaque_00: 0xfeed_face,
            cursor: CurrentRecordCursor {
                opaque_00: 0x0123_4567,
                records: 0,
                current_index: -1,
            },
        };

        assert_eq!(unsafe { current_record_handle_from_owner(&owner) }, 0);
    }

    #[test]
    fn owner_adapter_reads_the_embedded_cursor_selected_record() {
        let _guard = FIXTURE_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(records) = try_map_u32_slab(hints::OWNER_CURRENT_RECORD_HANDLE, FIXTURE_LEN) else {
            assert!(note_missing_u32_fixture("app::current_record_handle owner"));
            return;
        };
        let records = records as *mut CurrentRecord;

        unsafe {
            ptr::write_bytes(records.cast::<u8>(), 0, FIXTURE_LEN);
            records.add(1).write(CurrentRecord {
                opaque_00: 0x1111_1111,
                handle: 0xc001_d00d,
                opaque_08: 0x2222_2222,
                opaque_0c: 0x3333_3333,
                opaque_10: 0x4444_4444,
            });
            let owner = CurrentRecordCursorOwner {
                opaque_00: 0xaaaa_aaaa,
                cursor: CurrentRecordCursor {
                    opaque_00: 0xbbbb_bbbb,
                    records: records as usize as u32,
                    current_index: 1,
                },
            };

            assert_eq!(current_record_handle_from_owner(&owner), 0xc001_d00d);
        }
    }
}
