//! FreeType SFNT table-directory lookup.
//!
//! The table records are the 16-byte `TT_TableRec` directory entries carried
//! by a TrueType face. The face stores the directory pointer in a target-width
//! word, so host tests map the complete fixture below 4 GiB.

use crate::ft::trace::ft_error_trace;

/// The `TT_FaceRec` prefix consumed by [`tt_face_lookup_table`]. On ARM,
/// `num_tables` is at `+0x98` and `table_records` is the raw target pointer at
/// `+0x9c`.
#[repr(C)]
pub struct TtFace {
    _prefix: [u32; 38],
    pub num_tables: u16,
    _table_padding: u16,
    pub table_records: u32,
}

/// A 16-byte SFNT table-directory entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TtTableRecord {
    pub tag: u32,
    pub check_sum: u32,
    pub offset: u32,
    pub length: u32,
}

static TABLE_LOOKUP: &[u8] = b"tt_face_lookup_table: %p, %c%c%c%c --\0";
static FOUND_TABLE: &[u8] = b"found table.\n\0";
static MISSING_TABLE: &[u8] = b"could not find table!\n\0";

#[cfg(target_os = "none")]
unsafe fn trace_level() -> i32 {
    core::ptr::read_volatile((0x08b2_0a24usize) as *const i32)
}

#[cfg(not(target_os = "none"))]
static mut HOST_TRACE_LEVEL: i32 = 0;

#[cfg(not(target_os = "none"))]
unsafe fn trace_level() -> i32 {
    core::ptr::addr_of!(HOST_TRACE_LEVEL).read_volatile()
}

fn signed_tag_byte(tag: u32, shift: u32) -> u32 {
    ((tag >> shift) as u8 as i8 as i32) as u32
}

/// tt_face_lookup_table (FreeType `tt_face_lookup_table`, ttpload.c) —
/// original: `FUN_080bb7d4` @ `0x080bb7d4` (172 instruction bytes, followed
/// by its 4-byte trace-level literal at `0x080bb880`; Ghidra incorrectly
/// reports 168 bytes).
///
/// With trace level `> 3`, logs the face and the tag's four signed character
/// bytes, then linearly scans `num_tables` 16-byte directory entries. It
/// returns the first entry whose tag matches and whose `length` word is
/// nonzero; matching zero-length entries are skipped. A missing match logs
/// the failure and returns NULL; a found entry logs the success and returns
/// that entry. Seven call sites were verified by decoding every ARM B/BL word
/// in `osos.dec`: all are unconditional `bl` at `0x0808b690`, `0x0808b6a4`,
/// `0x0808c08c`, `0x0808c0a0`, `0x0808c0b4`, `0x0809cd8c`, and `0x080a9f8c`.
///
/// On target the trace gate reads the original `0x08b209dc + 0x48` state
/// word. Host builds use a test-only model of that unmapped firmware word.
/// The shared `ft_error_trace` port exposes only the register-passed r0-r3
/// slots, so an installed host trace sink cannot observe this lookup's final
/// two stacked `%c` arguments; these are the deliberate trace-only deviations.
///
/// # Safety
/// `face` must point to a valid `TtFace`. When `num_tables` is nonzero,
/// `table_records` must be a valid target-width pointer to at least that many
/// `TtTableRecord` entries.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tt_face_lookup_table")]
pub unsafe extern "C" fn tt_face_lookup_table(face: *mut TtFace, tag: u32) -> *mut TtTableRecord {
    if trace_level() > 3 {
        ft_error_trace(
            TABLE_LOOKUP.as_ptr(),
            face as usize as u32,
            signed_tag_byte(tag, 24),
            signed_tag_byte(tag, 16),
        );
    }

    let mut record = (*face).table_records as usize as *mut TtTableRecord;
    let end = record.wrapping_add((*face).num_tables as usize);
    while (record as usize) < (end as usize) {
        if (*record).tag == tag && (*record).length != 0 {
            if trace_level() > 3 {
                ft_error_trace(FOUND_TABLE.as_ptr(), 0, 0, 0);
            }
            return record;
        }
        record = record.wrapping_add(1);
    }

    if trace_level() > 3 {
        ft_error_trace(MISSING_TABLE.as_ptr(), 0, 0, 0);
    }
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::ft::trace::{capture, TEST_TRACE_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::LazyLock;
    use parking_lot::Mutex;

    const FIXTURE_LEN: usize = 4096;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::TT_FACE_LOOKUP, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn fixture() -> Option<(*mut TtFace, *mut TtTableRecord)> {
        let base = (*FIXTURE)? as *mut u8;
        let face = base.cast::<TtFace>();
        let records = base.add(core::mem::size_of::<TtFace>()).cast::<TtTableRecord>();
        core::ptr::write_bytes(base, 0, FIXTURE_LEN);
        Some((face, records))
    }

    unsafe fn set_host_trace_level(level: i32) {
        core::ptr::addr_of_mut!(HOST_TRACE_LEVEL).write_volatile(level);
    }

    #[test]
    fn returns_first_nonempty_matching_record() {
        let _fixture_guard = FIXTURE_LOCK.lock();
        let Some((face, records)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("ft/sfnt tt_face_lookup_table"));
            return;
        };
        unsafe {
            records.add(0).write(TtTableRecord { tag: u32::from_be_bytes(*b"head"), check_sum: 1, offset: 0, length: 0 });
            records.add(1).write(TtTableRecord { tag: u32::from_be_bytes(*b"cmap"), check_sum: 2, offset: 12, length: 20 });
            records.add(2).write(TtTableRecord { tag: u32::from_be_bytes(*b"cmap"), check_sum: 3, offset: 32, length: 30 });
            face.write(TtFace {
                _prefix: [0; 38],
                num_tables: 3,
                _table_padding: 0,
                table_records: records as usize as u32,
            });
            set_host_trace_level(0);
            assert_eq!(tt_face_lookup_table(face, u32::from_be_bytes(*b"cmap")), records.add(1));
            assert!(tt_face_lookup_table(face, u32::from_be_bytes(*b"head")).is_null());
        }
    }

    #[test]
    fn empty_directory_returns_null_without_dereferencing_records() {
        let _fixture_guard = FIXTURE_LOCK.lock();
        let Some((face, _)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("ft/sfnt tt_face_lookup_table"));
            return;
        };
        unsafe {
            face.write(TtFace {
                _prefix: [0; 38],
                num_tables: 0,
                _table_padding: 0,
                table_records: 0,
            });
            set_host_trace_level(0);
            assert!(tt_face_lookup_table(face, u32::from_be_bytes(*b"name")).is_null());
        }
    }

    #[test]
    fn trace_gate_logs_probe_and_outcome() {
        let _fixture_guard = FIXTURE_LOCK.lock();
        let _trace_guard = TEST_TRACE_LOCK.lock().unwrap();
        let Some((face, records)) = (unsafe { fixture() }) else {
            assert!(note_missing_u32_fixture("ft/sfnt tt_face_lookup_table"));
            return;
        };
        let tag = u32::from_be_bytes([0xff, 0x80, b'a', b'b']);
        let (found_calls, missing_calls) = unsafe {
            records.write(TtTableRecord { tag, check_sum: 0, offset: 0, length: 1 });
            face.write(TtFace {
                _prefix: [0; 38],
                num_tables: 1,
                _table_padding: 0,
                table_records: records as usize as u32,
            });
            set_host_trace_level(4);
            capture::start();
            assert_eq!(tt_face_lookup_table(face, tag), records);
            let found_calls = capture::finish();
            capture::start();
            assert!(tt_face_lookup_table(face, u32::from_be_bytes(*b"name")).is_null());
            let missing_calls = capture::finish();
            set_host_trace_level(0);
            (found_calls, missing_calls)
        };
        assert_eq!(found_calls.len(), 2);
        assert_eq!(unsafe { capture::formats(&found_calls) }, ["tt_face_lookup_table: %p, %c%c%c%c --", "found table.\n"]);
        assert_eq!(found_calls[0].args, [face as usize as u32, u32::MAX, 0xffff_ff80]);
        assert_eq!(missing_calls.len(), 2);
        assert_eq!(unsafe { capture::formats(&missing_calls) }, ["tt_face_lookup_table: %p, %c%c%c%c --", "could not find table!\n"]);
    }
}
