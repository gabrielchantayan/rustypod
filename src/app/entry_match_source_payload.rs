//! Payload word of an opaque entry-match source.

/// entry_match_source_payload — original: `FUN_0826fb44` @ **0x0826fb44**
/// (8 bytes; Ghidra's 24-byte extent incorrectly includes the following
/// `matched_entry_select_nth` function at 0x0826fb4c).
///
/// Raw ARM establishes the two-instruction extent `0x0826fb44..0x0826fb4c`:
/// `ldr r0, [r0, #4]` then `b 0x080514d0`. The tail target returns zero for a
/// null first-level word and otherwise loads its word at `+0x0c`; this port
/// expresses that verified combined operation without assigning an identity to
/// the unported tail target. There are exactly four inbound direct plain `bl`
/// sites (0x0812f9e0, 0x081b765c, 0x081f8fc8, 0x08211648), zero predicated
/// `bl` sites, and no outbound `bl` instructions.
///
/// Algorithm: load the target-width collection word from `source + 4`; return
/// zero when it is null, otherwise return the target-width payload word from
/// the collection at `+0x0c`.
///
/// Deliberate deviation: the retail tail branch is inlined so the Rust export
/// does not require a seam or an invented name for 0x080514d0.
///
/// # Safety
///
/// `source` must be four-byte aligned and readable through `+0x07`. Its
/// target-width word at `+0x04` is either zero or a four-byte-aligned address
/// readable through `+0x0f`. These are unchecked retail contracts.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.entry_match_source_payload")]
pub unsafe extern "C" fn entry_match_source_payload(source: *const u8) -> u32 {
    let collection = unsafe { source.add(4).cast::<u32>().read() } as *const u8;
    if collection.is_null() {
        0
    } else {
        unsafe { collection.add(12).cast::<u32>().read() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    extern crate std;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    const FIXTURE_LEN: usize = 0x1000;
    const SOURCE_OFFSET: usize = 0x100;
    const COLLECTION_OFFSET: usize = 0x200;
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::ENTRY_MATCH_SOURCE_PAYLOAD, FIXTURE_LEN).map(|pointer| pointer as usize)
    });
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    fn fixture() -> Option<(*mut u8, *mut u8)> {
        let base = (*FIXTURE)? as *mut u8;
        unsafe { base.write_bytes(0, FIXTURE_LEN) };
        Some((unsafe { base.add(SOURCE_OFFSET) }, unsafe { base.add(COLLECTION_OFFSET) }))
    }

    #[test]
    fn returns_zero_for_a_null_collection_word() {
        let _guard = FIXTURE_LOCK.lock();
        let Some((source, _)) = fixture() else {
            assert!(note_missing_u32_fixture("app/entry_match_source_payload"));
            return;
        };

        assert_eq!(unsafe { entry_match_source_payload(source) }, 0);
    }

    #[test]
    fn returns_the_nested_payload_word() {
        let _guard = FIXTURE_LOCK.lock();
        let Some((source, collection)) = fixture() else {
            assert!(note_missing_u32_fixture("app/entry_match_source_payload"));
            return;
        };
        unsafe {
            source.add(4).cast::<u32>().write(collection as usize as u32);
            collection.add(12).cast::<u32>().write(0xdecafbad);
        }

        assert_eq!(unsafe { entry_match_source_payload(source) }, 0xdecafbad);
    }
}
