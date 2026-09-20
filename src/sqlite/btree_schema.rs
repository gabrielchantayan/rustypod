//! B-tree schema accessor — retailOS `FUN_08371370` at `0x08371370` (16 bytes).
//!
//! Raw ARM establishes the exact extent: `ldr r0,[r0,#4]`, `ldr r0,[r0]`,
//! `ldr r0,[r0,#0x5c]`, `bx lr`; the next separately linked function starts
//! with `push {r3-r9,lr}` at `0x08371380`. Decoding inbound ARM BL immediates
//! finds three direct plain unconditional `bl` call sites and no predicated
//! calls.
//!
//! SQLite 3.5.x's `sqlite3BtreeSchema`: follow `Btree.pBt` at +0x04 and
//! return `BtShared.pSchema` at +0x5c. Deliberate deviation: none. The
//! target-width intermediate pointer is retained as a `u32`, so host pointer
//! width cannot alter either recovered field offset.

/// Target byte offset of `Btree.pBt`.
const BTREE_SHARED_OFFSET: usize = 0x04;
/// Target byte offset of `BtShared.pSchema`.
const SHARED_SCHEMA_OFFSET: usize = 0x5c;

/// btree_schema — original: `FUN_08371370` @ `0x08371370` (16 bytes; 3
/// direct plain-`bl` call sites, no predicated calls).
///
/// Returns the schema pointer stored in `btree`'s shared B-tree.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn btree_schema(btree: *const u8) -> u32 {
    let shared = unsafe { btree.add(BTREE_SHARED_OFFSET).cast::<u32>().read() };
    unsafe { (shared as *const u8).add(SHARED_SCHEMA_OFFSET).cast::<u32>().read() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    const FIXTURE_LEN: usize = 0x1000;
    const SHARED_OFFSET: usize = 0x100;

    fn fixture() -> Option<*mut u8> {
        try_map_u32_slab(hints::BTREE_SCHEMA, FIXTURE_LEN)
    }

    #[test]
    fn returns_the_shared_btree_schema_word_verbatim() {
        let Some(base) = fixture() else {
            assert!(note_missing_u32_fixture("sqlite/btree_schema"));
            return;
        };
        unsafe {
            base.write_bytes(0xa5, FIXTURE_LEN);
            let shared = base.add(SHARED_OFFSET);
            base.add(BTREE_SHARED_OFFSET).cast::<u32>().write(shared as u32);
            shared.add(SHARED_SCHEMA_OFFSET).cast::<u32>().write(0xfeed_beef);
            assert_eq!(btree_schema(base), 0xfeed_beef);
        }
    }

    #[test]
    fn does_not_treat_the_schema_word_as_a_pointer() {
        let Some(base) = fixture() else {
            assert!(note_missing_u32_fixture("sqlite/btree_schema"));
            return;
        };
        unsafe {
            base.write_bytes(0xa5, FIXTURE_LEN);
            let shared = base.add(SHARED_OFFSET);
            base.add(BTREE_SHARED_OFFSET).cast::<u32>().write(shared as u32);
            shared.add(SHARED_SCHEMA_OFFSET).cast::<u32>().write(0);
            assert_eq!(btree_schema(base), 0);
            shared.add(SHARED_SCHEMA_OFFSET).cast::<u32>().write(u32::MAX);
            assert_eq!(btree_schema(base), u32::MAX);
        }
    }

    #[test]
    fn reads_only_the_recovered_pointer_slots() {
        let Some(base) = fixture() else {
            assert!(note_missing_u32_fixture("sqlite/btree_schema"));
            return;
        };
        unsafe {
            base.write_bytes(0xa5, FIXTURE_LEN);
            let shared = base.add(SHARED_OFFSET);
            base.add(BTREE_SHARED_OFFSET).cast::<u32>().write(shared as u32);
            shared.add(SHARED_SCHEMA_OFFSET).cast::<u32>().write(0x1234_5678);
            let before = core::slice::from_raw_parts(base, FIXTURE_LEN).to_vec();
            assert_eq!(btree_schema(base), 0x1234_5678);
            assert_eq!(core::slice::from_raw_parts(base, FIXTURE_LEN), before);
        }
    }
}
