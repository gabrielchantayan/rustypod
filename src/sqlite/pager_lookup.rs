//! SQLite pager-cache lookup — `sqlite3PagerLookup` from pager.c.
//!
//! `pager_lookup` — original: `FUN_082ddd78` @ 0x082ddd78 (60 bytes; 6
//! direct `bl` call sites, all unconditional).
//!
//! The pager owns a power-of-two page-hash array through `+0xd0`; its bucket
//! count is `+0xcc`. Each `PgHdr` chain node stores its page number at `+0x04`
//! and its next hash link at `+0x08`. This is the direct 3.5.x pager-cache
//! lookup used before inserting a new page and while resolving cached pages.

/// Target-layout word offset of `Pager.nHash`.
const HASH_BUCKET_COUNT: usize = 0xcc / 4;
/// Target-layout word offset of `Pager.apHash`.
const HASH_BUCKETS: usize = 0xd0 / 4;
/// Target-layout word offset of `PgHdr.pgno`.
const PAGE_NUMBER: usize = 0x04 / 4;
/// Target-layout word offset of `PgHdr.pNextHash`.
const NEXT_HASH_PAGE: usize = 0x08 / 4;

/// `pager_lookup` — original: `FUN_082ddd78` @ 0x082ddd78 (60 bytes; 6 `bl`
/// call sites, all unconditional).
///
/// Returns the cached pager page for `page_number`, or NULL. It returns NULL
/// before reading the hash count when `pager->apHash` is NULL; otherwise it
/// selects `apHash[(nHash - 1) & page_number]` and walks `pNextHash` until the
/// page-number word matches. There are no NULL or zero-count guards beyond the
/// bucket-array check, matching the ARM body. No deliberate deviations.
///
/// # Safety
/// `pager` must point to the 32-bit target-layout `Pager`; when its `+0xd0`
/// bucket pointer is nonzero, `+0xcc` must be a nonzero power of two and the
/// selected bucket and each linked `PgHdr` must be readable target-layout
/// objects.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pager_lookup(pager: *const u32, page_number: u32) -> *mut u32 {
    let buckets = unsafe { pager.add(HASH_BUCKETS).read() } as usize as *const u32;
    if buckets.is_null() {
        return core::ptr::null_mut();
    }

    let bucket = unsafe { pager.add(HASH_BUCKET_COUNT).read() }.wrapping_sub(1) & page_number;
    let mut page = unsafe { buckets.add(bucket as usize).read() } as usize as *mut u32;
    while !page.is_null() && unsafe { page.add(PAGE_NUMBER).read() } != page_number {
        page = unsafe { page.add(NEXT_HASH_PAGE).read() } as usize as *mut u32;
    }
    page
}

#[cfg(test)]
mod tests {
    use super::pager_lookup;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn pager_lookup_handles_absent_table_empty_bucket_and_collisions() {
        const FIXTURE_LEN: usize = 0x1000;
        const BUCKETS_OFFSET: usize = 0x200;
        const FIRST_PAGE_OFFSET: usize = 0x300;
        const SECOND_PAGE_OFFSET: usize = 0x340;

        let Some(base) = try_map_u32_slab(hints::SQLITE_PAGER_LOOKUP, FIXTURE_LEN) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };

        unsafe {
            let pager = base.cast::<u32>();
            let buckets = base.add(BUCKETS_OFFSET).cast::<u32>();
            let first_page = base.add(FIRST_PAGE_OFFSET).cast::<u32>();
            let second_page = base.add(SECOND_PAGE_OFFSET).cast::<u32>();

            // nHash = 4 makes page 6 select bucket 2, not a modulo-derived bucket.
            pager.add(0xcc / 4).write(4);
            pager.add(0xd0 / 4).write(buckets as usize as u32);
            buckets.add(2).write(first_page as usize as u32);
            first_page.add(0x04 / 4).write(2);
            first_page.add(0x08 / 4).write(second_page as usize as u32);
            second_page.add(0x04 / 4).write(6);
            second_page.add(0x08 / 4).write(0);

            assert_eq!(pager_lookup(pager, 6), second_page, "walks past a colliding head");
            assert_eq!(pager_lookup(pager, 10), core::ptr::null_mut(), "returns NULL at a chain end");
            assert_eq!(pager_lookup(pager, 1), core::ptr::null_mut(), "returns NULL for an empty bucket");

            pager.add(0xd0 / 4).write(0);
            assert_eq!(pager_lookup(pager, 6), core::ptr::null_mut(), "NULL apHash returns before a bucket read");
        }
    }
}
