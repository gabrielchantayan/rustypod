//! `tagged_object_link` — original: `FUN_0805bc34` @ 0x0805bc34 (196 bytes).
//!
//! The independently entered sibling at 0x0805bcf8 follows the `pop` at
//! 0x0805bcf4, so the raw extent is exactly 0x0805bc34..0x0805bcf4. Decoding
//! every ARM B/BL word in `osos.dec` finds 12 direct call sites: 11
//! unconditional `bl` instructions and one `blne` at 0x080e5c24. The
//! predicated caller first checks whether its optional target is non-null;
//! this routine itself performs no such optional-target policy and instead
//! returns -50 when either tag check fails.
//!
//! # Algorithm
//!
//! Validate the source's `0x4d536e64` tag and the target's `0x4d526376` tag
//! plus its nonzero word at +0x30. If the source already contains the target,
//! do nothing and return success. Otherwise insert `{target, 0}` in the
//! source list and `{source}` in the target list. A failed source insertion
//! returns -108; a failed target insertion removes the just-created source
//! record and also returns -108. On success, increment each object's link
//! count with 32-bit wrapping arithmetic.
//!
//! The concrete identities of the two tagged object families and their list
//! implementations are not recovered. The source membership scan
//! (0x080e2d70), insertion (0x0803bbfc), and removal (0x080646b8) therefore
//! remain volatile firmware boundaries. The stock `bzero` calls only clear
//! the temporary records before the pointer words are written; initialized
//! Rust arrays produce the same records, so the already-ported bzero has no
//! unnecessary seam here.

use core::ptr;

/// First-word tag required by the source guard at 0x080b49a4.
pub const LINK_SOURCE_TAG: u32 = 0x4d53_6e64;

/// First-word tag required by the target guard at 0x080c67b8.
pub const LINK_TARGET_TAG: u32 = 0x4d52_6376;

/// Status returned for either invalid tagged object (`mvn r0, #0x31`).
pub const ERR_INVALID_TAGGED_OBJECT: i32 = -50;

/// Status returned when either list cannot accept the new record
/// (`mvn r6, #0x6b`).
pub const ERR_LINK_INSERT: i32 = -108;

/// Prefix of the source tagged-object family consumed by
/// [`tagged_object_link`].
///
/// `entry_list_words` begins at target offset +0x10. Its concrete layout is
/// owned by the unported list routines; words preserve the firmware's
/// four-byte spacing on hosts as well as on the target.
#[repr(C)]
pub struct TaggedLinkSource {
    pub tag: u32,
    pub opaque_04: u32,
    pub opaque_08: u32,
    pub link_count: u32,
    pub entry_list_words: [u32; 10],
}

/// Prefix of the target tagged-object family consumed by
/// [`tagged_object_link`].
///
/// `entry_list_words[9]` is the word at target offset +0x30 checked by the
/// stock target guard. The list itself begins at +0x0c and is otherwise
/// interpreted only by the firmware boundaries.
#[repr(C)]
pub struct TaggedLinkTarget {
    pub tag: u32,
    pub opaque_04: u32,
    pub link_count: u32,
    pub entry_list_words: [u32; 10],
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::offset_of!(TaggedLinkSource, entry_list_words)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(TaggedLinkTarget, entry_list_words)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x30] = [0; core::mem::offset_of!(TaggedLinkTarget, entry_list_words) + 9 * 4];

type SourceContainsTarget = unsafe extern "C" fn(*mut TaggedLinkSource, *mut TaggedLinkTarget) -> u32;
type ListInsert = unsafe extern "C" fn(*mut u8, *const u32) -> u32;
type ListRemove = unsafe extern "C" fn(*mut u8, u32, u32) -> u32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_source_contains_target(
    source: *mut TaggedLinkSource,
    target: *mut TaggedLinkTarget,
) -> u32 {
    let function: SourceContainsTarget = core::mem::transmute(0x080e_2d70usize);
    function(source, target)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_source_contains_target(
    _source: *mut TaggedLinkSource,
    _target: *mut TaggedLinkTarget,
) -> u32 {
    panic!("tagged_object_link requires source membership scan 0x080e2d70")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_list_insert(list: *mut u8, entry: *const u32) -> u32 {
    let function: ListInsert = core::mem::transmute(0x0803_bbfcusize);
    function(list, entry)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_list_insert(_list: *mut u8, _entry: *const u32) -> u32 {
    panic!("tagged_object_link requires list insertion 0x0803bbfc")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_list_remove(list: *mut u8, count: u32, index: u32) -> u32 {
    let function: ListRemove = core::mem::transmute(0x0806_46b8usize);
    function(list, count, index)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_list_remove(_list: *mut u8, _count: u32, _index: u32) -> u32 {
    panic!("tagged_object_link requires list removal 0x080646b8")
}

#[cfg(target_os = "none")]
static mut SOURCE_CONTAINS_TARGET: SourceContainsTarget = retail_source_contains_target;
#[cfg(not(target_os = "none"))]
static mut SOURCE_CONTAINS_TARGET: SourceContainsTarget = missing_source_contains_target;

#[cfg(target_os = "none")]
static mut LIST_INSERT: ListInsert = retail_list_insert;
#[cfg(not(target_os = "none"))]
static mut LIST_INSERT: ListInsert = missing_list_insert;

#[cfg(target_os = "none")]
static mut LIST_REMOVE: ListRemove = retail_list_remove;
#[cfg(not(target_os = "none"))]
static mut LIST_REMOVE: ListRemove = missing_list_remove;

#[inline(always)]
unsafe fn source_contains_target_fn() -> SourceContainsTarget {
    ptr::read_volatile(ptr::addr_of!(SOURCE_CONTAINS_TARGET))
}

#[inline(always)]
unsafe fn list_insert_fn() -> ListInsert {
    ptr::read_volatile(ptr::addr_of!(LIST_INSERT))
}

#[inline(always)]
unsafe fn list_remove_fn() -> ListRemove {
    ptr::read_volatile(ptr::addr_of!(LIST_REMOVE))
}

/// Links a validated source and target, without duplicating an existing link.
///
/// # Safety
///
/// `source` and `target` must be null or valid aligned pointers to their
/// respective tagged object prefixes. Valid objects must provide the complete
/// list storage required by the three firmware boundaries; the source's list
/// begins at +0x10 and the target's at +0x0c. The function mutates each
/// object's `link_count` only after both insertions report success.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.tagged_object_link")]
pub unsafe extern "C" fn tagged_object_link(
    source: *mut TaggedLinkSource,
    target: *mut TaggedLinkTarget,
) -> i32 {
    if source.is_null() || (*source).tag != LINK_SOURCE_TAG {
        return ERR_INVALID_TAGGED_OBJECT;
    }
    if target.is_null()
        || (*target).tag != LINK_TARGET_TAG
        || (*target).entry_list_words[9] == 0
    {
        return ERR_INVALID_TAGGED_OBJECT;
    }

    if source_contains_target_fn()(source, target) != 0 {
        return 0;
    }

    let source_entry = [target as usize as u32, 0];
    let source_index = list_insert_fn()(
        ptr::addr_of_mut!((*source).entry_list_words).cast::<u8>(),
        source_entry.as_ptr(),
    );
    if source_index == 0 {
        return ERR_LINK_INSERT;
    }

    let target_entry = source as usize as u32;
    if list_insert_fn()(
        ptr::addr_of_mut!((*target).entry_list_words).cast::<u8>(),
        ptr::addr_of!(target_entry),
    ) == 0
    {
        list_remove_fn()(
            ptr::addr_of_mut!((*source).entry_list_words).cast::<u8>(),
            1,
            source_index,
        );
        return ERR_LINK_INSERT;
    }

    (*source).link_count = (*source).link_count.wrapping_add(1);
    (*target).link_count = (*target).link_count.wrapping_add(1);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static CONTAINS_RESULT: AtomicU32 = AtomicU32::new(0);
    static INSERT_RESULTS: [AtomicU32; 2] = [AtomicU32::new(1), AtomicU32::new(1)];
    static INSERT_CALLS: AtomicU32 = AtomicU32::new(0);
    static REMOVE_CALLS: AtomicU32 = AtomicU32::new(0);
    static LAST_REMOVE_LIST: AtomicUsize = AtomicUsize::new(0);
    static LAST_REMOVE_COUNT: AtomicU32 = AtomicU32::new(0);
    static LAST_REMOVE_INDEX: AtomicU32 = AtomicU32::new(0);
    static FIRST_ENTRY_WORD_0: AtomicU32 = AtomicU32::new(0);
    static FIRST_ENTRY_WORD_1: AtomicU32 = AtomicU32::new(0);
    static SECOND_ENTRY_WORD: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn mock_source_contains_target(
        _source: *mut TaggedLinkSource,
        _target: *mut TaggedLinkTarget,
    ) -> u32 {
        CONTAINS_RESULT.load(Ordering::Relaxed)
    }

    unsafe extern "C" fn mock_list_insert(_list: *mut u8, entry: *const u32) -> u32 {
        let call = INSERT_CALLS.fetch_add(1, Ordering::Relaxed);
        if call == 0 {
            FIRST_ENTRY_WORD_0.store(entry.read(), Ordering::Relaxed);
            FIRST_ENTRY_WORD_1.store(entry.add(1).read(), Ordering::Relaxed);
        } else {
            SECOND_ENTRY_WORD.store(entry.read(), Ordering::Relaxed);
        }
        INSERT_RESULTS[call as usize].load(Ordering::Relaxed)
    }

    unsafe extern "C" fn mock_list_remove(list: *mut u8, count: u32, index: u32) -> u32 {
        REMOVE_CALLS.fetch_add(1, Ordering::Relaxed);
        LAST_REMOVE_LIST.store(list as usize, Ordering::Relaxed);
        LAST_REMOVE_COUNT.store(count, Ordering::Relaxed);
        LAST_REMOVE_INDEX.store(index, Ordering::Relaxed);
        0
    }

    unsafe fn reset_boundaries() {
        SOURCE_CONTAINS_TARGET = mock_source_contains_target;
        LIST_INSERT = mock_list_insert;
        LIST_REMOVE = mock_list_remove;
        CONTAINS_RESULT.store(0, Ordering::Relaxed);
        INSERT_RESULTS[0].store(1, Ordering::Relaxed);
        INSERT_RESULTS[1].store(1, Ordering::Relaxed);
        INSERT_CALLS.store(0, Ordering::Relaxed);
        REMOVE_CALLS.store(0, Ordering::Relaxed);
        LAST_REMOVE_LIST.store(0, Ordering::Relaxed);
        LAST_REMOVE_COUNT.store(0, Ordering::Relaxed);
        LAST_REMOVE_INDEX.store(0, Ordering::Relaxed);
        FIRST_ENTRY_WORD_0.store(0, Ordering::Relaxed);
        FIRST_ENTRY_WORD_1.store(0, Ordering::Relaxed);
        SECOND_ENTRY_WORD.store(0, Ordering::Relaxed);
    }

    fn source() -> TaggedLinkSource {
        TaggedLinkSource {
            tag: LINK_SOURCE_TAG,
            opaque_04: 0,
            opaque_08: 0,
            link_count: 4,
            entry_list_words: [0; 10],
        }
    }

    fn target() -> TaggedLinkTarget {
        let mut target = TaggedLinkTarget {
            tag: LINK_TARGET_TAG,
            opaque_04: 0,
            link_count: 7,
            entry_list_words: [0; 10],
        };
        target.entry_list_words[9] = 1;
        target
    }

    #[test]
    fn rejects_invalid_or_unready_objects_without_calling_boundaries() {
        let _guard = TEST_LOCK.lock();
        unsafe { reset_boundaries() };
        let mut valid_source = source();
        let mut valid_target = target();
        let mut invalid_source = source();
        invalid_source.tag = 0;
        let mut unready_target = target();
        unready_target.entry_list_words[9] = 0;

        unsafe {
            assert_eq!(tagged_object_link(&mut invalid_source, &mut valid_target), ERR_INVALID_TAGGED_OBJECT);
            assert_eq!(tagged_object_link(core::ptr::null_mut(), &mut valid_target), ERR_INVALID_TAGGED_OBJECT);
            assert_eq!(tagged_object_link(&mut valid_source, &mut unready_target), ERR_INVALID_TAGGED_OBJECT);
            assert_eq!(tagged_object_link(&mut valid_source, core::ptr::null_mut()), ERR_INVALID_TAGGED_OBJECT);
        }
        assert_eq!(INSERT_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(REMOVE_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn preserves_counts_for_an_existing_link() {
        let _guard = TEST_LOCK.lock();
        unsafe { reset_boundaries() };
        CONTAINS_RESULT.store(3, Ordering::Relaxed);
        let mut source = source();
        let mut target = target();

        assert_eq!(unsafe { tagged_object_link(&mut source, &mut target) }, 0);
        assert_eq!((source.link_count, target.link_count), (4, 7));
        assert_eq!(INSERT_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn returns_insert_error_when_source_list_rejects_entry() {
        let _guard = TEST_LOCK.lock();
        unsafe { reset_boundaries() };
        INSERT_RESULTS[0].store(0, Ordering::Relaxed);
        let mut source = source();
        let mut target = target();

        assert_eq!(unsafe { tagged_object_link(&mut source, &mut target) }, ERR_LINK_INSERT);
        assert_eq!((source.link_count, target.link_count), (4, 7));
        assert_eq!(INSERT_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(REMOVE_CALLS.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rolls_back_source_entry_when_target_list_rejects_entry() {
        let _guard = TEST_LOCK.lock();
        unsafe { reset_boundaries() };
        INSERT_RESULTS[0].store(9, Ordering::Relaxed);
        INSERT_RESULTS[1].store(0, Ordering::Relaxed);
        let mut source = source();
        let mut target = target();
        let source_list = source.entry_list_words.as_mut_ptr() as usize;

        assert_eq!(unsafe { tagged_object_link(&mut source, &mut target) }, ERR_LINK_INSERT);
        assert_eq!((source.link_count, target.link_count), (4, 7));
        assert_eq!(INSERT_CALLS.load(Ordering::Relaxed), 2);
        assert_eq!(REMOVE_CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(LAST_REMOVE_LIST.load(Ordering::Relaxed), source_list);
        assert_eq!(LAST_REMOVE_COUNT.load(Ordering::Relaxed), 1);
        assert_eq!(LAST_REMOVE_INDEX.load(Ordering::Relaxed), 9);
    }

    #[test]
    fn links_records_in_both_directions_and_wraps_counts() {
        let _guard = TEST_LOCK.lock();
        unsafe { reset_boundaries() };
        let mut source = source();
        let mut target = target();
        source.link_count = u32::MAX;
        target.link_count = u32::MAX;

        assert_eq!(unsafe { tagged_object_link(&mut source, &mut target) }, 0);
        assert_eq!((source.link_count, target.link_count), (0, 0));
        assert_eq!(INSERT_CALLS.load(Ordering::Relaxed), 2);
        assert_eq!(REMOVE_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(FIRST_ENTRY_WORD_0.load(Ordering::Relaxed), &mut target as *mut TaggedLinkTarget as usize as u32);
        assert_eq!(FIRST_ENTRY_WORD_1.load(Ordering::Relaxed), 0);
        assert_eq!(SECOND_ENTRY_WORD.load(Ordering::Relaxed), &mut source as *mut TaggedLinkSource as usize as u32);
    }
}
