//! `embedded_list_clear` — original: `FUN_083dbfb4` @ **0x083dbfb4**
//! (**56 bytes exactly**, `0x083dbfb4..0x083dbfeb`; the following
//! `push {r1-r5, lr}` at `0x083dbfec` begins the next real function).
//!
//! Raw A32 decoding finds one outbound unconditional plain `bl`, to the
//! unported list operation at **0x083cc794**, and no predicated outbound
//! `bl`. Full-image decoding finds two inbound unconditional plain `bl` sites
//! (0x0819edc4 and 0x0819edcc) and no predicated inbound direct calls.
//!
//! # Algorithm
//!
//! Loads the target-width list pointer at `owner + 0x10`, reads that list's
//! `+0x08` link, reloads `owner + 0x10`, and calls the unported list operation
//! with stack-local output, link, and list words. The caller invokes this on
//! two embedded collection fields while rebuilding its state; the empty range
//! (`list + 0x08` through `list`) establishes this wrapper as a clear.
//!
//! # Deliberate deviations
//!
//! The 0x083cc794 callee has no recovered semantic identity. Target builds
//! call its verified load address; host builds use a volatile replaceable seam.
//! The list and link remain `u32` target addresses so host pointer width cannot
//! alter retail offsets.

pub type EmbeddedListClearOperation = unsafe extern "C" fn(*mut u32, *mut u32, *mut u32, *mut u32);

const EMBEDDED_LIST_CLEAR_OPERATION_ADDRESS: usize = 0x083c_c794;
const OWNER_EMBEDDED_LIST_WORD: usize = 0x10 / 4;
const LIST_LINK_WORD: usize = 0x08 / 4;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_embedded_list_clear_operation(
    output: *mut u32,
    owner: *mut u32,
    link: *mut u32,
    embedded_list: *mut u32,
) {
    unsafe {
        core::mem::transmute::<usize, EmbeddedListClearOperation>(EMBEDDED_LIST_CLEAR_OPERATION_ADDRESS)(
            output,
            owner,
            link,
            embedded_list,
        )
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_embedded_list_clear_operation(
    _output: *mut u32,
    _owner: *mut u32,
    _link: *mut u32,
    _embedded_list: *mut u32,
) {
    panic!("embedded_list_clear requires retail operation 0x083cc794")
}

#[cfg(target_os = "none")]
pub static mut EMBEDDED_LIST_CLEAR_OPERATION: EmbeddedListClearOperation = retail_embedded_list_clear_operation;
#[cfg(not(target_os = "none"))]
pub static mut EMBEDDED_LIST_CLEAR_OPERATION: EmbeddedListClearOperation = missing_embedded_list_clear_operation;

#[inline(always)]
fn embedded_list_clear_operation() -> EmbeddedListClearOperation {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EMBEDDED_LIST_CLEAR_OPERATION)) }
}

/// Clears the list embedded at `owner + 0x10` through its retail list operation.
///
/// # Safety
///
/// `owner` and its target-width embedded-list and link pointers must be valid
/// for the reads and the unported operation's full ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.embedded_list_clear"))]
#[inline(never)]
pub unsafe extern "C" fn embedded_list_clear(owner: *mut u32) {
    let first_embedded_list = unsafe { owner.add(OWNER_EMBEDDED_LIST_WORD).read_volatile() };
    let mut link = unsafe { (first_embedded_list as *const u32).add(LIST_LINK_WORD).read_volatile() };
    let mut embedded_list = unsafe { owner.add(OWNER_EMBEDDED_LIST_WORD).read_volatile() };
    let mut output = embedded_list;
    unsafe { embedded_list_clear_operation()(&mut output, owner, &mut link, &mut embedded_list) }
}

/// `embedded_list_pool_destruct` — original: `FUN_082a8470` @ 0x082a8470.
/// True extent: 136 bytes, [0x082a8470, 0x082a84f8); the next word is a
/// sibling's push prologue. Raw A32 has three unconditional BL instructions
/// (0x083cc794 once, 0x08266f2c twice), no predicated BL, and two inbound
/// unconditional BL sites (0x0819fd00, 0x0819fd08).
///
/// With a non-null +0x10 header, clears [header+0x08 link, header) through
/// the existing opaque retail operation, reloads the header, links it into
/// the +0x04 recycle chain via header+0x0c, then drains the +0x00 chunk
/// chain. Unlinks each 12-byte chunk before freeing its +0x08 block with
/// +0x04 capacity, then the chunk with count 1. Returns owner; null header
/// skips all cleanup, even if chunks remain.
///
/// Deliberate deviations: dead ADS register spills are omitted; r1 is a
/// restored scratch register, not a second result. The unported operation
/// uses the existing address seam without claiming a concrete class identity.
///
/// # Safety
/// Owner, header and chunk words must be aligned and live through cleanup;
/// their target-width pointers must satisfy the retail operation and allocator.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn embedded_list_pool_destruct(owner: *mut u32) -> *mut u32 {
    unsafe {
        embedded_list_pool_destruct_with(
            owner,
            |out, owner, first, last| embedded_list_clear_operation()(out, owner, first, last),
            |ptr, count, elem| crate::heap::veneers::cxx_array_dealloc(ptr, count, elem),
        )
    }
}

#[inline(always)]
unsafe fn embedded_list_pool_destruct_with(
    owner: *mut u32,
    mut clear: impl FnMut(*mut u32, *mut u32, *mut u32, *mut u32),
    mut dealloc: impl FnMut(*mut u8, usize, usize),
) -> *mut u32 {
    unsafe {
        let mut header = owner.add(OWNER_EMBEDDED_LIST_WORD).read();
        if header != 0 {
            let current_header = owner.add(OWNER_EMBEDDED_LIST_WORD).read();
            let mut first = (current_header as usize as *const u32).add(LIST_LINK_WORD).read();
            let mut output = core::mem::MaybeUninit::<u32>::uninit();
            clear(output.as_mut_ptr(), owner, &mut first, &mut header);
            let header = owner.add(OWNER_EMBEDDED_LIST_WORD).read();
            (header as usize as *mut u32).add(3).write(owner.add(1).read());
            owner.add(1).write(header);
            loop {
                let chunk = owner.read();
                if chunk == 0 { break; }
                let chunk = chunk as usize as *mut u32;
                owner.write(chunk.read());
                dealloc(chunk.add(2).read() as usize as *mut u8, chunk.add(1).read() as usize, 0);
                dealloc(chunk.cast(), 1, 0);
            }
        }
        owner
    }
}

#[cfg(test)]
mod pool_tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(crate::testing::hints::EMBEDDED_LIST_POOL_DESTRUCT, 0x1000).map(|p| p as usize)
    });

    #[test]
    fn null_header_preserves_chunks_and_recycle_chain() {
        let mut owner = [0xdead_beef, 0x1234_5678, 17, 19, 0, 23];
        let before = owner;
        unsafe {
            assert_eq!(embedded_list_pool_destruct_with(owner.as_mut_ptr(), |_, _, _, _| panic!("clear"), |_, _, _| panic!("free")), owner.as_mut_ptr());
        }
        assert_eq!(owner, before);
    }

    #[test]
    fn reloads_header_and_unlinks_before_block_then_record_release() {
        let _guard = LOCK.lock();
        let Some(slab) = *SLAB else {
            assert!(crate::testing::note_missing_u32_fixture("cxx::embedded_list_pool_destruct"));
            return;
        };
        unsafe {
            (slab as *mut u8).write_bytes(0, 0x1000);
            let owner = slab as *mut u32;
            let old_header = owner.add(32);
            let new_header = owner.add(48);
            let chunk1 = owner.add(64);
            let chunk2 = owner.add(80);
            owner.add(4).write(old_header as usize as u32);
            owner.add(1).write(0x1234_5678);
            owner.add(2).write(0xaabb_ccdd);
            owner.add(5).write(7);
            old_header.add(2).write(0x7654_3210);
            old_header.add(3).write(0x8888_8888);
            owner.write(chunk1 as usize as u32);
            chunk1.write(chunk2 as usize as u32);
            chunk1.add(1).write(0);
            chunk1.add(2).write(0);
            chunk2.write(0);
            chunk2.add(1).write(u32::MAX);
            chunk2.add(2).write(0xfeed_0000);
            let mut released = std::vec::Vec::new();
            let result = embedded_list_pool_destruct_with(owner, |out, actual_owner, first, last| {
                assert_eq!(actual_owner, owner);
                assert_eq!(first.read(), 0x7654_3210);
                assert_eq!(last.read(), old_header as usize as u32);
                out.write(0);
                last.write(0); // Stack iterator changes must not select the recycled header.
                owner.add(4).write(new_header as usize as u32);
                owner.add(1).write(0x8765_4321);
            }, |ptr, count, elem| {
                assert_eq!(owner.add(1).read(), new_header as usize as u32);
                assert_eq!(new_header.add(3).read(), 0x8765_4321);
                assert_eq!(owner.read(), if released.len() < 2 { chunk2 as usize as u32 } else { 0 });
                released.push((ptr as usize, count, elem));
            });
            assert_eq!(result, owner);
            assert_eq!(released, std::vec![
                (0, 0, 0), (chunk1 as usize, 1, 0),
                (0xfeed_0000, u32::MAX as usize, 0), (chunk2 as usize, 1, 0),
            ]);
            assert_eq!(owner.read(), 0);
            assert_eq!(old_header.add(3).read(), 0x8888_8888);
            assert_eq!(owner.add(4).read(), new_header as usize as u32);
            assert_eq!(owner.add(2).read(), 0xaabb_ccdd);
            assert_eq!(owner.add(5).read(), 7);
        }
    }

    #[test]
    fn header_without_chunks_is_still_recycled() {
        let _guard = LOCK.lock();
        let Some(slab) = *SLAB else {
            assert!(crate::testing::note_missing_u32_fixture("cxx::embedded_list_pool_destruct"));
            return;
        };
        unsafe {
            (slab as *mut u8).write_bytes(0, 0x1000);
            let owner = slab as *mut u32;
            let header = owner.add(32);
            owner.add(4).write(header as usize as u32);
            header.add(2).write(header as usize as u32);
            let mut cleared = false;
            embedded_list_pool_destruct_with(owner, |out, _, first, last| {
                assert_eq!(first.read(), last.read());
                cleared = true;
                out.write(last.read());
            }, |_, _, _| panic!("empty chunk chain must not free"));
            assert!(cleared);
            assert_eq!(owner.add(1).read(), header as usize as u32);
            assert_eq!(header.add(3).read(), 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut ARGUMENT_WORDS: [u32; 4] = [0; 4];

    unsafe extern "C" fn record_operation(
        output: *mut u32,
        owner: *mut u32,
        link: *mut u32,
        embedded_list: *mut u32,
    ) {
        unsafe {
            CALLS += 1;
            ARGUMENT_WORDS = [
                output.read_volatile(),
                owner as usize as u32,
                link.read_volatile(),
                embedded_list.read_volatile(),
            ];
        }
    }

    #[test]
    fn forwards_normal_and_null_links_as_target_words() {
        let Some(slab) = try_map_u32_slab(hints::EMBEDDED_LIST_CLEAR, 0x1000) else {
            return;
        };
        let _guard = TEST_LOCK.lock();
        unsafe {
            slab.write_bytes(0, 0x1000);
            let owner = slab.cast::<u32>();
            let list = slab.add(0x100).cast::<u32>();
            owner.add(OWNER_EMBEDDED_LIST_WORD).write_volatile(list as usize as u32);
            list.add(LIST_LINK_WORD).write_volatile(0x1234_5678);
            CALLS = 0;
            ARGUMENT_WORDS = [0; 4];
            EMBEDDED_LIST_CLEAR_OPERATION = record_operation;
            embedded_list_clear(owner);
            assert_eq!(CALLS, 1);
            assert_eq!(ARGUMENT_WORDS, [list as usize as u32, owner as usize as u32, 0x1234_5678, list as usize as u32]);
            list.add(LIST_LINK_WORD).write_volatile(0);
            embedded_list_clear(owner);
            assert_eq!(CALLS, 2);
            assert_eq!(ARGUMENT_WORDS, [list as usize as u32, owner as usize as u32, 0, list as usize as u32]);
            EMBEDDED_LIST_CLEAR_OPERATION = missing_embedded_list_clear_operation;
        }
    }
}
