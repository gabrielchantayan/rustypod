//! Clearing SQLite's generic symbol-table hash — `sqlite3HashClear`
//! from hash.c, the destructor half of the `Hash` machinery
//! [`super::hash_init`] constructs.
//!
//! - `hash_clear` — original: `FUN_0837ad2c` @ 0x0837ad2c (92 bytes; 7
//!   `bl` call sites in two functions, binary-scanned). SQLite
//!   3.4.x/3.5.x's `sqlite3HashClear`:
//!
//! ```c
//! void sqlite3HashClear(Hash *pH){
//!   HashElem *elem;
//!   assert( pH!=0 );
//!   elem = pH->first;
//!   pH->first = 0;
//!   sqlite3_free(pH->ht);
//!   pH->ht = 0;
//!   pH->htsize = 0;
//!   while( elem ){
//!     HashElem *next_elem = elem->next;
//!     if( pH->copyKey && elem->pKey ){
//!       sqlite3_free(elem->pKey);
//!     }
//!     sqlite3_free(elem);
//!     elem = next_elem;
//!   }
//!   pH->count = 0;
//! }
//! ```
//!
//! ```text
//! 0837ad2c:  stmdb sp!,{r4,r5,r6,r7,r8,lr}
//! 0837ad30:  ldr  r4,[r0,#0xc]    ; elem = first
//! 0837ad34:  mov  r7,#0x0
//! 0837ad38:  mov  r5,r0
//! 0837ad3c:  str  r7,[r0,#0xc]    ; first = NULL
//! 0837ad40:  ldr  r0,[r0,#0x10]
//! 0837ad44:  bl   0x083906f4      ; sqlite3_free(ht)
//! 0837ad48:  str  r7,[r5,#0x10]   ; ht     = NULL
//! 0837ad4c:  str  r7,[r5,#0x8]    ; htsize = 0
//! 0837ad50:  b    loop-test
//! loop:                            ; elem in r4
//! 0837ad54:  ldrb r0,[r5,#0x1]    ; copyKey (reloaded each round)
//! 0837ad58:  ldr  r6,[r4,#0x0]    ; next = elem->next
//! 0837ad5c:  cmp  r0,#0x0
//! 0837ad60:  ldrne r0,[r4,#0xc]   ; key = elem->pKey
//! 0837ad64:  cmpne r0,#0x0
//! 0837ad68:  blne 0x083906f4      ; if (copyKey && key) free(key)
//! 0837ad6c:  mov  r0,r4
//! 0837ad70:  bl   0x083906f4      ; free(elem)
//! 0837ad74:  mov  r4,r6
//! loop-test:
//! 0837ad78:  cmp  r4,#0x0
//! 0837ad7c:  bne  loop
//! 0837ad80:  str  r7,[r5,#0x4]    ; count = 0
//! ```
//!
//! It confirms the 20-byte `Hash` layout [`super::hash_init`] pins and
//! pins this build's `HashElem` node layout: the chain link walked by
//! the loop at +0x00 and the strdup'd key at +0x0c (freed iff
//! `copy_key`), which is the `pKey` of 3.4.x's
//! `{next, prev, data, pKey, nKey}`.
//!
//! Callers (both binary-verified):
//!
//! - `sqlite3SchemaClear` @ 0x08382c58 (4 sites): clears `fkeyHash`
//!   @ +0x40 and `idxHash` @ +0x18 directly, and the two stack
//!   snapshots of `tblHash`/`trigHash` (sp+0x04 / sp+0x18) taken before
//!   the delete loops — each live `Schema` hash is re-stamped by
//!   `hash_init` @ 0x0837ade8 right after its contents are dropped.
//! - `closeDatabase` @ 0x0838f890 (3 sites): the db handle's hashes at
//!   +0x128 / +0xf4 / +0x114 (aCollSeq / aModule / aFunc family), torn
//!   down on the `sqlite3_close` path after their entries' destructors
//!   have run.
//!
//! Deviations:
//! - Upstream wraps the `ht` free in `if( pH->ht )`; the firmware calls
//!   the free unconditionally and lets the callee NULL-guard. This port
//!   does the same through the ported [`tracked_free`], whose NULL
//!   early-out *is* the original's `sqlite3_free` guard.
//! - The two key-field conditions are fused in the original
//!   (`ldrne`/`cmpne`/`blne`): with `copy_key` clear the key word is
//!   never even loaded. Same behavior, same shape.
//! - The `Hash`/`HashElem` structs are target-exact (asserted on the
//!   32-bit target); on a 64-bit host the pointer fields merely widen
//!   and stay disjoint — all access goes through the structs, matching
//!   the crate's struct-port convention.

use crate::heap::tracked::tracked_free;

/// The 20-byte generic hash table (`sqlite3 Hash`), the layout
/// [`super::hash_init`] documents byte by byte: `key_class` +0x00,
/// `copy_key` +0x01, `count` +0x04, `htsize` +0x08, `first` +0x0c,
/// `ht` +0x10. On a 64-bit host the two pointer fields widen (offsets
/// shift, harmless — all access goes through the struct).
#[repr(C)]
pub struct Hash {
    /// `SQLITE_HASH_*` key discriminator (u8; original: `strb r1`).
    pub key_class: u8,
    /// Keys are strdup'd on insert and freed on delete (u8; original:
    /// `ldrb r0,[r5,#0x1]`).
    pub copy_key: u8,
    /// +0x02/+0x03: never touched by init or clear.
    _pad: [u8; 2],
    /// Entries in the table (original: `str r7,[r5,#0x4]`).
    pub count: u32,
    /// Bucket count (original: `str r7,[r5,#0x8]`).
    pub htsize: u32,
    /// Insertion-order chain head (original: `ldr r4,[r0,#0xc]`).
    pub first: *mut HashElem,
    /// Bucket array of {count, chain} pairs (original:
    /// `ldr r0,[r0,#0x10]`).
    pub ht: *mut u8,
}

/// A hash chain node (`sqlite3 HashElem`), only the fields this
/// destructor touches are pinned by its disassembly: the singly-linked
/// `next` at +0x00 and the key at +0x0c. The middle words are named per
/// upstream 3.4.x's `{next, prev, data, pKey, nKey}`; nothing in this
/// function reads them.
#[repr(C)]
pub struct HashElem {
    /// Next element in the chain (original: `ldr r6,[r4,#0x0]`).
    pub next: *mut HashElem,
    /// Upstream `prev`; never touched by clear.
    pub prev: *mut HashElem,
    /// Upstream `data` payload pointer; never touched by clear (the
    /// payload's owner frees it before calling clear).
    pub data: *mut u8,
    /// The strdup'd key, freed iff `copy_key` (original:
    /// `ldrne r0,[r4,#0xc]`).
    pub key: *mut u8,
}

// Target-exact layout (the offsets the original's ldr/str literals
// encode); on a 64-bit host the pointer fields widen and stay disjoint.
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x14] = [0; core::mem::size_of::<Hash>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(Hash, count)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::offset_of!(Hash, htsize)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(Hash, first)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x10] = [0; core::mem::offset_of!(Hash, ht)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x00] = [0; core::mem::offset_of!(HashElem, next)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::offset_of!(HashElem, key)];

/// hash_clear — original: `FUN_0837ad2c` @ 0x0837ad2c (92 bytes; 7 `bl`
/// call sites).
///
/// `sqlite3HashClear`: detach the insertion-order chain head and free
/// the bucket array up front (NULL-tolerantly — the free guards
/// internally), then walk the chain freeing each `HashElem`, and each
/// element's key when `copy_key` is set and the key is non-NULL. The
/// table fields are all zeroed: `first` and `ht` before the walk,
/// `htsize` alongside, `count` as the final store; `key_class` and
/// `copy_key` survive, matching upstream. `hash` must be a valid `Hash`
/// (or its firmware 20-byte layout) and every chain pointer a live
/// tracked-allocation payload accepted by [`tracked_free`].
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_clear(hash: *mut Hash) {
    let hash = &mut *hash;
    let mut elem = hash.first;
    hash.first = core::ptr::null_mut();
    let ht = hash.ht;
    tracked_free(ht);
    hash.ht = core::ptr::null_mut();
    hash.htsize = 0;
    while !elem.is_null() {
        let next = (*elem).next;
        if hash.copy_key != 0 {
            let key = (*elem).key;
            if !key.is_null() {
                tracked_free(key);
            }
        }
        tracked_free(elem as *mut u8);
        elem = next;
    }
    hash.count = 0;
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::heap::tracked::{BLOCK_HEADER_SIZE, TAG_TRACKED};
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{tests::mock_heap, HEAP_OPS};
    use std::vec::Vec;

    /// Every (raw block, tag) the mock heap was asked to free, in order.
    static mut FREED: Vec<(*mut u8, usize)> = Vec::new();

    unsafe extern "C" fn recording_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        tag: usize,
    ) {
        (*core::ptr::addr_of_mut!(FREED)).push((ptr, tag));
    }

    fn freed() -> Vec<(*mut u8, usize)> {
        unsafe { (*core::ptr::addr_of!(FREED)).clone() }
    }

    /// Installs the mock heap with the recording free and clears the
    /// log; the returned guard holds the ops lock for the test body.
    fn with_recording_heap() -> std::sync::MutexGuard<'static, ()> {
        let guard = mock_heap();
        unsafe {
            (*core::ptr::addr_of_mut!(FREED)).clear();
            (*core::ptr::addr_of_mut!(HEAP_OPS)).free = recording_free;
        }
        guard
    }

    /// A dirty `Hash`: every scalar seeded non-zero, chain detached.
    fn dirty_hash() -> Hash {
        Hash {
            key_class: 3,
            copy_key: 0,
            _pad: [0xa5; 2],
            count: 9,
            htsize: 16,
            first: core::ptr::null_mut(),
            ht: core::ptr::null_mut(),
        }
    }

    /// A hand-built tag-57 tracked block (layout: `heap::tracked`), raw
    /// block at offset 0 of a 32-aligned buffer, payload at raw + 32,
    /// pad word 32 - 8 = 24.
    #[repr(align(32))]
    struct TrackedBlock([u8; 128]);

    impl TrackedBlock {
        fn new(size: i32) -> Self {
            let mut block = TrackedBlock([0; 128]);
            block.0[0..4].copy_from_slice(&size.to_le_bytes());
            let pad = (32 - BLOCK_HEADER_SIZE) as u32;
            block.0[28..32].copy_from_slice(&pad.to_le_bytes());
            block
        }
        fn raw(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn payload(&mut self) -> *mut u8 {
            // In-bounds by construction (128-byte block, payload at 32).
            unsafe { self.0.as_mut_ptr().add(32) }
        }
        /// The payload as a zeroed chain node.
        fn elem(&mut self) -> *mut HashElem {
            let elem = self.payload() as *mut HashElem;
            unsafe {
                (*elem).next = core::ptr::null_mut();
                (*elem).prev = core::ptr::null_mut();
                (*elem).data = core::ptr::null_mut();
                (*elem).key = core::ptr::null_mut();
            }
            elem
        }
    }

    #[test]
    fn empty_hash_frees_nothing_and_zeroes_the_table_only() {
        let _heap = with_recording_heap();
        let mut hash = dirty_hash();
        hash.copy_key = 1;
        unsafe { hash_clear(&mut hash) };
        assert_eq!(hash.key_class, 3, "key_class untouched");
        assert_eq!(hash.copy_key, 1, "copy_key untouched");
        assert_eq!(hash._pad, [0xa5; 2], "the padding survives");
        assert_eq!(hash.count, 0, "count");
        assert_eq!(hash.htsize, 0, "htsize");
        assert!(hash.first.is_null(), "first");
        assert!(hash.ht.is_null(), "ht");
        assert!(
            freed().is_empty(),
            "NULL ht and a NULL chain: tracked_free NULL-guards, nothing reaches the heap"
        );
    }

    #[test]
    fn bucket_array_is_freed_first_then_each_node() {
        let _heap = with_recording_heap();
        let mut hash = dirty_hash();
        let mut ht = TrackedBlock::new(0x40);
        let mut elem_a = TrackedBlock::new(0x14);
        let mut elem_b = TrackedBlock::new(0x14);
        unsafe {
            let a = elem_a.elem();
            (*a).next = elem_b.elem();
            hash.first = a;
            hash.ht = ht.payload();
            hash_clear(&mut hash);
        }
        assert_eq!(
            freed(),
            std::vec![
                (ht.raw(), TAG_TRACKED),
                (elem_a.raw(), TAG_TRACKED),
                (elem_b.raw(), TAG_TRACKED),
            ],
            "bucket array first, then the chain in order, all tag 57"
        );
    }

    #[test]
    fn copy_key_frees_each_non_null_key_before_its_node() {
        let _heap = with_recording_heap();
        let mut hash = dirty_hash();
        hash.copy_key = 1;
        let mut elem_a = TrackedBlock::new(0x14);
        let mut key_a = TrackedBlock::new(8);
        let mut elem_b = TrackedBlock::new(0x14);
        unsafe {
            let a = elem_a.elem();
            (*a).next = elem_b.elem();
            (*a).key = key_a.payload();
            hash.first = a;
            hash_clear(&mut hash);
        }
        assert_eq!(
            freed(),
            std::vec![
                (key_a.raw(), TAG_TRACKED),
                (elem_a.raw(), TAG_TRACKED),
                (elem_b.raw(), TAG_TRACKED),
            ],
            "key before its node; a NULL key frees nothing (blne)"
        );
    }

    #[test]
    fn copy_key_clear_never_frees_a_set_key() {
        let _heap = with_recording_heap();
        let mut hash = dirty_hash();
        let mut elem = TrackedBlock::new(0x14);
        unsafe {
            // Non-NULL key word with copyKey clear: the ldrne never even
            // loads it, so it must survive and stay unfreed.
            let node = elem.elem();
            (*node).key = 0xdeadbeef as *mut u8;
            hash.first = node;
            hash_clear(&mut hash);
        }
        assert_eq!(
            freed(),
            std::vec![(elem.raw(), TAG_TRACKED)],
            "only the node goes back to the heap"
        );
    }

    #[test]
    fn every_table_field_is_zeroed_and_the_flags_survive() {
        let _heap = with_recording_heap();
        let mut hash = dirty_hash();
        let mut ht = TrackedBlock::new(0x40);
        let mut elem = TrackedBlock::new(0x14);
        unsafe {
            hash.first = elem.elem();
            hash.ht = ht.payload();
            hash_clear(&mut hash);
        }
        assert_eq!(hash.count, 0, "count — the final store");
        assert_eq!(hash.htsize, 0, "htsize");
        assert!(hash.first.is_null(), "first — cleared before the walk");
        assert!(hash.ht.is_null(), "ht — cleared right after the free");
        assert_eq!(hash.key_class, 3, "key_class survives");
        assert_eq!(hash.copy_key, 0, "copy_key survives");
        assert_eq!(hash._pad, [0xa5; 2], "padding +0x02/+0x03 survives");
    }
}
