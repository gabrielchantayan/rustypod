//! Walking one bucket chain of SQLite's generic symbol-table hash —
//! `findElementGivenHash` from hash.c, the chain walker
//! [`super::hash_find`] reaches through its `find_elem` seam (whose
//! shipped default is now this port).
//!
//! - `find_element_given_hash` — original: `FUN_082ce2e8` @
//!   0x082ce2e8 (120 bytes, plus the 8-byte comparator literal pool at
//!   0x082ce360/0x082ce364; 2 `bl` call sites, binary-scanned). SQLite
//!   3.5.x's `findElementGivenHash`, with `findCompareFunction`
//!   inlined:
//!
//! ```c
//! static HashElem *findElementGivenHash(
//!   const Hash *pH, const void *pKey, int nKey, int h
//! ){
//!   HashElem *elem;
//!   int count;
//!   int (*xCompare)(const void*,int,const void*,int);
//!   if( pH->ht ){
//!     struct _ht *pEntry = &pH->ht[h];
//!     elem = pEntry->chain;
//!     count = pEntry->count;
//!     xCompare = pH->keyClass==SQLITE_HASH_STRING ? strCompare
//!                                                 : binCompare;
//!     while( count-- && elem ){
//!       if( (*xCompare)(elem->pKey,elem->nKey,pKey,nKey)==0 )
//!         return elem;
//!       elem = elem->next;
//!     }
//!   }
//!   return 0;
//! }
//! ```
//!
//! The whole body (`decomp/c/031/082ce2e8_FUN_082ce2e8.c` agrees):
//!
//! ```text
//! 082ce2e8:  stmdb sp!,{r4,r5,r6,r7,r8,lr}
//! 082ce2ec:  mov  r7,r1            ; pKey
//! 082ce2f0:  ldr  r1,[r0,#0x10]    ; ht
//! 082ce2f4:  mov  r8,r2            ; nKey
//! 082ce2f8:  cmp  r1,#0x0
//! 082ce2fc:  beq  0x082ce358       ; ht == NULL -> return NULL
//! 082ce300:  ldrb r0,[r0,#0x0]     ; keyClass
//! 082ce304:  add  r1,r1,r3, lsl #3 ; &ht[h]
//! 082ce308:  ldr  r4,[r1,#0x4]     ; elem = ht[h].chain
//! 082ce30c:  cmp  r0,#0x3          ; SQLITE_HASH_STRING
//! 082ce310:  ldrne r6,[0x82ce360]  ; -> binCompare (runtime 0x082ac998)
//! 082ce314:  ldreq r6,[0x82ce364]  ; -> strCompare (runtime 0x08386ef8)
//! 082ce318:  ldr  r5,[r1,#0x0]     ; count = ht[h].count
//! 082ce31c:  b    loop-test
//! loop:                              ; elem in r4
//! 082ce320:  ldr  r0,[r4,#0xc]     ; elem->pKey
//! 082ce324:  ldr  r1,[r4,#0x10]    ; elem->nKey
//! 082ce328:  mov  r3,r8            ; nKey
//! 082ce32c:  mov  r2,r7            ; pKey
//! 082ce330:  blx  r6               ; compare(elem->pKey, elem->nKey, pKey, nKey)
//! 082ce334:  cmp  r0,#0x0
//! 082ce338:  ldrne r4,[r4,#0x0]    ; mismatch: elem = elem->next
//! 082ce33c:  bne  loop-test
//! 082ce340:  mov  r0,r4            ; match: return elem
//! 082ce344:  ldmia sp!,{r4,r5,r6,r7,r8,pc}
//! loop-test:                         ; while( count-- && elem )
//! 082ce348:  sub  r5,r5,#0x1
//! 082ce34c:  cmn  r5,#0x1
//! 082ce350:  cmpne r4,#0x0
//! 082ce354:  bne  loop
//! 082ce358:  mov  r0,#0x0          ; exhausted: NULL
//! 082ce35c:  ldmia sp!,{r4,r5,r6,r7,r8,pc}
//! ```
//!
//! Two facts this body pins:
//!
//! - `HashElem.nKey` @ +0x10 — the last word of 3.4.x's
//!   `{next, prev, data, pKey, nKey}`, exactly where
//!   [`super::hash_find`]'s scouting note predicted it; the
//!   [`super::hash_clear`] `HashElem` struct now carries the field.
//! - The bucket entry is the 8-byte `{count, chain}` pair the
//!   htsize-doubling rehash in `sqlite3HashInsert` @ 0x0837ae08
//!   implies: `ht + h*8`, count at +0x00, chain head at +0x04 (the
//!   [`Bucket`] struct below; on a 64-bit host its pointer field
//!   widens and the stride follows — all access goes through the
//!   struct, the house struct-port convention).
//!
//! The two comparators (the literal-pool words are runtime addresses;
//! both targets sit in Ghidra-undecoded gaps and decode by hand to
//! the same 28-byte shape, upstream 3.5.x verbatim):
//!
//! ```c
//! static int strCompare(const void *pKey1, int n1, const void *pKey2, int n2){
//!   if( n1!=n2 ) return 1;
//!   return sqlite3StrNICmp((const char*)pKey1,(const char*)pKey2,n1);
//! }
//! static int binCompare(const void *pKey1, int n1, const void *pKey2, int n2){
//!   if( n1!=n2 ) return 1;
//!   return memcmp(pKey1,pKey2,n1);
//! }
//! ```
//!
//! - `strCompare` — runtime 0x08386ef8, image 0x08391dd0 (28 bytes,
//!   directly before strHash @ image 0x08391dec): `mov r12,r1 /
//!   cmp r12,r3 / mov r1,r2 / moveq r2,r12 / beq str_nicmp /
//!   mov r0,#1 / bx lr`, the tail call landing on the ported
//!   [`super::stricmp::str_nicmp`] @ 0x08384fa0. Identified, not yet
//!   ported.
//! - `binCompare` — runtime 0x082ac998, image 0x082b7870 (28 bytes,
//!   directly before binHash @ image 0x082b788c): the identical shape
//!   tail-calling the ported `memcmp` @ 0x08030f64. Identified, not
//!   yet ported.
//!
//! Callers (both `bl` sites binary-scanned):
//!
//! - `sqlite3HashFind` @ 0x0837ad88 (`bl` @ 0x0837add8; ported as
//!   [`super::hash_find`]) — the lookup path; this port is its
//!   `find_elem` seam default.
//! - `sqlite3HashInsert` @ 0x0837ae08 (`bl` @ 0x0837ae64) — the
//!   duplicate-key probe of the insert/replace path.
//!
//! Deviations:
//!
//! - The original's comparator select is two literal-pool loads and an
//!   indirect `blx r6`; the port reads the same two pointers out of
//!   the volatile [`FIND_ELEMENT_HOOKS`] slots and makes the same
//!   indirect call — the shapes coincide. The slot defaults are the
//!   stock runtime addresses exactly as the original's literal pool
//!   holds them (the [`super::hash_function`] convention):
//!   transparent to on-target hooks planted on either stock body,
//!   while host tests substitute host-resident comparators.
//! - `hash` itself is NOT NULL-checked — the original dereferences
//!   +0x10 unconditionally and both callers pass a live `Hash` (the
//!   caller-side guard is [`super::hash_find`]'s own prologue).

use super::hash_clear::{Hash, HashElem};
use super::hash_function::SQLITE_HASH_STRING;

/// A key comparator in SQLite's `Hash` machinery: 0 when the
/// `len1`-byte key at `key1` equals the `len2`-byte key at `key2`,
/// nonzero otherwise. The original C type is
/// `int (*)(const void *, int, const void *, int)`; both stock
/// bodies return exactly 1 on a length mismatch.
pub type CompareFn =
    unsafe extern "C" fn(key1: *const u8, len1: i32, key2: *const u8, len2: i32) -> i32;

/// Runtime address of `strCompare` (image 0x08391dd0 under the
/// +0xaed8 skew — see [`super`]); identified, not yet ported. This is
/// the word stored in the original's literal pool at 0x082ce364,
/// selected for [`SQLITE_HASH_STRING`].
pub const STR_COMPARE_ADDR: usize = 0x0838_6ef8;

/// Runtime address of `binCompare` (image 0x082b7870); identified, not
/// yet ported. This is the word stored in the original's literal pool
/// at 0x082ce360, selected for every other key class.
pub const BIN_COMPARE_ADDR: usize = 0x082a_c998;

/// One bucket of the `Hash.ht` array: the 8-byte `{count, chain}` pair
/// the original indexes as `ht + h*8` (`add r1,r1,r3, lsl #3`), the
/// chain length at +0x00 (`ldr r5,[r1,#0x0]`) and the chain head at
/// +0x04 (`ldr r4,[r1,#0x4]`). On a 64-bit host `chain` widens and the
/// stride follows — harmless, all access goes through the struct.
#[repr(C)]
pub struct Bucket {
    /// Elements on this bucket's chain (upstream `_ht::count`).
    pub count: i32,
    /// Chain head (upstream `_ht::chain`).
    pub chain: *mut HashElem,
}

// Target-exact layout (the offsets the original's ldr literals
// encode); on a 64-bit host the pointer widens and the stride with it.
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::size_of::<Bucket>()];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(Bucket, chain)];

/// The unported comparators `find_element_given_hash` selects
/// between, modeled as the two words of the original's literal pool
/// (0x082ce360/0x082ce364) so host tests can substitute host-resident
/// bodies (the stock addresses are only callable on-target). The
/// slots are raw addresses — a host `const` cannot hold a fn pointer
/// to firmware — transmuted to [`CompareFn`] at the call site,
/// exactly the [`super::hash_function`] convention.
#[derive(Clone, Copy)]
pub struct FindElementHooks {
    /// The `ldreq r6,[0x82ce364]` word: `strCompare` @ runtime
    /// 0x08386ef8 (UNPORTED — [`STR_COMPARE_ADDR`] is the shipped
    /// default), the length-gated case-insensitive compare selected
    /// when `key_class == SQLITE_HASH_STRING`. Its body is
    /// `if (n1 != n2) return 1; return str_nicmp(p1, p2, n1)` — the
    /// tail call reaches the ported [`super::stricmp::str_nicmp`], so
    /// a host substitute is one line of glue.
    pub str_compare: usize,
    /// The `ldrne r6,[0x82ce360]` word: `binCompare` @ runtime
    /// 0x082ac998 (UNPORTED — [`BIN_COMPARE_ADDR`] is the shipped
    /// default), the length-gated raw compare selected for every
    /// other key class. Its body is
    /// `if (n1 != n2) return 1; return memcmp(p1, p2, n1)`,
    /// tail-calling the ported `memcmp` @ 0x08030f64.
    pub bin_compare: usize,
}

/// Wired default for [`FIND_ELEMENT_HOOKS`]: the stock runtime
/// addresses exactly as the original's literal pool holds them —
/// transparent to on-target hooks planted on either stock body,
/// callable on-target only.
pub const DEFAULT_FIND_ELEMENT_HOOKS: FindElementHooks = FindElementHooks {
    str_compare: STR_COMPARE_ADDR,
    bin_compare: BIN_COMPARE_ADDR,
};

/// Active model of the comparator select in
/// [`find_element_given_hash`]. Host tests replace both slots with
/// host-resident comparators; a later port of the two stock bodies
/// replaces the defaults without touching this caller.
pub static mut FIND_ELEMENT_HOOKS: FindElementHooks = DEFAULT_FIND_ELEMENT_HOOKS;

/// Reads a comparator slot and retypes it for the call. Volatile so
/// LLVM cannot constant-fold the load to the default (the house
/// pattern — `sqlite/blob_to_hex.rs`); the transmute is the
/// [`super::hash_function`] convention — the slot names firmware (or,
/// in host tests, host) code with the `CompareFn` signature.
#[inline(always)]
unsafe fn compare_op(slot: *const usize) -> CompareFn {
    let address = core::ptr::read_volatile(slot);
    core::mem::transmute::<usize, CompareFn>(address)
}

/// find_element_given_hash — original: `FUN_082ce2e8` @ 0x082ce2e8
/// (120 bytes; 2 `bl` call sites).
///
/// `findElementGivenHash`: walk bucket `h`'s chain of `hash`,
/// comparing each element's `(key @ +0x0c, n_key @ +0x10)` against
/// `(key, key_len)` through the `key_class`-selected comparator, and
/// return the first matching `HashElem` — or NULL when the bucket
/// array is NULL, the bucket's count is exhausted, or the chain ends.
///
/// # Safety
/// `hash` must be a valid `Hash` (or its firmware 20-byte layout) —
/// like the original, `hash` itself is never NULL-checked. `h` must
/// be in range of the `htsize`-entry bucket array when `ht` is
/// non-NULL, and every chain pointer a live `HashElem`. With the
/// default hook table the comparator is firmware code, callable
/// on-target only.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn find_element_given_hash(
    hash: *const Hash,
    key: *const u8,
    key_len: i32,
    h: u32,
) -> *mut HashElem {
    // `ldr r1,[r0,#0x10]` + `cmp`/`beq`: a table with no bucket array
    // finds nothing. `hash` itself is never NULL-checked — both
    // callers pass a live Hash.
    let hash = &*hash;
    if hash.ht.is_null() {
        return core::ptr::null_mut();
    }
    // `ldrb r0,[r0,#0x0]` + `cmp r0,#0x3` + `ldreq`/`ldrne`:
    // findCompareFunction, inlined — strCompare for string keys,
    // binCompare for everything else.
    let compare = if hash.key_class == SQLITE_HASH_STRING as u8 {
        compare_op(core::ptr::addr_of!(FIND_ELEMENT_HOOKS.str_compare))
    } else {
        compare_op(core::ptr::addr_of!(FIND_ELEMENT_HOOKS.bin_compare))
    };
    // `add r1,r1,r3,lsl #3` + `ldr r4,[r1,#0x4]` + `ldr r5,[r1,#0x0]`:
    // bucket h's chain head and chain length.
    let bucket = &*(hash.ht as *const Bucket).add(h as usize);
    let mut elem = bucket.chain;
    let mut count = bucket.count;
    // `sub r5,r5,#0x1` + `cmn r5,#0x1` + `cmpne r4,#0x0`:
    // while( count-- && elem ) — the count is decremented before the
    // test, so a zero count stops the walk even with a live chain.
    loop {
        count = count.wrapping_sub(1);
        if count == -1 || elem.is_null() {
            return core::ptr::null_mut();
        }
        // `ldr r0,[r4,#0xc]` + `ldr r1,[r4,#0x10]` + `blx r6`:
        // compare(elem->pKey, elem->nKey, pKey, nKey) == 0 is a hit.
        if compare((*elem).key, (*elem).n_key, key, key_len) == 0 {
            return elem;
        }
        // `ldrne r4,[r4,#0x0]`: on to the next chain node.
        elem = (*elem).next;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Serializes every host test that installs comparators into
    /// [`FIND_ELEMENT_HOOKS`]. This module's own tests and
    /// `super::hash_find`'s default-walker integration test both swap
    /// its slots, so a per-module lock would let one teardown restore
    /// defaults under the other's mock (the
    /// `crate::testing::BTREE_CELL_TEST_LOCK` rationale; kept here so
    /// the seam's owner ships the lock and the shared-static contract
    /// travels with it).
    pub(crate) static FIND_ELEMENT_TEST_LOCK: std::sync::Mutex<()> =
        std::sync::Mutex::new(());

    /// Every (key1, len1, key2, len2) either recording comparator was
    /// called with, in order.
    static mut COMPARE_CALLS: Vec<(*const u8, i32, *const u8, i32)> = Vec::new();
    /// Comparator results not equal to the byte-wise answer, keyed by
    /// call index (unused here — the honest compare suffices).
    fn record(args: (*const u8, i32, *const u8, i32)) {
        unsafe { (*core::ptr::addr_of_mut!(COMPARE_CALLS)).push(args) }
    }

    fn compare_calls() -> Vec<(*const u8, i32, *const u8, i32)> {
        unsafe { (*core::ptr::addr_of!(COMPARE_CALLS)).clone() }
    }

    /// Host-resident `strCompare` substitute, faithful to the stock
    /// shape: length gate first, then a case-insensitive byte compare
    /// through the ported [`crate::sqlite::stricmp::str_nicmp`].
    unsafe extern "C" fn host_str_compare(
        key1: *const u8,
        len1: i32,
        key2: *const u8,
        len2: i32,
    ) -> i32 {
        record((key1, len1, key2, len2));
        if len1 != len2 {
            return 1;
        }
        crate::sqlite::stricmp::str_nicmp(key1, key2, len1)
    }

    /// Host-resident `binCompare` substitute: length gate, then a raw
    /// byte compare.
    unsafe extern "C" fn host_bin_compare(
        key1: *const u8,
        len1: i32,
        key2: *const u8,
        len2: i32,
    ) -> i32 {
        record((key1, len1, key2, len2));
        if len1 != len2 {
            return 1;
        }
        let a = core::slice::from_raw_parts(key1, len1 as usize);
        let b = core::slice::from_raw_parts(key2, len2 as usize);
        (a != b) as i32
    }

    /// Installs the host comparators and clears the call log; the
    /// returned guard holds the seam lock for the test body and
    /// restores the stock-address defaults on drop.
    struct HookGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for HookGuard {
        fn drop(&mut self) {
            unsafe {
                *core::ptr::addr_of_mut!(FIND_ELEMENT_HOOKS) = DEFAULT_FIND_ELEMENT_HOOKS;
            }
        }
    }

    fn with_host_comparators() -> HookGuard {
        let guard = HookGuard {
            _guard: FIND_ELEMENT_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        };
        unsafe {
            (*core::ptr::addr_of_mut!(COMPARE_CALLS)).clear();
            *core::ptr::addr_of_mut!(FIND_ELEMENT_HOOKS) = FindElementHooks {
                str_compare: host_str_compare as CompareFn as usize,
                bin_compare: host_bin_compare as CompareFn as usize,
            };
        }
        guard
    }

    /// A `Hash` over `buckets`, string key class by default. (`Hash._pad`
    /// is private to `hash_clear`, so the fixture is a zeroed struct
    /// with the live fields poked in — the `hash_find` precedent.)
    fn hash_over(buckets: &[Bucket], key_class: u8) -> Hash {
        let mut hash: Hash = unsafe { core::mem::zeroed() };
        hash.key_class = key_class;
        hash.htsize = buckets.len() as u32;
        hash.ht = buckets.as_ptr() as *mut u8;
        hash
    }

    /// A chain node holding a borrowed key; `next` is linked by the
    /// fixture builder.
    fn elem(key: &'static [u8]) -> HashElem {
        HashElem {
            next: core::ptr::null_mut(),
            prev: core::ptr::null_mut(),
            data: core::ptr::null_mut(),
            key: key.as_ptr() as *mut u8,
            n_key: key.len() as i32,
        }
    }

    /// Builds one bucket holding a chain of `keys` (head first).
    /// Returns the node storage — which must outlive every walk — and
    /// the bucket pointing at the chain head.
    fn chain_of(keys: &[&'static [u8]]) -> (Vec<HashElem>, Bucket) {
        let mut nodes: Vec<HashElem> = keys.iter().map(|key| elem(key)).collect();
        let mut chain: *mut HashElem = core::ptr::null_mut();
        for node in nodes.iter_mut().rev() {
            node.next = chain;
            chain = node;
        }
        let bucket = Bucket {
            count: keys.len() as i32,
            chain,
        };
        (nodes, bucket)
    }

    /// Raw address of node `i` in a fixture's storage.
    fn node_ptr(nodes: &[HashElem], i: usize) -> *mut HashElem {
        &nodes[i] as *const HashElem as *mut HashElem
    }

    #[test]
    fn default_slots_are_the_stock_runtime_addresses() {
        assert_eq!(
            DEFAULT_FIND_ELEMENT_HOOKS.str_compare,
            STR_COMPARE_ADDR,
            "str_compare ships the stock strCompare runtime address (pool word @ 0x082ce364)"
        );
        assert_eq!(
            DEFAULT_FIND_ELEMENT_HOOKS.bin_compare,
            BIN_COMPARE_ADDR,
            "bin_compare ships the stock binCompare runtime address (pool word @ 0x082ce360)"
        );
    }

    #[test]
    fn null_bucket_array_returns_null_without_comparing() {
        let _hooks = with_host_comparators();
        let mut hash: Hash = unsafe { core::mem::zeroed() };
        hash.key_class = SQLITE_HASH_STRING as u8;
        let found = unsafe { find_element_given_hash(&hash, b"k".as_ptr(), 1, 0) };
        assert!(found.is_null(), "no bucket array finds nothing");
        assert!(
            compare_calls().is_empty(),
            "the comparator is never reached"
        );
    }

    #[test]
    fn empty_bucket_stops_before_the_chain() {
        let _hooks = with_host_comparators();
        // count == 0 with a LIVE chain pointer: the `count--` runs
        // first, so the walk never looks at the chain.
        let (_nodes, mut bucket) = chain_of(&[b"key"]);
        bucket.count = 0;
        let hash = hash_over(std::slice::from_ref(&bucket), SQLITE_HASH_STRING as u8);
        let found = unsafe { find_element_given_hash(&hash, b"key".as_ptr(), 3, 0) };
        assert!(found.is_null(), "an exhausted count finds nothing");
        assert!(
            compare_calls().is_empty(),
            "count == 0 never consults the chain"
        );
    }

    #[test]
    fn single_element_hit_returns_the_node() {
        let _hooks = with_host_comparators();
        let (nodes, bucket) = chain_of(&[b"Alpha"]);
        let buckets = [bucket];
        let hash = hash_over(&buckets, SQLITE_HASH_STRING as u8);
        let key = b"alpha".as_ptr(); // strCompare is case-insensitive
        let found = unsafe { find_element_given_hash(&hash, key, 5, 0) };
        assert_eq!(found, node_ptr(&nodes, 0), "the matching node itself");
        assert_eq!(
            compare_calls(),
            std::vec![(b"Alpha".as_ptr(), 5, key, 5)],
            "comparator gets (elem->pKey @ +0x0c, elem->nKey @ +0x10, pKey, nKey)"
        );
    }

    #[test]
    fn chain_walk_hits_first_middle_and_last() {
        let _hooks = with_host_comparators();
        let keys: [&'static [u8]; 3] = [b"one", b"two", b"three"];
        for hit in 0..3 {
            let (nodes, bucket) = chain_of(&keys);
            let buckets = [bucket];
            let hash = hash_over(&buckets, SQLITE_HASH_STRING as u8);
            let wanted = keys[hit];
            let found = unsafe {
                find_element_given_hash(&hash, wanted.as_ptr(), wanted.len() as i32, 0)
            };
            assert_eq!(found, node_ptr(&nodes, hit), "hit at chain position {hit}");
            assert_eq!(
                compare_calls().len(),
                hit + 1,
                "the walk stops at the first match (position {hit})"
            );
            unsafe { (*core::ptr::addr_of_mut!(COMPARE_CALLS)).clear() };
        }
    }

    #[test]
    fn mismatched_elements_are_skipped_down_the_chain() {
        let _hooks = with_host_comparators();
        let (nodes, bucket) = chain_of(&[b"toolong", b"no", b"ok"]);
        let buckets = [bucket];
        let hash = hash_over(&buckets, SQLITE_HASH_STRING as u8);
        let found = unsafe { find_element_given_hash(&hash, b"ok".as_ptr(), 2, 0) };
        assert_eq!(found, node_ptr(&nodes, 2), "the walker skips past both misses");
        assert_eq!(compare_calls().len(), 3, "every element compared once");
    }

    #[test]
    fn absent_key_returns_null_after_the_whole_chain() {
        let _hooks = with_host_comparators();
        let (_nodes, bucket) = chain_of(&[b"one", b"two"]);
        let buckets = [bucket];
        let hash = hash_over(&buckets, SQLITE_HASH_STRING as u8);
        let found = unsafe { find_element_given_hash(&hash, b"absent".as_ptr(), 6, 0) };
        assert!(found.is_null(), "no match anywhere is NULL");
        assert_eq!(compare_calls().len(), 2, "the whole chain was walked");
    }

    #[test]
    fn a_short_count_truncates_the_walk() {
        let _hooks = with_host_comparators();
        // count < chain length: the bucket's count governs, not the
        // chain's end — a matching tail node is never reached.
        let (_nodes, mut bucket) = chain_of(&[b"one", b"two"]);
        bucket.count = 1;
        let buckets = [bucket];
        let hash = hash_over(&buckets, SQLITE_HASH_STRING as u8);
        let found = unsafe { find_element_given_hash(&hash, b"two".as_ptr(), 3, 0) };
        assert!(found.is_null(), "count 1 never reaches the second node");
        assert_eq!(compare_calls().len(), 1, "exactly one comparison");
    }

    #[test]
    fn a_long_count_stops_at_the_chain_end() {
        let _hooks = with_host_comparators();
        // count > chain length: the NULL link ends the walk first.
        let (_nodes, mut bucket) = chain_of(&[b"one"]);
        bucket.count = 5;
        let buckets = [bucket];
        let hash = hash_over(&buckets, SQLITE_HASH_STRING as u8);
        let found = unsafe { find_element_given_hash(&hash, b"absent".as_ptr(), 6, 0) };
        assert!(found.is_null());
        assert_eq!(
            compare_calls().len(),
            1,
            "the NULL chain link, not the count, ends the walk"
        );
    }

    #[test]
    fn the_bucket_index_selects_the_pair() {
        let _hooks = with_host_comparators();
        let (_one, bucket_one) = chain_of(&[b"one"]);
        let (two, bucket_two) = chain_of(&[b"two"]);
        let buckets = [
            Bucket {
                count: 0,
                chain: core::ptr::null_mut(),
            },
            bucket_one,
            bucket_two,
        ];
        let hash = hash_over(&buckets, SQLITE_HASH_STRING as u8);
        // Bucket 2 holds "two"; asking for it from bucket 1 (which
        // holds "one") misses — the index picks the pair.
        let missed = unsafe { find_element_given_hash(&hash, b"two".as_ptr(), 3, 1) };
        assert!(missed.is_null(), "bucket 1 does not hold 'two'");
        let found = unsafe { find_element_given_hash(&hash, b"two".as_ptr(), 3, 2) };
        assert_eq!(found, node_ptr(&two, 0), "bucket 2 does");
    }

    #[test]
    fn binary_keys_take_the_bin_compare_slot() {
        let _hooks = with_host_comparators();
        let (nodes, bucket) = chain_of(&[b"\x01\x02"]);
        let buckets = [bucket];
        for class in [0u8, 1, 2, 4, 5, 255] {
            let hash = hash_over(&buckets, class);
            let found =
                unsafe { find_element_given_hash(&hash, b"\x01\x02".as_ptr(), 2, 0) };
            assert_eq!(
                found,
                node_ptr(&nodes, 0),
                "class {class} selects binCompare (only 3 is strCompare)"
            );
        }
        // Same node under the string class still hits — and the
        // length gate fires on a length mismatch.
        let hash = hash_over(&buckets, SQLITE_HASH_STRING as u8);
        let found = unsafe { find_element_given_hash(&hash, b"\x01\x02\x03".as_ptr(), 3, 0) };
        assert!(found.is_null(), "n1 != n2 is a miss, by length alone");
    }
}
