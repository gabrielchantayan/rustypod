//! Finding an entry in SQLite's generic symbol-table hash —
//! `sqlite3HashFind` from hash.c, the read path of the `Hash`
//! machinery [`super::hash_init`] constructs and
//! [`super::hash_clear`] destroys.
//!
//! - `hash_find` — original: `FUN_0837ad88` @ 0x0837ad88 (96 bytes;
//!   11 `bl` call sites, binary-scanned). SQLite 3.4.x/3.5.x's
//!   `sqlite3HashFind`:
//!
//! ```c
//! void *sqlite3HashFind(const Hash *pH, const void *pKey, int nKey){
//!   HashElem *elem;                /* The element that matches key */
//!   if( pH==0 || pH->ht==0 ) return 0;
//!   elem = findElementGivenHash(pH, pKey, nKey,
//!                               sqlite3HashValue(pH, pKey, nKey));
//!   return elem ? elem->data : 0;
//! }
//! ```
//!
//! with `sqlite3HashValue` inlined: the keyClass-selected key hash of
//! `(pKey, nKey)` taken modulo `htsize`. The whole body, predicated
//! NULL guards included:
//!
//! ```text
//! 0837ad88:  stmdb sp!,{r4,r5,r6,lr}
//! 0837ad8c:  movs r4,r0           ; hash, flags
//! 0837ad90:  ldrne r0,[r4,#0x10] ; ht, only if hash != NULL
//! 0837ad94:  mov  r6,r2          ; nKey
//! 0837ad98:  cmpne r0,#0x0
//! 0837ad9c:  moveq r0,#0x0       ; hash == NULL or ht == NULL
//! 0837ada0:  mov  r5,r1          ; pKey
//! 0837ada4:  beq  0x0837addc     ;   -> return NULL
//! 0837ada8:  ldrb r0,[r4,#0x0]   ; keyClass
//! 0837adac:  bl   0x082d2a1c     ; hash_function (ported)
//! 0837adb0:  mov  r2,r0
//! 0837adb4:  mov  r0,r5
//! 0837adb8:  mov  r1,r6
//! 0837adbc:  blx  r2             ; h = hashfn(pKey, nKey)
//! 0837adc0:  ldr  r1,[r4,#0x8]   ; htsize
//! 0837adc4:  bl   0x08031568     ; __rt_sdiv: r0 = quot, r1 = rem
//! 0837adc8:  mov  r3,r1          ; bucket = h % htsize (remainder!)
//! 0837adcc:  mov  r1,r5
//! 0837add0:  mov  r2,r6
//! 0837add4:  mov  r0,r4
//! 0837add8:  bl   0x082ce2e8     ; findElementGivenHash (seam)
//! 0837addc:  cmp  r0,#0x0
//! 0837ade0:  ldrne r0,[r0,#0x8]  ; elem ? elem->data : NULL
//! 0837ade4:  ldmia sp!,{r4,r5,r6,pc}
//! ```
//!
//! Three facts this body pins:
//!
//! - The bucket index is the signed-division *remainder* (`mov r3,r1`
//!   after the divide), i.e. upstream's `% pH->htsize` — not the
//!   `h & (htsize - 1)` a power-of-two table could get away with.
//!   Both key hashes return `h & 0x7fffffff`, so the signed remainder
//!   is the unsigned one on every reachable path.
//! - The found element's payload is the word at `HashElem + 0x08` —
//!   the `data` of upstream 3.4.x's `{next, prev, data, pKey, nKey}`,
//!   agreeing with the `next` @ +0x00 / `key` @ +0x0c layout
//!   [`super::hash_clear`] pins.
//! - The walk helper takes the bucket index in r3, not a masked
//!   pointer: `findElementGivenHash(hash, pKey, nKey, h % htsize)`.
//!
//! The two callees:
//!
//! - `hashFunction` @ 0x082d2a1c — ported as
//!   [`super::hash_function::hash_function`], and this module's
//!   `hash_dispatch` slot defaults to the real port. The slot exists
//!   because the real dispatcher returns *firmware runtime addresses*
//!   (transparent to on-target hooks planted on the stock hash
//!   bodies — see its own doc header); those pointers are only
//!   callable on-target, so host tests substitute a dispatcher whose
//!   tables are host-resident.
//! - `findElementGivenHash` @ 0x082ce2e8 — ported as
//!   [`super::find_element_given_hash::find_element_given_hash`], the
//!   shipped default of this module's `find_elem` seam (see
//!   [`HashFindHooks`]). Its disassembly (bucket = `ht + h*8` of
//!   {count, chain} pairs, keyClass-selected comparator blx'd with
//!   (elem->key @ +0x0c, elem->nKey @ +0x10, pKey, nKey), chain
//!   walked via `next` @ +0x00) pinned `HashElem.nKey` at +0x10 —
//!   the field its port added to [`super::hash_clear`]'s struct.
//!
//! Callers (11 `bl` sites, all binary-scanned; none of the enclosing
//! functions is named yet — the `Hash`-offset evidence is what
//! identifies them):
//!
//! - 0x082ce250 in the find-or-create helper @ 0x082ce220: looks up
//!   the db handle's +0x128 hash (the aCollSeq-family table
//!   [`super::hash_init`] documents) by NUL-terminated name
//!   (`nKey = strlen`), and on a miss mallocs, fills and
//!   `sqlite3HashInsert`s a new entry — the classic
//!   `sqlite3FindFunction` shape.
//! - 0x0838d52c: `db + 0xf4` (aModule family) looked up by a
//!   strlen'd module name, the result stored at caller +0x3c.
//! - 0x0836fecc: a +0x2c hash of a 0x18-strided table object
//!   (trigHash-style), NULL result branching to a create path.
//! - 0x082c52d8, 0x08375c98, 0x083761bc, 0x08378bbc, 0x08378ffc,
//!   0x08379094, 0x083794e0, 0x08385354: the remaining name-lookup
//!   sites in the parser/VDEF half of the SQLite unit.
//!
//! Deviations:
//!
//! - The original's `bl 0x082d2a1c` / `bl 0x082ce2e8` are direct
//!   calls; the port reaches both through the volatile hook slots of
//!   [`HASH_FIND_HOOKS`] (the house seam convention —
//!   `sqlite/cell_size.rs`), so the shipped image's indirect `blx`
//!   replaces two direct `bl`s. The defaults make the indirection
//!   behaviorally transparent: the real ported dispatcher and the
//!   real ported walker.
//! - The remainder comes out of the ported
//!   [`__rt_sdivmod`]'s out-param where the original reads r1 after
//!   `bl 0x08031568`; same divide, same div0 funnel on the
//!   unreachable `htsize == 0` path. LLVM inlines the divide into the
//!   body (the `hash_clear`/`tracked_free` precedent — same bytes,
//!   different shape), so the original's `bl 0x08031568` boundary
//!   does not survive in the match.py diff.

use super::find_element_given_hash::find_element_given_hash;
use super::hash_clear::{Hash, HashElem};
use super::hash_function::{hash_function, HashFn};
use crate::runtime::rt_div::__rt_sdivmod;

/// The unported services `hash_find` reaches, plus the ported
/// dispatcher host tests must be able to replace (the real one
/// returns firmware addresses — see the module header).
#[derive(Clone, Copy)]
pub struct HashFindHooks {
    /// `hashFunction` @ 0x082d2a1c (ported —
    /// [`super::hash_function::hash_function`] is the shipped
    /// default): select the key hash for `key_class`. The returned
    /// pointer is blx'd with `(key, key_len)` exactly like the
    /// original's `blx r2`; with the default slot that pointer names
    /// firmware code and is only callable on-target.
    pub hash_dispatch: unsafe extern "C" fn(key_class: i32) -> HashFn,
    /// `findElementGivenHash` @ 0x082ce2e8 (ported —
    /// [`super::find_element_given_hash::find_element_given_hash`] is
    /// the shipped default): walk bucket `h`'s chain comparing
    /// `(key, key_len)` against each element's key @ +0x0c / nKey
    /// @ +0x10 through the keyClass-selected comparator, and return
    /// the matching `HashElem` or NULL. See
    /// `decomp/c/031/082ce2e8_FUN_082ce2e8.c`. The walker's own
    /// comparator select goes through its `FIND_ELEMENT_HOOKS` seam,
    /// whose stock-address defaults are callable on-target only —
    /// host tests of the real walker substitute host comparators
    /// there, not in this slot.
    pub find_elem: unsafe extern "C" fn(
        hash: *const Hash,
        key: *const u8,
        key_len: i32,
        h: u32,
    ) -> *mut HashElem,
}

/// Wired default for [`HASH_FIND_HOOKS`]: the real ported
/// `hashFunction` (its returned pointers resolve on-target through
/// the stock-address hooks, as its own doc header describes) and the
/// real ported walker @ 0x082ce2e8.
pub const DEFAULT_HASH_FIND_HOOKS: HashFindHooks = HashFindHooks {
    hash_dispatch: hash_function,
    find_elem: find_element_given_hash,
};

/// Active model of the dispatcher and walker calls in [`hash_find`].
/// Host tests replace both slots to observe the exact arguments; the
/// walker's own comparator seam lives one module down, in
/// [`super::find_element_given_hash`].
pub static mut HASH_FIND_HOOKS: HashFindHooks = DEFAULT_HASH_FIND_HOOKS;

/// Reads the dispatcher slot. Volatile so LLVM cannot constant-fold
/// the load to the default (the house pattern — `sqlite/blob_to_hex.rs`).
#[inline(always)]
unsafe fn hash_dispatch_op() -> unsafe extern "C" fn(i32) -> HashFn {
    core::ptr::read_volatile(core::ptr::addr_of!(HASH_FIND_HOOKS.hash_dispatch))
}

/// Reads the `findElementGivenHash` slot. Volatile, same rationale as
/// `hash_dispatch_op` above.
#[inline(always)]
unsafe fn find_elem_op() -> unsafe extern "C" fn(*const Hash, *const u8, i32, u32) -> *mut HashElem {
    core::ptr::read_volatile(core::ptr::addr_of!(HASH_FIND_HOOKS.find_elem))
}

/// hash_find — original: `FUN_0837ad88` @ 0x0837ad88 (96 bytes; 11
/// `bl` call sites).
///
/// `sqlite3HashFind`: return the payload (`HashElem.data` @ +0x08) of
/// the element matching `(key, key_len)` in `hash`, or NULL when
/// `hash` is NULL, its bucket array is NULL, or no element matches.
/// The bucket is `hashfn(key, key_len) % htsize` with `hashfn`
/// selected by `key_class` through the ported
/// [`super::hash_function::hash_function`].
///
/// # Safety
/// `hash`, when non-NULL, must be a valid `Hash` (or its firmware
/// 20-byte layout) with a live bucket array; `key` must be readable
/// for the key hash the dispatcher selects (a NUL-terminated string
/// for the strlen-probing `strHash` when `key_len <= 0`). With the
/// default hook table the dispatcher's returned hash is firmware
/// code, callable on-target only.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn hash_find(hash: *const Hash, key: *const u8, key_len: i32) -> *mut u8 {
    // `movs r4,r0` + predicated `ldrne`/`cmpne`/`moveq`/`beq`: a NULL
    // hash — or one with a NULL bucket array — finds nothing, and the
    // dispatcher is never reached.
    if hash.is_null() || (*hash).ht.is_null() {
        return core::ptr::null_mut();
    }
    let hash = &*hash;
    // `ldrb r0,[r4,#0x0]` + `bl 0x082d2a1c` + `blx r2`: the
    // keyClass-selected hash of (pKey, nKey).
    let h = (hash_dispatch_op()(hash.key_class as i32))(key, key_len);
    // `ldr r1,[r4,#0x8]` + `bl 0x08031568` + `mov r3,r1`: the bucket
    // index is the division *remainder*, h % htsize. Both key hashes
    // return h & 0x7fffffff, so the signed divide never sees a
    // negative numerator on a reachable path.
    let mut bucket: i32 = 0;
    __rt_sdivmod(h as i32, hash.htsize as i32, &mut bucket);
    // `bl 0x082ce2e8` with (hash, pKey, nKey, bucket).
    let elem = find_elem_op()(hash, key, key_len, bucket as u32);
    // `cmp r0,#0x0` + `ldrne r0,[r0,#0x8]`: the payload word or NULL.
    if elem.is_null() {
        core::ptr::null_mut()
    } else {
        (*elem).data
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Serializes the tests that swap [`HASH_FIND_HOOKS`] (the static
    /// is private to this module, so a module-local lock suffices —
    /// the `BTREE_CELL_TEST_LOCK` precedent is for statics shared
    /// across modules).
    static HOOK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Every key_class the mock dispatcher was asked about, in order.
    static mut DISPATCH_CALLS: Vec<i32> = Vec::new();
    /// Every (key, key_len) the mock key hash was called with.
    static mut HASH_CALLS: Vec<(*const u8, i32)> = Vec::new();
    /// Every (hash, key, key_len, bucket) the mock walker was called with.
    static mut FIND_CALLS: Vec<(*const Hash, *const u8, i32, u32)> = Vec::new();
    /// Value the mock key hash returns.
    static mut HASH_RESULT: u32 = 0;
    /// Value the mock walker returns.
    static mut FIND_RESULT: *mut HashElem = core::ptr::null_mut();

    unsafe extern "C" fn mock_dispatch(key_class: i32) -> HashFn {
        (*core::ptr::addr_of_mut!(DISPATCH_CALLS)).push(key_class);
        mock_hash
    }

    unsafe extern "C" fn mock_hash(key: *const u8, key_len: i32) -> u32 {
        (*core::ptr::addr_of_mut!(HASH_CALLS)).push((key, key_len));
        *core::ptr::addr_of!(HASH_RESULT)
    }

    unsafe extern "C" fn mock_find_elem(
        hash: *const Hash,
        key: *const u8,
        key_len: i32,
        h: u32,
    ) -> *mut HashElem {
        (*core::ptr::addr_of_mut!(FIND_CALLS)).push((hash, key, key_len, h));
        *core::ptr::addr_of!(FIND_RESULT)
    }

    /// Installs the recording mocks and clears the logs; the returned
    /// guard holds the hook lock for the test body and restores the
    /// defaults on drop.
    struct HookGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for HookGuard {
        fn drop(&mut self) {
            unsafe {
                *core::ptr::addr_of_mut!(HASH_FIND_HOOKS) = DEFAULT_HASH_FIND_HOOKS;
            }
        }
    }

    fn with_mock_hooks() -> HookGuard {
        let guard = HookGuard {
            _guard: HOOK_LOCK.lock().unwrap(),
        };
        unsafe {
            (*core::ptr::addr_of_mut!(DISPATCH_CALLS)).clear();
            (*core::ptr::addr_of_mut!(HASH_CALLS)).clear();
            (*core::ptr::addr_of_mut!(FIND_CALLS)).clear();
            *core::ptr::addr_of_mut!(HASH_RESULT) = 0;
            *core::ptr::addr_of_mut!(FIND_RESULT) = core::ptr::null_mut();
            *core::ptr::addr_of_mut!(HASH_FIND_HOOKS) = HashFindHooks {
                hash_dispatch: mock_dispatch,
                find_elem: mock_find_elem,
            };
        }
        guard
    }

    fn dispatch_calls() -> Vec<i32> {
        unsafe { (*core::ptr::addr_of!(DISPATCH_CALLS)).clone() }
    }
    fn hash_calls() -> Vec<(*const u8, i32)> {
        unsafe { (*core::ptr::addr_of!(HASH_CALLS)).clone() }
    }
    fn find_calls() -> Vec<(*const Hash, *const u8, i32, u32)> {
        unsafe { (*core::ptr::addr_of!(FIND_CALLS)).clone() }
    }

    /// A live-looking `Hash`: non-NULL bucket array, htsize 8, string
    /// key class. (`Hash._pad` is private to `hash_clear`, so the
    /// fixture is a zeroed struct with the live fields poked in.)
    fn live_hash() -> Hash {
        let mut hash: Hash = unsafe { core::mem::zeroed() };
        hash.key_class = 3;
        hash.count = 1;
        hash.htsize = 8;
        hash.ht = 0x1000 as *mut u8; // never dereferenced through the seam
        hash
    }

    #[test]
    fn default_slots_are_the_ported_dispatch_and_the_ported_walker() {
        assert_eq!(
            DEFAULT_HASH_FIND_HOOKS.hash_dispatch as usize,
            hash_function as *const () as usize,
            "the dispatch slot ships the real ported hashFunction"
        );
        assert_eq!(
            DEFAULT_HASH_FIND_HOOKS.find_elem as usize,
            find_element_given_hash as *const () as usize,
            "the walker slot ships the real ported findElementGivenHash"
        );
    }

    #[test]
    fn null_hash_returns_null_without_touching_the_hooks() {
        let _hooks = with_mock_hooks();
        let found = unsafe { hash_find(core::ptr::null(), b"k".as_ptr(), 1) };
        assert!(found.is_null(), "NULL hash finds nothing");
        assert!(dispatch_calls().is_empty(), "dispatcher never reached");
        assert!(find_calls().is_empty(), "walker never reached");
    }

    #[test]
    fn null_bucket_array_returns_null_without_touching_the_hooks() {
        let _hooks = with_mock_hooks();
        let mut hash = live_hash();
        hash.ht = core::ptr::null_mut();
        let found = unsafe { hash_find(&hash, b"k".as_ptr(), 1) };
        assert!(found.is_null(), "empty table finds nothing");
        assert!(dispatch_calls().is_empty(), "dispatcher never reached");
        assert!(find_calls().is_empty(), "walker never reached");
    }

    #[test]
    fn key_class_drives_the_dispatch_and_the_bucket_is_the_remainder() {
        let _hooks = with_mock_hooks();
        let hash = live_hash(); // key_class 3, htsize 8
        let key = b"Name".as_ptr();
        unsafe {
            *core::ptr::addr_of_mut!(HASH_RESULT) = 13; // 13 % 8 = 5
            let found = hash_find(&hash, key, -7); // negative nKey: strlen probe
            assert!(found.is_null(), "the default mock walker finds nothing");
        }
        assert_eq!(dispatch_calls(), std::vec![3], "keyClass @ +0x00, once");
        assert_eq!(
            hash_calls(),
            std::vec![(key, -7)],
            "(pKey, nKey) blx'd verbatim — the negative probe survives"
        );
        assert_eq!(
            find_calls(),
            std::vec![(&hash as *const Hash, key, -7, 5)],
            "walker gets (hash, pKey, nKey, h % htsize) — the remainder, not the quotient"
        );
    }

    #[test]
    fn binary_key_class_reaches_the_dispatcher_verbatim() {
        let _hooks = with_mock_hooks();
        let mut hash = live_hash();
        hash.key_class = 4; // SQLITE_HASH_BINARY
        unsafe {
            hash_find(&hash, b"\x01\x02".as_ptr(), 2);
        }
        assert_eq!(dispatch_calls(), std::vec![4], "binary class dispatched as 4");
    }

    #[test]
    fn found_element_yields_its_data_word() {
        let _hooks = with_mock_hooks();
        let hash = live_hash();
        let payload = 0x0ead_beef as *mut u8;
        let mut elem = HashElem {
            next: core::ptr::null_mut(),
            prev: core::ptr::null_mut(),
            data: payload,
            key: core::ptr::null_mut(),
            n_key: 0,
        };
        unsafe {
            *core::ptr::addr_of_mut!(FIND_RESULT) = &mut elem;
            let found = hash_find(&hash, b"k".as_ptr(), 1);
            assert_eq!(found, payload, "elem ? elem->data @ +0x08 : NULL");
        }
    }

    #[test]
    fn not_found_yields_null() {
        let _hooks = with_mock_hooks();
        let hash = live_hash();
        let found = unsafe { hash_find(&hash, b"absent".as_ptr(), 6) };
        assert!(found.is_null(), "a NULL from the walker is a NULL result");
        assert_eq!(find_calls().len(), 1, "the walk happened");
    }

    #[test]
    fn htsize_one_buckets_everything_to_zero() {
        let _hooks = with_mock_hooks();
        let mut hash = live_hash();
        hash.htsize = 1;
        unsafe {
            *core::ptr::addr_of_mut!(HASH_RESULT) = 0x7fff_ffff;
            hash_find(&hash, b"k".as_ptr(), 1);
        }
        assert_eq!(
            find_calls()[0].3,
            0,
            "the largest strHash output mod 1: the remainder path, not a mask"
        );
    }

    // --- Integration through the real default walker ---------------
    //
    // `hash_find` with its shipped `find_elem` default — the ported
    // findElementGivenHash — over a hand-built live table. Only the
    // two firmware-address boundaries are stubbed host-side: the key
    // hash (a dispatcher returning the ported string_hash_tabled) and
    // the comparators (the stock strCompare/binCompare shapes over the
    // ported str_nicmp / a slice compare).

    use crate::sqlite::find_element_given_hash::tests::FIND_ELEMENT_TEST_LOCK;
    use crate::sqlite::find_element_given_hash::{
        Bucket, CompareFn, FindElementHooks, DEFAULT_FIND_ELEMENT_HOOKS, FIND_ELEMENT_HOOKS,
    };
    use crate::sqlite::strhash::string_hash_tabled;
    use crate::sqlite::stricmp::str_nicmp;

    /// The stock `strCompare` shape, host-resident.
    unsafe extern "C" fn host_str_compare(
        key1: *const u8,
        len1: i32,
        key2: *const u8,
        len2: i32,
    ) -> i32 {
        if len1 != len2 {
            return 1;
        }
        str_nicmp(key1, key2, len1)
    }

    /// The stock `binCompare` shape, host-resident.
    unsafe extern "C" fn host_bin_compare(
        key1: *const u8,
        len1: i32,
        key2: *const u8,
        len2: i32,
    ) -> i32 {
        if len1 != len2 {
            return 1;
        }
        let a = core::slice::from_raw_parts(key1, len1 as usize);
        let b = core::slice::from_raw_parts(key2, len2 as usize);
        (a != b) as i32
    }

    /// A dispatcher whose string hash is the ported `strHash` body.
    unsafe extern "C" fn host_string_dispatch(_key_class: i32) -> HashFn {
        string_hash_tabled
    }

    /// Holds the walker module's seam lock and restores its stock
    /// defaults on drop (the HookGuard pattern, one module down).
    struct FindElemGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for FindElemGuard {
        fn drop(&mut self) {
            unsafe {
                *core::ptr::addr_of_mut!(FIND_ELEMENT_HOOKS) = DEFAULT_FIND_ELEMENT_HOOKS;
            }
        }
    }

    fn with_host_comparators() -> FindElemGuard {
        let guard = FindElemGuard {
            _guard: FIND_ELEMENT_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        };
        unsafe {
            *core::ptr::addr_of_mut!(FIND_ELEMENT_HOOKS) = FindElementHooks {
                str_compare: host_str_compare as CompareFn as usize,
                bin_compare: host_bin_compare as CompareFn as usize,
            };
        }
        guard
    }

    #[test]
    fn hash_find_through_the_real_default_walker() {
        let _hooks = with_mock_hooks();
        let _comparators = with_host_comparators();
        unsafe {
            (*core::ptr::addr_of_mut!(HASH_FIND_HOOKS)).hash_dispatch = host_string_dispatch;
            // The shipped default slot — the function under test.
            (*core::ptr::addr_of_mut!(HASH_FIND_HOOKS)).find_elem = find_element_given_hash;
        }

        // A live 8-bucket table, laid out exactly as the firmware's
        // sqlite3HashInsert would: bucket = strHash(key) % htsize,
        // newest element at the chain head.
        let keys: [&'static [u8]; 3] = [b"alpha", b"beta", b"gamma"];
        let mut elems: Vec<HashElem> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| HashElem {
                next: core::ptr::null_mut(),
                prev: core::ptr::null_mut(),
                data: (0x1000 + i) as *mut u8,
                key: key.as_ptr() as *mut u8,
                n_key: key.len() as i32,
            })
            .collect();
        let mut buckets: Vec<Bucket> = (0..8)
            .map(|_| Bucket {
                count: 0,
                chain: core::ptr::null_mut(),
            })
            .collect();
        for elem in elems.iter_mut() {
            let bucket =
                unsafe { string_hash_tabled(elem.key, elem.n_key) } % 8;
            elem.next = buckets[bucket as usize].chain;
            buckets[bucket as usize].chain = elem;
            buckets[bucket as usize].count += 1;
        }
        let mut hash: Hash = unsafe { core::mem::zeroed() };
        hash.key_class = 3; // SQLITE_HASH_STRING
        hash.count = 3;
        hash.htsize = 8;
        hash.ht = buckets.as_mut_ptr() as *mut u8;

        for (i, key) in keys.iter().enumerate() {
            let found = unsafe { hash_find(&hash, key.as_ptr(), key.len() as i32) };
            assert_eq!(
                found,
                (0x1000 + i) as *mut u8,
                "the real walker recovers {:?}'s payload",
                core::str::from_utf8(key).unwrap()
            );
        }
        // Case folds end to end: the ported strHash buckets "ALPHA"
        // with "alpha", and the stock strCompare shape (over the
        // ported str_nicmp) matches it.
        let found = unsafe { hash_find(&hash, b"ALPHA".as_ptr(), 5) };
        assert_eq!(found, 0x1000 as *mut u8, "case-insensitive hit");
        // An absent key hashes, walks its bucket, and misses.
        let found = unsafe { hash_find(&hash, b"delta".as_ptr(), 5) };
        assert!(found.is_null(), "absent key: the walk ends in NULL");
    }
}
