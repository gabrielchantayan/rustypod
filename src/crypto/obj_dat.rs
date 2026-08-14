//! OpenSSL's object-identifier database — the NID lookup.
//!
//! `obj_obj2nid` — original: `FUN_0805f074` @ 0x0805f074 (156 bytes:
//! 140 of code plus the four literal-pool words @ 0x0805f100..0x0805f10c
//! — Ghidra's `functions.csv` reports 140 and drops the pool; the next
//! function starts at 0x0805f110. 57 `bl` call sites and zero predicated
//! or plain `b`, binary-scanned over every branch word in
//! `work/firmware/osos.dec`).
//!
//! # What it is
//!
//! Upstream OpenSSL `crypto/objects/obj_dat.c`:
//!
//! ```c
//! int OBJ_obj2nid(const ASN1_OBJECT *a)
//! {
//!     ASN1_OBJECT **op;
//!     ADDED_OBJ ad, *adp;
//!
//!     if (a == NULL)  return NID_undef;
//!     if (a->nid != 0) return a->nid;
//!     if (added != NULL) {
//!         ad.type = ADDED_DATA;
//!         ad.obj  = (ASN1_OBJECT *)a;
//!         adp = (ADDED_OBJ *)lh_retrieve(added, &ad);
//!         if (adp != NULL) return adp->obj->nid;
//!     }
//!     op = (ASN1_OBJECT **)OBJ_bsearch((char *)&a, (char *)obj_objs,
//!                                      NUM_OBJ, sizeof(ASN1_OBJECT *),
//!                                      obj_cmp);
//!     if (op == NULL) return NID_undef;
//!     return (*op)->nid;
//! }
//! ```
//!
//! Identification evidence, all from the decrypted image:
//!
//! - The object layout the body walks is `ASN1_OBJECT`'s: `nid` @ +0x08
//!   here, and the neighbouring `OBJ_obj2txt` @ 0x0805f110 reads
//!   `length` @ +0x0c and `data` @ +0x10 off the same pointer, then
//!   decodes the DER OID (`b & 0x7f` accumulated with `<< 7` per
//!   continuation byte, first arc split by 40 through `__rt_sdiv`
//!   @ 0x08036f14, formatted with `"%d.%lu"` @ 0x0805f2b4).
//! - 0x082d7e0c is `lh_retrieve`: it clears `lh->error` @ +0x5c, calls
//!   `getrn` @ 0x080e82cc, and bumps `num_retrieve_miss` @ +0x54 or
//!   `num_retrieve` @ +0x50 — OpenSSL's `lhash.c` verbatim.
//! - 0x0805eb04 is `OBJ_bsearch(key, base, num, size, cmp)`: the classic
//!   `lo`/`hi` halving with `mla` for `base + size * mid` and a
//!   `blx` through the fifth (stacked) argument.
//! - The sibling entry points share the machinery with a different
//!   `ADDED_OBJ` tag and a different sorted table: `OBJ_sn2nid`
//!   @ 0x0805f2c4 (tag `ADDED_SNAME` = 1, `sn_objs` @ 0x08a0c33c, 643
//!   entries) and `OBJ_ln2nid` @ 0x0805edc4 (tag `ADDED_LNAME` = 2,
//!   `ln_objs` @ 0x08a0cd48, 643 entries).
//! - The wider cluster is unmistakably OpenSSL: `"ssl2-md5"`,
//!   `"ssl3-md5"`, `"ssl3-sha1"`, `"RSA-SHA1"` @ 0x0805f574 and
//!   `"signature has problems, re-make with post SSLeay045"`
//!   @ 0x08063268. Apple's own OID `"1.3.6.1.4.1.63.42"` /
//!   `"iPod Serial Number"` sits @ 0x080782bc.
//!
//! The table count 617 (`NUM_OBJ`) and 643 (`NUM_SN`/`NUM_LN`) date the
//! vendored copy to the 0.9.6/0.9.7 era, where `obj_objs` is an array of
//! `ASN1_OBJECT *` rather than the `unsigned int` index array 0.9.8
//! switched to — which is why the hit path is `(*op)->nid`, two loads,
//! and why the table lives in RW data (0x08a0d754) filled by the ADS
//! runtime initializers rather than in ROM.
//!
//! # Body
//!
//! ```text
//! 0805f074:  stmdb sp!,{r0,r4,lr}   ; the argument slot doubles as
//! 0805f078:  sub   sp,sp,#0xc       ;   the bsearch key `&a`
//! 0805f07c:  ldr   r1,[sp,#0xc]
//! 0805f080:  cmp   r1,#0x0
//! 0805f084:  beq   0x0805f0e8       ; a == NULL -> NID_undef
//! 0805f088:  ldr   r0,[r1,#0x8]
//! 0805f08c:  cmp   r0,#0x0
//! 0805f090:  bne   0x0805f0ec       ; a->nid != 0 -> a->nid
//! 0805f094:  ldr   r0,=0x08a0c334
//! 0805f098:  ldr   r0,[r0,#0x4]     ; `added`
//! 0805f09c:  cmp   r0,#0x0
//! 0805f0a0:  beq   0x0805f0c4
//! 0805f0a4:  mov   r2,#0x0          ; ad.type = ADDED_DATA
//! 0805f0a8:  str   r1,[sp,#0x8]     ; ad.obj  = a
//! 0805f0ac:  add   r1,sp,#0x4
//! 0805f0b0:  str   r2,[sp,#0x4]
//! 0805f0b4:  bl    0x082d7e0c       ; lh_retrieve(added, &ad)
//! 0805f0b8:  cmp   r0,#0x0
//! 0805f0bc:  ldrne r0,[r0,#0x4]     ; adp->obj
//! 0805f0c0:  bne   0x0805f0f8
//! 0805f0c4:  ldr   r3,=0x080e1168   ; obj_cmp
//! 0805f0c8:  ldr   r2,=617          ; NUM_OBJ
//! 0805f0cc:  str   r3,[sp]
//! 0805f0d0:  ldr   r1,=0x08a0d754   ; obj_objs
//! 0805f0d4:  mov   r3,#0x4          ; sizeof(ASN1_OBJECT *)
//! 0805f0d8:  add   r0,sp,#0xc       ; &a
//! 0805f0dc:  bl    0x0805eb04       ; OBJ_bsearch
//! 0805f0e0:  cmp   r0,#0x0
//! 0805f0e4:  bne   0x0805f0f4
//! 0805f0e8:  mov   r0,#0x0          ; NID_undef
//! 0805f0ec:  add   sp,sp,#0x10
//! 0805f0f0:  ldmia sp!,{r4,pc}
//! 0805f0f4:  ldr   r0,[r0]          ; *op
//! 0805f0f8:  ldr   r0,[r0,#0x8]     ; ->nid
//! 0805f0fc:  b     0x0805f0ec
//! ```
//!
//! Note the shared tail: the added-hash hit and the table hit both land
//! on `ldr r0,[r0,#8]`, so both really do return `->nid` of an
//! `ASN1_OBJECT`, one dereference apart.
//!
//! # Deviations
//!
//! - `added` and `obj_objs` live at their firmware addresses on device
//!   and in host test storage otherwise (`cxx/object_flags.rs`
//!   precedent). The host table starts empty, so an uninstalled fixture
//!   misses instead of dereferencing a null base — no guard needed.
//! - `lh_retrieve` @ 0x082d7e0c is not ported; it rides the
//!   [`OBJ_ADDED_RETRIEVE`] seam (house pattern). It is unreachable
//!   until something sets `added`, which only `OBJ_create` does.
//! - `OBJ_bsearch` @ 0x0805eb04 and its comparator are inlined into
//!   [`obj_bsearch`] / [`obj_cmp`] rather than called out: the generic
//!   bsearch is shared with `OBJ_sn2nid`/`OBJ_ln2nid` and belongs with
//!   them, and the key indirection (`&a` plus the comparator's
//!   `*(ASN1_OBJECT * const *)`) folds away to passing `a` directly.
//! - **Unresolved anomaly, recorded rather than guessed at**: the
//!   comparator pointer in the literal pool is 0x080e1168, and that
//!   address does *not* decode as a function entry in our image — it
//!   lands mid-body in the 0x080df818..0x080e1318 block, on a
//!   `bl 0x0804d17c` trace call. The same is true of every comparator
//!   this bsearch family passes (0x080de770 for `sn_objs`, 0x080de478
//!   for `ln_objs`, 0x080e1158 and 0x080e0cf0 for two other tables), and
//!   a scan of the whole image finds no cluster of comparator-shaped
//!   leaf functions anywhere near them. Since the address cannot be
//!   read, [`obj_cmp`] implements upstream's body — length first, then
//!   `memcmp` over `data` — which the `length` @ +0x0c / `data` @ +0x10
//!   layout recovered from `OBJ_obj2txt` @ 0x0805f110 corroborates.

use core::ffi::c_void;

/// OpenSSL's `NID_undef`.
pub const NID_UNDEF: i32 = 0;

/// `NUM_OBJ` — entries in the DER-sorted `obj_objs` table @ 0x08a0d754.
pub const NUM_OBJ: usize = 617;

/// `ADDED_OBJ.type` for a lookup keyed by the encoded OID.
pub const ADDED_DATA: i32 = 0;

/// OpenSSL's `ASN1_OBJECT`, at the offsets the firmware uses.
#[repr(C)]
pub struct Asn1Object {
    /// +0x00: short name.
    pub sn: *const u8,
    /// +0x04: long name.
    pub ln: *const u8,
    /// +0x08: the NID this whole function exists to return.
    pub nid: i32,
    /// +0x0c: length of the encoded OID body.
    pub length: i32,
    /// +0x10: the encoded OID body.
    pub data: *const u8,
    /// +0x14: `ASN1_OBJECT_FLAG_*`.
    pub flags: i32,
}

/// OpenSSL's `ADDED_OBJ`: the key/value record of the `added` hash.
#[repr(C)]
pub struct AddedObj {
    /// +0x00: which of the four indexes this record belongs to.
    pub kind: i32,
    /// +0x04: the object itself.
    pub obj: *mut Asn1Object,
}

// Target-exact layouts (the byte offsets the original's `ldr` immediates
// assume).
#[cfg(target_pointer_width = "32")]
mod object_layout {
    use super::{AddedObj, Asn1Object};
    const _: [u8; 0x08] = [0; core::mem::offset_of!(Asn1Object, nid)];
    const _: [u8; 0x0c] = [0; core::mem::offset_of!(Asn1Object, length)];
    const _: [u8; 0x10] = [0; core::mem::offset_of!(Asn1Object, data)];
    const _: [u8; 0x04] = [0; core::mem::offset_of!(AddedObj, obj)];
    const _: [u8; 0x08] = [0; core::mem::size_of::<AddedObj>()];
}

/// `lh_retrieve` @ 0x082d7e0c: looks `key` up in `table`, returning the
/// stored `ADDED_OBJ` or NULL.
pub type LhRetrieve =
    unsafe extern "C" fn(table: *mut c_void, key: *const AddedObj) -> *mut AddedObj;

/// Stand-in installed until target integration supplies the real
/// `lh_retrieve`. Spins rather than inventing a result — it is only
/// reachable once `added` is non-NULL, which needs `OBJ_create`.
unsafe extern "C" fn missing_lh_retrieve(
    _table: *mut c_void,
    _key: *const AddedObj,
) -> *mut AddedObj {
    loop {
        core::hint::spin_loop();
    }
}

/// RetailOS dependency of [`obj_obj2nid`]: `lh_retrieve` @ 0x082d7e0c.
pub static mut OBJ_ADDED_RETRIEVE: LhRetrieve = missing_lh_retrieve;

/// The `obj_objs` table: a DER-sorted array of `ASN1_OBJECT *`.
pub struct ObjTable {
    /// Original: 0x08a0d754.
    pub base: *const *mut Asn1Object,
    /// Original: `NUM_OBJ`.
    pub len: usize,
}

/// On device the table is the link-time array @ 0x08a0d754.
#[cfg(target_os = "none")]
pub static mut OBJ_OBJS: ObjTable =
    ObjTable { base: 0x08a0_d754 as *const *mut Asn1Object, len: NUM_OBJ };

/// Host stand-in: empty until a fixture installs one, so lookups miss.
#[cfg(not(target_os = "none"))]
pub static mut OBJ_OBJS: ObjTable = ObjTable { base: core::ptr::null(), len: 0 };

/// The `added` hash pointer — the word @ 0x08a0c334 + 4 on device.
#[cfg(target_os = "none")]
const ADDED_SLOT: *mut *mut c_void = 0x08a0_c338 as *mut *mut c_void;

/// Host stand-in for that word.
#[cfg(not(target_os = "none"))]
static mut HOST_ADDED_SLOT: *mut c_void = core::ptr::null_mut();

/// Reads `added`.
#[inline(always)]
unsafe fn added_table() -> *mut c_void {
    #[cfg(target_os = "none")]
    {
        ADDED_SLOT.read_volatile()
    }
    #[cfg(not(target_os = "none"))]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(HOST_ADDED_SLOT))
    }
}

/// `obj_cmp` — the comparator `OBJ_bsearch` calls through (see the
/// module header's anomaly note on 0x080e1168). Orders objects by
/// encoded length first, then by the encoded bytes.
unsafe fn obj_cmp(a: *const Asn1Object, b: *const Asn1Object) -> i32 {
    let difference = (*a).length.wrapping_sub((*b).length);
    if difference != 0 {
        return difference;
    }
    crate::libc::memcmp::memcmp((*a).data, (*b).data, (*a).length as usize)
}

/// `OBJ_bsearch` @ 0x0805eb04 specialized to this table: halving search
/// over `len` `ASN1_OBJECT *` slots, returning the matching slot or
/// NULL. `lo`/`hi` are `int`s and the midpoint is C's `(lo + hi) / 2`.
unsafe fn obj_bsearch(
    key: *const Asn1Object,
    base: *const *mut Asn1Object,
    len: usize,
) -> *const *mut Asn1Object {
    let mut low = 0usize;
    let mut high = len;
    while low < high {
        let middle = (low + high) / 2;
        let slot = base.add(middle);
        let order = obj_cmp(key, slot.read());
        if order < 0 {
            high = middle;
        } else if order > 0 {
            low = middle + 1;
        } else {
            return slot;
        }
    }
    core::ptr::null()
}

/// obj_obj2nid — original: `FUN_0805f074` @ 0x0805f074 (156 bytes).
///
/// Returns the NID of `object`: its own if already resolved, else the
/// one the runtime-registered `added` hash or the static `obj_objs`
/// table gives for its encoded OID, else `NID_undef`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn obj_obj2nid(object: *const Asn1Object) -> i32 {
    if object.is_null() {
        return NID_UNDEF;
    }

    let nid = (*object).nid;
    if nid != NID_UNDEF {
        return nid;
    }

    let added = added_table();
    if !added.is_null() {
        let key = AddedObj { kind: ADDED_DATA, obj: object as *mut Asn1Object };
        let retrieve = core::ptr::read_volatile(core::ptr::addr_of!(OBJ_ADDED_RETRIEVE));
        let found = retrieve(added, &key);
        if !found.is_null() {
            return (*(*found).obj).nid;
        }
    }

    let table = core::ptr::addr_of!(OBJ_OBJS);
    let slot = obj_bsearch(object, (*table).base, (*table).len);
    if slot.is_null() {
        return NID_UNDEF;
    }
    (*slot.read()).nid
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::boxed::Box;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    /// Serializes the tests that drive the two globals.
    static OBJ_LOCK: Mutex<()> = Mutex::new(());

    fn object(nid: i32, encoded: &'static [u8]) -> Asn1Object {
        Asn1Object {
            sn: core::ptr::null(),
            ln: core::ptr::null(),
            nid,
            length: encoded.len() as i32,
            data: encoded.as_ptr(),
            flags: 0,
        }
    }

    /// Installs a sorted `obj_objs` and hands back the guard.
    fn with_table(slots: &mut Vec<*mut Asn1Object>) -> MutexGuard<'static, ()> {
        let guard = OBJ_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            OBJ_OBJS.base = slots.as_ptr();
            OBJ_OBJS.len = slots.len();
        }
        guard
    }

    /// Restores the empty defaults. Takes the guard by value so it
    /// cannot be re-locked while still held.
    fn clear(guard: MutexGuard<'static, ()>) {
        unsafe {
            OBJ_OBJS.base = core::ptr::null();
            OBJ_OBJS.len = 0;
            HOST_ADDED_SLOT = core::ptr::null_mut();
            OBJ_ADDED_RETRIEVE = missing_lh_retrieve;
        }
        drop(guard);
    }

    /// Encoded OIDs in the order `obj_cmp` sorts them: length first,
    /// then bytes.
    const OID_A: &[u8] = &[0x2a];
    const OID_B: &[u8] = &[0x2b];
    const OID_C: &[u8] = &[0x2a, 0x03];
    const OID_D: &[u8] = &[0x2a, 0x86, 0x48];
    const OID_E: &[u8] = &[0x2b, 0x06, 0x01];

    /// The five-entry fixture table, sorted, plus the objects it points
    /// at (kept alive by the returned boxes).
    fn fixture() -> (Vec<Box<Asn1Object>>, Vec<*mut Asn1Object>) {
        let entries: Vec<Box<Asn1Object>> = std::vec![
            Box::new(object(101, OID_A)),
            Box::new(object(102, OID_B)),
            Box::new(object(103, OID_C)),
            Box::new(object(104, OID_D)),
            Box::new(object(105, OID_E)),
        ];
        let slots = entries.iter().map(|e| &**e as *const Asn1Object as *mut Asn1Object).collect();
        (entries, slots)
    }

    fn lookup(encoded: &'static [u8]) -> i32 {
        let probe = object(NID_UNDEF, encoded);
        unsafe { obj_obj2nid(&probe) }
    }

    #[test]
    fn a_null_object_is_nid_undef() {
        assert_eq!(unsafe { obj_obj2nid(core::ptr::null()) }, NID_UNDEF);
    }

    #[test]
    fn an_already_resolved_object_returns_its_own_nid_without_a_lookup() {
        // No table installed and no `added`: a non-zero nid still comes
        // straight back, so neither lookup ran.
        let guard = OBJ_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let resolved = object(42, OID_A);
        assert_eq!(unsafe { obj_obj2nid(&resolved) }, 42);
        drop(guard);
    }

    #[test]
    fn a_negative_nid_is_returned_verbatim() {
        // The early-out tests `!= 0`, not `> 0`.
        let guard = OBJ_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let resolved = object(-7, OID_A);
        assert_eq!(unsafe { obj_obj2nid(&resolved) }, -7);
        drop(guard);
    }

    #[test]
    fn every_table_entry_is_found_by_its_encoded_oid() {
        let (_entries, mut slots) = fixture();
        let guard = with_table(&mut slots);
        assert_eq!(lookup(OID_A), 101);
        assert_eq!(lookup(OID_B), 102);
        assert_eq!(lookup(OID_C), 103);
        assert_eq!(lookup(OID_D), 104);
        assert_eq!(lookup(OID_E), 105);
        clear(guard);
    }

    #[test]
    fn an_unknown_oid_is_nid_undef() {
        let (_entries, mut slots) = fixture();
        let guard = with_table(&mut slots);
        assert_eq!(lookup(&[0x2c]), NID_UNDEF, "same length, no match");
        assert_eq!(lookup(&[0x2a, 0x04]), NID_UNDEF, "same length, differing tail");
        assert_eq!(lookup(&[0x2a, 0x86, 0x48, 0x01]), NID_UNDEF, "longer than anything");
        assert_eq!(lookup(&[]), NID_UNDEF, "empty encoding");
        clear(guard);
    }

    #[test]
    fn an_empty_table_misses_without_touching_the_base() {
        // The host default: base NULL, len 0. The loop never runs.
        let guard = OBJ_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            OBJ_OBJS.base = core::ptr::null();
            OBJ_OBJS.len = 0;
        }
        assert_eq!(lookup(OID_A), NID_UNDEF);
        drop(guard);
    }

    #[test]
    fn the_search_covers_a_table_of_every_size_up_to_the_real_one() {
        // Encoded OIDs `[0x00, hi, lo]` sort by their bytes, so index
        // order is search order for any prefix length.
        let mut storage: Vec<Box<[u8; 3]>> = Vec::new();
        for index in 0..NUM_OBJ {
            storage.push(Box::new([0x00, (index >> 8) as u8, (index & 0xff) as u8]));
        }
        let mut objects: Vec<Box<Asn1Object>> = storage
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                Box::new(Asn1Object {
                    sn: core::ptr::null(),
                    ln: core::ptr::null(),
                    nid: index as i32 + 1,
                    length: 3,
                    data: bytes.as_ptr(),
                    flags: 0,
                })
            })
            .collect();
        let mut slots: Vec<*mut Asn1Object> =
            objects.iter_mut().map(|o| &mut **o as *mut Asn1Object).collect();

        let guard = with_table(&mut slots);
        for index in 0..NUM_OBJ {
            let encoded = [0x00, (index >> 8) as u8, (index & 0xff) as u8];
            let probe = Asn1Object {
                sn: core::ptr::null(),
                ln: core::ptr::null(),
                nid: NID_UNDEF,
                length: 3,
                data: encoded.as_ptr(),
                flags: 0,
            };
            assert_eq!(unsafe { obj_obj2nid(&probe) }, index as i32 + 1, "entry {index}");
        }
        clear(guard);
    }

    #[test]
    fn the_added_hash_wins_over_the_static_table() {
        static mut OVERRIDE: Asn1Object = Asn1Object {
            sn: core::ptr::null(),
            ln: core::ptr::null(),
            nid: 999,
            length: 0,
            data: core::ptr::null(),
            flags: 0,
        };
        static mut RECORD: AddedObj = AddedObj { kind: ADDED_DATA, obj: core::ptr::null_mut() };
        static mut SEEN_KIND: i32 = -1;

        unsafe extern "C" fn retrieve(_table: *mut c_void, key: *const AddedObj) -> *mut AddedObj {
            SEEN_KIND = (*key).kind;
            RECORD.obj = core::ptr::addr_of_mut!(OVERRIDE);
            core::ptr::addr_of_mut!(RECORD)
        }

        let (_entries, mut slots) = fixture();
        let guard = with_table(&mut slots);
        unsafe {
            HOST_ADDED_SLOT = 1 as *mut c_void;
            OBJ_ADDED_RETRIEVE = retrieve;
        }
        assert_eq!(lookup(OID_A), 999, "the hash hit shadows nid 101");
        assert_eq!(unsafe { SEEN_KIND }, ADDED_DATA, "the key is tagged ADDED_DATA");
        clear(guard);
    }

    #[test]
    fn an_added_hash_miss_falls_through_to_the_static_table() {
        unsafe extern "C" fn miss(_table: *mut c_void, _key: *const AddedObj) -> *mut AddedObj {
            core::ptr::null_mut()
        }

        let (_entries, mut slots) = fixture();
        let guard = with_table(&mut slots);
        unsafe {
            HOST_ADDED_SLOT = 1 as *mut c_void;
            OBJ_ADDED_RETRIEVE = miss;
        }
        assert_eq!(lookup(OID_C), 103);
        assert_eq!(lookup(&[0x2c]), NID_UNDEF);
        clear(guard);
    }

    #[test]
    fn the_added_hash_is_skipped_entirely_while_it_is_null() {
        // `missing_lh_retrieve` spins, so reaching it would hang: this
        // test passing *is* the proof that `added == NULL` short-circuits.
        let (_entries, mut slots) = fixture();
        let guard = with_table(&mut slots);
        unsafe { HOST_ADDED_SLOT = core::ptr::null_mut() };
        assert_eq!(lookup(OID_B), 102);
        clear(guard);
    }

    #[test]
    fn ordering_is_length_first_then_bytes() {
        // A short encoding whose bytes sort high must still be found,
        // which only holds if length dominates the comparison.
        let short = Box::new(object(1, &[0xff]));
        let long = Box::new(object(2, &[0x00, 0x00]));
        let mut slots: Vec<*mut Asn1Object> = std::vec![
            &*short as *const Asn1Object as *mut Asn1Object,
            &*long as *const Asn1Object as *mut Asn1Object,
        ];
        let guard = with_table(&mut slots);
        assert_eq!(lookup(&[0xff]), 1);
        assert_eq!(lookup(&[0x00, 0x00]), 2);
        clear(guard);
    }

    #[test]
    fn a_single_entry_table_both_hits_and_misses() {
        let only = Box::new(object(77, OID_D));
        let mut slots: Vec<*mut Asn1Object> =
            std::vec![&*only as *const Asn1Object as *mut Asn1Object];
        let guard = with_table(&mut slots);
        assert_eq!(lookup(OID_D), 77);
        assert_eq!(lookup(OID_A), NID_UNDEF);
        clear(guard);
    }
}
