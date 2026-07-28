//! retailOS's copy-on-write C++ `basic_string<char>` — the reference-counted
//! `_Rep` core, ported from the cluster @ 0x083d8518..0x083d8bac.
//!
//! The layout is the classic SGI/libstdc++ COW string: the string object
//! itself is *one word*, a pointer to the character data, and a 12-byte
//! header sits immediately below that pointer:
//!
//! ```text
//! rep + 0x00  i32  refcount    0 = one owner, N = N+1 owners, -1 = dying
//! rep + 0x04  u32  capacity    chars the buffer can hold (excl. NUL)
//! rep + 0x08  u32  length      chars currently in the string
//! rep + 0x0c  u8[] data        <- the string object's stored pointer
//! ```
//!
//! (Field order differs from GNU libstdc++, which is length/capacity/
//! refcount — recovered here from the header stores in
//! `cxx_string_rep_create`, not assumed.)
//!
//! The shared empty representation lives at 0x08b31804 in RAM, its data
//! pointer at 0x08b31810; every empty string points there and is never
//! refcounted. The port models it as a `static` block (`EMPTY_REP`), the
//! same simplification `heap/veneers.rs` makes for the default heap.
//!
//! Ported functions, all binary-scanned call counts:
//!
//! - `cxx_string_release` — original: `FUN_083d8b04` @ 0x083d8b04
//!   (80 bytes, **571 `bl` call sites** — the destructor half of every
//!   string in the OS, and the second-most-called function in
//!   0x08300000-0x083fffff). Drops one reference and, at -1, tail-branches
//!   to the sized-delete veneer @ 0x08266f2c, which is a 4-byte
//!   `b 0x082aad24` — plain `operator delete`, so the size and the third
//!   argument it computes are discarded. The port calls
//!   `heap::veneers::operator_delete` directly.
//! - `cxx_string_rep_create` — original: `FUN_083d8a64` @ 0x083d8a64
//!   (152 bytes, 99 call sites). Allocates and initializes a `_Rep`.
//! - `cxx_string_rep_reserve` — original: `FUN_083d8518` @ 0x083d8518
//!   (76 bytes, 5 call sites). Growth policy in front of
//!   `cxx_string_rep_create`; returns the *data* pointer (rep + 12).
//! - `cxx_string_from_cstr` — original: `FUN_083d8b5c` @ 0x083d8b5c
//!   (76 bytes, **495 call sites**). `basic_string(const char*)`.
//! - `cxx_string_from_buffer` — original: `FUN_083d8bac` @ 0x083d8bac
//!   (108 bytes, 7 call sites). `basic_string(const char*, size_t)`.
//! - `cxx_string_default_ctor` — original: `FUN_083d8c20` @ 0x083d8c20
//!   (12 bytes, 19 call sites). `basic_string()`.
//! - `cxx_string_copy_ctor` — original: `FUN_083d8c30` @ 0x083d8c30
//!   (92 bytes, 70 call sites). `basic_string(const basic_string&)`.
//! - `cxx_string_dtor` — original: `FUN_083d8c8c` @ 0x083d8c8c
//!   (20 bytes, 5 call sites). `~basic_string()`.
//! - `cxx_string_rep_add_ref` — original: `FUN_083b54f8` @ 0x083b54f8
//!   (24 bytes, 2 call sites). `_Rep::_M_add_ref`.
//!
//! `refcount == -1` carries two meanings, and both are the same
//! `adds r, r, #1; beq` test: to the destructor it means "no owners
//! left, destroy me", and to the copy constructor and assignment it
//! means "leaked" — a mutable reference escaped, so sharing is unsafe
//! and the copy must be deep. Nothing in this class ever produces a
//! refcount below -1.
//!
//! Deviations:
//! - `cxx_string_rep_create`'s header store (`stm r0, {r1, r4, r5}` @
//!   0x083d8ae8) is *unconditional* in the original — when the allocation
//!   fails it writes three words through a NULL pointer. The port returns
//!   NULL instead of faulting. Everything else on that path (including
//!   the redundant `stmiane` pre-zeroing of the same three words, which
//!   the port drops) is behavior-identical.
//! - The length-error paths call the C++ diagnostic/throw dispatch
//!   @ 0x08266abc with code 8 and two string arguments that both point at
//!   an empty string @ 0x083d8afc (the diagnostics were stripped from
//!   this build). It is reached with `bl`, and the original *falls
//!   through* to allocate anyway if it returns. The port routes it
//!   through the [`CXX_STRING_OPS`] hook, whose default is a no-op, and
//!   likewise falls through.
//! - `cxx_string_rep_create` ignores its first argument (the original
//!   never reads r0); kept in the signature so call sites transcribe
//!   one-to-one.

use crate::heap::veneers::{operator_delete, operator_new_checked};
use crate::libc::rt_memcpy::__rt_memcpy;
use crate::libc::strlen::strlen;

/// Bytes of header below the character data.
pub const REP_HEADER_SIZE: usize = 12;

/// Bytes allocated on top of the requested capacity: the 12-byte header,
/// the NUL terminator, and one spare byte (`add r1, r1, #14`).
pub const REP_ALLOC_OVERHEAD: u32 = 14;

/// Largest capacity accepted before the length-error report fires
/// (`cmn r1, #15` / `mvn r3, #14` — i.e. `(u32)-15`).
pub const MAX_CAPACITY: u32 = 0xffff_fff1;

/// Diagnostic code the original passes for a length error (`mov r0, #8`).
pub const LENGTH_ERROR_CODE: usize = 8;

/// The 12-byte `_Rep` header. No pointer fields, so its layout is the
/// same on the 32-bit target and a 64-bit test host.
#[repr(C)]
#[derive(Debug)]
pub struct StringRep {
    /// 0 = sole owner; -1 after the last release, i.e. "destroy me".
    pub refcount: i32,
    /// Characters the buffer can hold, excluding the NUL.
    pub capacity: u32,
    /// Characters currently stored.
    pub length: u32,
}

/// Storage for the shared empty representation. Original: the `_Rep` at
/// 0x08b31804 with its (always NUL) data byte at 0x08b31810.
#[repr(C, align(4))]
struct EmptyRepStorage {
    rep: StringRep,
    data: [u8; 4],
}

static EMPTY_REP: EmptyRepStorage = EmptyRepStorage {
    rep: StringRep { refcount: 0, capacity: 0, length: 0 },
    data: [0; 4],
};

/// The shared empty `_Rep` (original 0x08b31804).
#[inline]
pub fn empty_rep() -> *mut StringRep {
    core::ptr::addr_of!(EMPTY_REP.rep) as *mut StringRep
}

/// The shared empty `_Rep`'s data pointer (original 0x08b31810) — the
/// value every empty string stores.
#[inline]
pub fn empty_rep_data() -> *mut u8 {
    core::ptr::addr_of!(EMPTY_REP.data) as *mut u8
}

/// Indirect dispatch for the one callee that is not ported: the C++
/// diagnostic/throw dispatch @ 0x08266abc (shared with
/// `operator_new_checked`'s new-handler path, which passes code 3).
#[derive(Clone, Copy)]
pub struct CxxStringOps {
    /// `report_error(code, file, func, a, b)` — original @ 0x08266abc.
    /// `file`/`func` both point at an empty string in this build.
    pub report_error: unsafe extern "C" fn(usize, *const u8, *const u8, u32, u32),
}

/// Default: do nothing and return, which makes the original's
/// fall-through behavior observable in tests.
unsafe extern "C" fn report_error_noop(_: usize, _: *const u8, _: *const u8, _: u32, _: u32) {}

/// Replaceable callee table; see [`CxxStringOps`].
pub static mut CXX_STRING_OPS: CxxStringOps = CxxStringOps { report_error: report_error_noop };

/// Dispatches through [`CXX_STRING_OPS`]. The volatile read keeps the hook
/// a real runtime call: without it LLVM sees a `static mut` nothing in the
/// crate writes, const-folds the no-op default, and deletes both
/// length-error reports from the ARM build.
#[inline]
unsafe fn report_error(a: u32, b: u32) {
    let stripped = core::ptr::addr_of!(STRIPPED_DIAGNOSTIC);
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(CXX_STRING_OPS));
    (ops.report_error)(LENGTH_ERROR_CODE, stripped, stripped, a, b);
}

/// The stripped diagnostic string both string arguments point at
/// (original @ 0x083d8afc: a single NUL byte).
static STRIPPED_DIAGNOSTIC: u8 = 0;

/// Data pointer of a rep (`rep + 12`).
#[inline]
pub unsafe fn rep_data(rep: *mut StringRep) -> *mut u8 {
    (rep as *mut u8).add(REP_HEADER_SIZE)
}

/// Rep header of a data pointer (`data - 12`).
#[inline]
pub unsafe fn data_rep(data: *mut u8) -> *mut StringRep {
    data.sub(REP_HEADER_SIZE) as *mut StringRep
}

/// cxx_string_rep_create — original @ 0x083d8a64.
///
/// Allocates a `_Rep` with room for `capacity` characters and stamps it
/// with `length` (refcount 0 = sole owner), NUL-terminating at
/// `data[length]`. A `capacity` of 0 hands back the shared empty rep
/// without allocating. Returns the *rep*, not the data pointer.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_string_rep_create(
    _unused: *mut u8,
    capacity: u32,
    length: u32,
) -> *mut StringRep {
    if capacity > MAX_CAPACITY {
        report_error(capacity, MAX_CAPACITY);
    }
    if length > capacity {
        report_error(length, capacity);
    }
    if capacity == 0 {
        return empty_rep();
    }

    let rep = operator_new_checked((capacity + REP_ALLOC_OVERHEAD) as usize) as *mut StringRep;
    // Deviation: the original stores the header unconditionally, i.e.
    // through NULL when the allocation failed.
    if rep.is_null() {
        return rep;
    }
    (*rep).refcount = 0;
    (*rep).capacity = capacity;
    (*rep).length = length;
    rep_data(rep).add(length as usize).write(0);
    rep
}

/// cxx_string_rep_reserve — original @ 0x083d8518.
///
/// Growth policy in front of [`cxx_string_rep_create`]: the new capacity
/// is `max(old + old/2 + old/8, old + 32, needed)` (all wrapping, as in
/// the original), and the rep is stamped with `length`. Returns the
/// *data* pointer, `rep + 12`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_string_rep_reserve(
    unused: *mut u8,
    old_capacity: u32,
    needed: u32,
    length: u32,
) -> *mut u8 {
    let grown = old_capacity
        .wrapping_add(old_capacity >> 1)
        .wrapping_add(old_capacity >> 3);
    let floor = old_capacity.wrapping_add(32);
    let grown = if floor > grown { floor } else { grown };
    let capacity = if grown < needed { needed } else { grown };
    rep_data(cxx_string_rep_create(unused, capacity, length))
}

/// cxx_string_release — original @ 0x083d8b04.
///
/// Drops one reference to the string whose data pointer lives at
/// `*string`. The shared empty rep is never touched. A refcount that is
/// already -1, or that reaches -1 on this release, destroys the rep.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_string_release(string: *mut *mut u8) {
    let data = *string;
    if data == empty_rep_data() {
        return;
    }
    let rep = data_rep(data);
    if (*rep).refcount != -1 {
        // Redundant in the original too: rep == empty_rep is already
        // excluded by the data comparison above. Kept for fidelity.
        if rep == empty_rep() {
            return;
        }
        let dropped = (*rep).refcount - 1;
        (*rep).refcount = dropped;
        if dropped != -1 {
            return;
        }
    }
    // The original tail-branches to the sized-delete veneer @ 0x08266f2c
    // with (rep, capacity + 14, 0); that veneer is `b operator delete`,
    // which reads only the pointer.
    operator_delete(data_rep(*string) as *mut u8);
}

/// cxx_string_from_cstr — original @ 0x083d8b5c.
///
/// `basic_string(const char *)`: measures `source` with the byte-loop
/// `strlen` @ 0x08392478, allocates through [`cxx_string_rep_reserve`]
/// (old capacity 0, so the buffer is at least 32 characters), copies the
/// bytes with `__rt_memcpy`, and stores the data pointer in the
/// one-word string object. An empty source skips the allocation and
/// points at the shared empty rep. Returns `string`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_string_from_cstr(
    string: *mut *mut u8,
    source: *const u8,
) -> *mut *mut u8 {
    let length = strlen(source) as u32;
    let data = if length == 0 {
        empty_rep_data()
    } else {
        cxx_string_rep_reserve(string as *mut u8, 0, length, length)
    };
    *string = data;
    __rt_memcpy(data, source, length as usize);
    string
}

/// cxx_string_rep_add_ref — original: `FUN_083b54f8` @ 0x083b54f8
/// (24 bytes, 2 `bl` call sites — 0x083d8c54 in [`cxx_string_copy_ctor`]
/// and 0x083d8d3c in [`cxx_string_assign`], the only two places a rep is
/// ever shared).
///
/// `_Rep::_M_add_ref`: a **non-atomic** `++refcount` that skips the
/// shared empty rep (compared against the literal 0x08b31804). The
/// singleton is never refcounted, which is what lets it be immutable.
///
/// It sits a hair below this agent's 0x083c0000 sweep, but it is a
/// member of this string class and is reachable from nowhere else.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_rep_add_ref(rep: *mut StringRep) {
    if rep == empty_rep() {
        return;
    }
    (*rep).refcount += 1;
}

/// cxx_string_default_ctor — original: `FUN_083d8c20` @ 0x083d8c20
/// (12 bytes, 19 `bl` call sites).
///
/// `basic_string()`: parks the one-word string object on the shared
/// empty rep's data pointer. No allocation, no refcounting. The
/// original leaves `this` in r0, so the port returns it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_default_ctor(string: *mut *mut u8) -> *mut *mut u8 {
    *string = empty_rep_data();
    string
}

/// cxx_string_dtor — original: `FUN_083d8c8c` @ 0x083d8c8c
/// (20 bytes, 5 `bl` call sites).
///
/// `~basic_string()`: [`cxx_string_release`] and nothing else, with
/// `this` restored into r0 (the ADS destructor return convention).
/// Distinct from `cxx_string_release` only in that it preserves r0, and
/// the 571 direct callers of 0x083d8b04 show the compiler inlined this
/// wrapper away almost everywhere.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_dtor(string: *mut *mut u8) -> *mut *mut u8 {
    cxx_string_release(string);
    string
}

/// cxx_string_copy_ctor — original: `FUN_083d8c30` @ 0x083d8c30
/// (92 bytes, 64 `bl` + 6 `b` = 70 call sites).
///
/// `basic_string(const basic_string &)`, the COW grab: share the
/// source's rep by bumping its refcount, *unless* the rep is marked
/// leaked (`refcount == -1`, the same sentinel [`cxx_string_release`]
/// treats as "destroy me") — a leaked rep has handed a mutable
/// reference to someone else, so the copy must be deep. The deep path
/// allocates `length` capacity through [`cxx_string_rep_create`] and
/// copies `length` bytes; the terminator comes from `rep_create`.
///
/// Returns `dst`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_string_copy_ctor(
    dst: *mut *mut u8,
    src: *const *mut u8,
) -> *mut *mut u8 {
    let data = *src;
    let rep = data_rep(data);
    if (*rep).refcount != -1 {
        *dst = data;
        cxx_string_rep_add_ref(rep);
        return dst;
    }
    let length = (*rep).length;
    let copy = cxx_string_rep_create(dst as *mut u8, length, length);
    let copy_data = rep_data(copy);
    *dst = copy_data;
    __rt_memcpy(copy_data, *src, length as usize);
    dst
}

/// cxx_string_from_buffer — original: `FUN_083d8bac` @ 0x083d8bac
/// (108 bytes, 7 `bl` call sites).
///
/// `basic_string(const char *s, size_type n)`: the counted sibling of
/// [`cxx_string_from_cstr`]. `n == 0` parks on the shared empty rep
/// without allocating; otherwise [`cxx_string_rep_reserve`] sizes the
/// buffer (old capacity 0, so the floor is 32) and `n` bytes are copied.
///
/// Faithful quirks: the copy is guarded on `s != NULL`, not on `n`, so a
/// zero-length construction from a non-NULL pointer still calls memcpy
/// with length 0; and `n != 0` with a NULL `s` allocates a rep of length
/// `n` whose bytes are never written.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_string_from_buffer(
    string: *mut *mut u8,
    source: *const u8,
    length: u32,
) -> *mut *mut u8 {
    if length > MAX_CAPACITY {
        report_error(length, MAX_CAPACITY);
    }
    let data = if length == 0 {
        empty_rep_data()
    } else {
        cxx_string_rep_reserve(string as *mut u8, 0, length, length)
    };
    *string = data;
    if !source.is_null() {
        __rt_memcpy(data, source, length as usize);
    }
    string
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::HEAP_OPS;
    use std::sync::MutexGuard;
    use std::vec::Vec;

    /// Bump arena backing the heap-ops `alloc` slot for these tests: the
    /// real heap core is not exercised on the host, and the shared mock in
    /// heap/veneers hands out a fixed fake address that cannot be written.
    const ARENA_SIZE: usize = 4096;

    #[repr(C, align(8))]
    struct Arena([u8; ARENA_SIZE]);

    static mut ARENA: Arena = Arena([0; ARENA_SIZE]);
    static mut ARENA_USED: usize = 0;
    static mut FREED: [*mut u8; 16] = [core::ptr::null_mut(); 16];
    static mut FREE_COUNT: usize = 0;

    unsafe extern "C" fn arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let used = ARENA_USED;
        let aligned = (size + 7) & !7;
        if used + aligned > ARENA_SIZE {
            return core::ptr::null_mut();
        }
        ARENA_USED = used + aligned;
        core::ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(used)
    }

    unsafe extern "C" fn arena_free(
        _heap: *mut HeapDescriptorDescriptor,
        ptr: *mut u8,
        _tag: usize,
    ) {
        if FREE_COUNT < 16 {
            FREED[FREE_COUNT] = ptr;
            FREE_COUNT += 1;
        }
    }

    unsafe extern "C" fn arena_create(
        desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        desc as *mut HeapDescriptorDescriptor
    }

    /// Installs the arena over the shared heap-ops table, under the same
    /// lock heap/veneers' own tests use. One guard per test function (a
    /// second, shadowed guard in the same function would self-deadlock).
    fn arena() -> MutexGuard<'static, ()> {
        let guard = crate::heap::veneers::tests::mock_heap();
        unsafe {
            ARENA_USED = 0;
            FREE_COUNT = 0;
            FREED = [core::ptr::null_mut(); 16];
            let ops = core::ptr::addr_of_mut!(HEAP_OPS);
            (*ops).alloc = arena_alloc;
            (*ops).free = arena_free;
            (*ops).create = arena_create;
        }
        guard
    }

    unsafe fn freed() -> &'static [*mut u8] {
        let count = core::ptr::read(core::ptr::addr_of!(FREE_COUNT));
        core::slice::from_raw_parts(core::ptr::addr_of!(FREED).cast::<*mut u8>(), count)
    }

    /// Reference growth policy, transcribed straight from the
    /// disassembly of 0x083d8518.
    fn reference_capacity(old: u32, needed: u32) -> u32 {
        let grown = old
            .wrapping_add(old >> 1)
            .wrapping_add(old >> 3)
            .max(old.wrapping_add(32));
        if grown < needed {
            needed
        } else {
            grown
        }
    }

    #[test]
    fn empty_source_uses_the_shared_empty_rep() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            let slot_ptr: *mut *mut u8 = &mut slot;
            assert_eq!(cxx_string_from_cstr(slot_ptr, b"\0".as_ptr()), slot_ptr);
            assert_eq!(slot, empty_rep_data());
            assert_eq!(slot.read(), 0);
            assert_eq!(ARENA_USED, 0, "no allocation for an empty string");
            // Releasing an empty string must not touch the singleton.
            cxx_string_release(&mut slot);
            assert_eq!((*empty_rep()).refcount, 0);
            assert!(freed().is_empty());
        }
    }

    #[test]
    fn from_cstr_copies_and_nul_terminates() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            cxx_string_from_cstr(&mut slot, b"hello world\0".as_ptr());
            let rep = data_rep(slot);
            assert_eq!((*rep).length, 11);
            assert_eq!((*rep).refcount, 0);
            // Capacity floor is 32 for a fresh string.
            assert_eq!((*rep).capacity, 32);
            assert_eq!(core::slice::from_raw_parts(slot, 12), b"hello world\0");
            cxx_string_release(&mut slot);
            assert_eq!(freed(), &[rep as *mut u8]);
        }
    }

    #[test]
    fn long_source_gets_exactly_its_length_as_capacity() {
        let _guard = arena();
        unsafe {
            let mut text: Vec<u8> = std::vec![b'x'; 100];
            text.push(0);
            let mut slot: *mut u8 = core::ptr::null_mut();
            cxx_string_from_cstr(&mut slot, text.as_ptr());
            let rep = data_rep(slot);
            assert_eq!((*rep).length, 100);
            assert_eq!((*rep).capacity, 100);
            assert_eq!(slot.add(100).read(), 0, "NUL written by rep_create");
            assert!(core::slice::from_raw_parts(slot, 100).iter().all(|&c| c == b'x'));
        }
    }

    #[test]
    fn release_decrements_before_it_frees() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            cxx_string_from_cstr(&mut slot, b"shared\0".as_ptr());
            let rep = data_rep(slot);
            (*rep).refcount = 2; // two extra owners
            cxx_string_release(&mut slot);
            assert_eq!((*rep).refcount, 1);
            cxx_string_release(&mut slot);
            assert_eq!((*rep).refcount, 0);
            assert!(freed().is_empty(), "still owned");
            cxx_string_release(&mut slot);
            assert_eq!((*rep).refcount, -1);
            assert_eq!(freed(), &[rep as *mut u8]);
        }
    }

    /// A rep already marked -1 is destroyed without a further decrement
    /// (`adds r3, r2, #1; beq destroy` on entry).
    #[test]
    fn refcount_minus_one_frees_immediately() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            cxx_string_from_cstr(&mut slot, b"dying\0".as_ptr());
            let rep = data_rep(slot);
            (*rep).refcount = -1;
            cxx_string_release(&mut slot);
            assert_eq!((*rep).refcount, -1, "no decrement on the -1 path");
            assert_eq!(freed(), &[rep as *mut u8]);
        }
    }

    #[test]
    fn rep_create_zero_capacity_returns_the_singleton() {
        let _guard = arena();
        unsafe {
            assert_eq!(cxx_string_rep_create(core::ptr::null_mut(), 0, 0), empty_rep());
            assert_eq!(ARENA_USED, 0);
        }
    }

    #[test]
    fn rep_create_stamps_the_header_and_asks_for_capacity_plus_fourteen() {
        let _guard = arena();
        unsafe {
            let rep = cxx_string_rep_create(core::ptr::null_mut(), 40, 5);
            assert!(!rep.is_null());
            assert_eq!((*rep).refcount, 0);
            assert_eq!((*rep).capacity, 40);
            assert_eq!((*rep).length, 5);
            assert_eq!(rep_data(rep).add(5).read(), 0);
            // 40 + 14 = 54, rounded up to 56 by the arena's 8-byte step.
            assert_eq!(ARENA_USED, 56);
        }
    }

    #[test]
    fn rep_create_returns_null_when_the_allocation_fails() {
        let _guard = arena();
        unsafe {
            // Larger than the whole arena.
            assert!(cxx_string_rep_create(core::ptr::null_mut(), 8192, 0).is_null());
        }
    }

    #[test]
    fn growth_policy_matches_the_reference() {
        let _guard = arena();
        for old in [0u32, 1, 2, 7, 8, 16, 31, 32, 33, 84, 85, 88, 100, 1000] {
            for needed in [0u32, 1, 31, 32, 33, 64, 200, 1000] {
                let want = reference_capacity(old, needed);
                if want == 0 || want as usize + 14 > ARENA_SIZE {
                    continue;
                }
                unsafe {
                    ARENA_USED = 0;
                    let data = cxx_string_rep_reserve(core::ptr::null_mut(), old, needed, 0);
                    assert_eq!((*data_rep(data)).capacity, want, "old={old} needed={needed}");
                }
            }
        }
    }

    /// The 1.625x term overtakes the `old + 32` floor at old = 54; at 52
    /// and 53 the two are exactly equal and `movhi` keeps the 1.625x
    /// value (the original only replaces it when the floor is strictly
    /// greater). Pins both sides of that crossover.
    #[test]
    fn growth_crossover() {
        assert_eq!(reference_capacity(51, 0), 51 + 32); // floor wins
        assert_eq!(reference_capacity(52, 0), 84); // tie: 52+26+6 == 52+32
        assert_eq!(reference_capacity(54, 0), 54 + 27 + 6); // 1.625x wins
        assert_eq!(reference_capacity(1000, 0), 1000 + 500 + 125);
        // `needed` overrides both when it is larger.
        assert_eq!(reference_capacity(0, 500), 500);
        assert_eq!(reference_capacity(0, 0), 32);
    }

    #[test]
    fn default_ctor_parks_on_the_singleton() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = 0xdead as *mut u8;
            let slot_ptr: *mut *mut u8 = &mut slot;
            assert_eq!(cxx_string_default_ctor(slot_ptr), slot_ptr);
            assert_eq!(slot, empty_rep_data());
            assert_eq!(ARENA_USED, 0);
        }
    }

    #[test]
    fn dtor_releases_and_returns_this() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            let slot_ptr: *mut *mut u8 = &mut slot;
            cxx_string_from_cstr(slot_ptr, b"bye\0".as_ptr());
            let rep = data_rep(slot);
            assert_eq!(cxx_string_dtor(slot_ptr), slot_ptr);
            assert_eq!(freed(), &[rep as *mut u8]);
        }
    }

    #[test]
    fn add_ref_bumps_but_never_the_singleton() {
        unsafe {
            let mut rep = StringRep { refcount: 3, capacity: 0, length: 0 };
            cxx_string_rep_add_ref(&mut rep);
            assert_eq!(rep.refcount, 4);
            cxx_string_rep_add_ref(empty_rep());
            assert_eq!((*empty_rep()).refcount, 0);
        }
    }

    #[test]
    fn copy_ctor_shares_the_rep() {
        let _guard = arena();
        unsafe {
            let mut src: *mut u8 = core::ptr::null_mut();
            cxx_string_from_cstr(&mut src, b"shared\0".as_ptr());
            let used = ARENA_USED;
            let mut dst: *mut u8 = core::ptr::null_mut();
            let dst_ptr: *mut *mut u8 = &mut dst;
            assert_eq!(cxx_string_copy_ctor(dst_ptr, &src), dst_ptr);
            assert_eq!(dst, src, "same buffer");
            assert_eq!((*data_rep(src)).refcount, 1);
            assert_eq!(ARENA_USED, used, "no allocation on the shared path");
            // Two releases to unwind the two owners.
            cxx_string_release(&mut dst);
            assert!(freed().is_empty());
            cxx_string_release(&mut src);
            assert_eq!(freed().len(), 1);
        }
    }

    /// Copying an empty string shares the singleton and leaves its
    /// refcount alone (`_M_add_ref`'s literal compare).
    #[test]
    fn copy_ctor_of_empty_leaves_the_singleton_alone() {
        let _guard = arena();
        unsafe {
            let mut src: *mut u8 = empty_rep_data();
            let mut dst: *mut u8 = core::ptr::null_mut();
            cxx_string_copy_ctor(&mut dst, &src);
            assert_eq!(dst, empty_rep_data());
            assert_eq!((*empty_rep()).refcount, 0);
            assert_eq!(ARENA_USED, 0);
            let _ = &mut src;
        }
    }

    /// A leaked rep (-1) must be deep-copied, not shared.
    #[test]
    fn copy_ctor_deep_copies_a_leaked_rep() {
        let _guard = arena();
        unsafe {
            let mut src: *mut u8 = core::ptr::null_mut();
            cxx_string_from_cstr(&mut src, b"leaked\0".as_ptr());
            (*data_rep(src)).refcount = -1;
            let mut dst: *mut u8 = core::ptr::null_mut();
            cxx_string_copy_ctor(&mut dst, &src);
            assert_ne!(dst, src, "fresh buffer");
            assert_eq!((*data_rep(src)).refcount, -1, "source untouched");
            let rep = data_rep(dst);
            assert_eq!((*rep).refcount, 0);
            assert_eq!((*rep).length, 6);
            assert_eq!((*rep).capacity, 6, "exactly length, no growth policy");
            assert_eq!(core::slice::from_raw_parts(dst, 7), b"leaked\0");
        }
    }

    #[test]
    fn from_buffer_copies_exactly_n_bytes() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            let slot_ptr: *mut *mut u8 = &mut slot;
            // No NUL in the source; `n` alone decides the length.
            assert_eq!(cxx_string_from_buffer(slot_ptr, b"abcdefgh".as_ptr(), 3), slot_ptr);
            let rep = data_rep(slot);
            assert_eq!((*rep).length, 3);
            assert_eq!((*rep).capacity, 32);
            assert_eq!(core::slice::from_raw_parts(slot, 4), b"abc\0");
        }
    }

    /// Embedded NULs survive — this is the constructor that makes the
    /// class binary-safe.
    #[test]
    fn from_buffer_keeps_embedded_nuls() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            cxx_string_from_buffer(&mut slot, b"a\0b\0c".as_ptr(), 5);
            assert_eq!((*data_rep(slot)).length, 5);
            assert_eq!(core::slice::from_raw_parts(slot, 6), b"a\0b\0c\0");
        }
    }

    #[test]
    fn from_buffer_zero_length_uses_the_singleton() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            cxx_string_from_buffer(&mut slot, b"abc".as_ptr(), 0);
            assert_eq!(slot, empty_rep_data());
            assert_eq!(ARENA_USED, 0);
            // ...and a NULL source is simply not copied.
            cxx_string_from_buffer(&mut slot, core::ptr::null(), 0);
            assert_eq!(slot, empty_rep_data());
        }
    }

    /// `data_rep`/`rep_data` are exact inverses (the -12/+12 the original
    /// spells as `ldr r2, [r1, #-12]!` and `add r0, r0, #12`).
    #[test]
    fn header_offset_round_trips() {
        let _guard = arena();
        unsafe {
            let rep = cxx_string_rep_create(core::ptr::null_mut(), 16, 0);
            assert_eq!(data_rep(rep_data(rep)), rep);
            assert_eq!(rep_data(rep) as usize - rep as usize, REP_HEADER_SIZE);
        }
    }

    /// The length-error hook fires on `length > capacity` and, like the
    /// original, execution continues into the allocation.
    #[test]
    fn length_error_reports_and_falls_through() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn counting(_: usize, _: *const u8, _: *const u8, _: u32, _: u32) {
            CALLS.fetch_add(1, Ordering::SeqCst);
        }
        let _guard = arena();
        unsafe {
            let saved = CXX_STRING_OPS.report_error;
            (*core::ptr::addr_of_mut!(CXX_STRING_OPS)).report_error = counting;
            let rep = cxx_string_rep_create(core::ptr::null_mut(), 8, 9);
            assert_eq!(CALLS.load(Ordering::SeqCst), 1);
            assert!(!rep.is_null(), "the original falls through and allocates");
            assert_eq!((*rep).length, 9);
            (*core::ptr::addr_of_mut!(CXX_STRING_OPS)).report_error = saved;
        }
    }
}
