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
//! - `cxx_string_replace_core` — original: `FUN_083d865c` @ 0x083d865c
//!   (552 bytes, 3 call sites). The class's only splice primitive;
//!   everything below funnels through it.
//! - `cxx_string_replace_cstr` — original: `FUN_083d8624` @ 0x083d8624
//!   (56 bytes, 3 call sites). `replace(pos, n1, const char*, n2)`.
//! - `cxx_string_append_substr` — original: `FUN_083d8564` @ 0x083d8564
//!   (188 bytes, 3 call sites). `append(const basic_string&, pos, n)`.
//! - `cxx_string_assign_cstr` — original: `FUN_083d8ca0` @ 0x083d8ca0
//!   (120 bytes, 24 call sites). `operator=(const char*)`.
//! - `cxx_string_assign` — original: `FUN_083d8d1c` @ 0x083d8d1c
//!   (104 bytes, 46 call sites). `operator=(const basic_string&)`.
//! - `cxx_string_append_cstr` — original: `FUN_083d8d84` @ 0x083d8d84
//!   (56 bytes, 21 call sites). `operator+=(const char*)`.
//! - `cxx_string_empty` — original: `FUN_083d6f0c` @ 0x083d6f0c
//!   (20 bytes, 7 direct unconditional `bl` call sites). `basic_string::empty()`.
//! - `cxx_string_less` — original: `FUN_083d74f4` @ 0x083d74f4
//!   (116 bytes, 34 call sites). `std::less<basic_string>`.
//! - `strstreambuf_has_input_and_output` — original: `FUN_083d7008` @
//!   0x083d7008 (24 bytes, 2 direct `bl` call sites). Tests whether both
//!   the input and output areas of a `strstreambuf` are active.
//! - `strstreambuf_input_available` — original: `FUN_083d7020` @
//!   0x083d7020 (36 bytes, 1 direct `bl` call site). Returns the active
//!   input area's end-minus-current cursor span.
//! - `streambuf_sgetc` — original: `FUN_083da5a8` @ 0x083da5a8 (32 bytes,
//!   5 direct unconditional `bl` call sites). Returns an unconsumed get-area
//!   byte or calls virtual slot `+0x20` when the get area is exhausted.
//! - `streambuf_sputc` — original: `FUN_083da5c8` @ 0x083da5c8 (76
//!   bytes, 5 direct unconditional `bl` call sites). Stores one byte in an
//!   active put area or calls virtual slot `+0x28` when full or inactive.
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
use crate::cxx::string_object::{string_object_c_str, StringObject};
use crate::libc::memcmp::memcmp;
use crate::libc::memmove::memmove;
use crate::libc::rt_memcpy::__rt_memcpy;
use crate::libc::strlen::strlen;
use crate::libc::strncpy::strncpy;

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

/// Diagnostic code the original passes for an out-of-range index
/// (`mov r0, #9`), raised by the mutation core's precondition checks.
pub const RANGE_ERROR_CODE: usize = 9;

/// Capacity floor the *mutation* core adds to the old length when it has
/// to reallocate (`add r1, r1, #128`). Note this is 128, not the 32 the
/// construction path's [`cxx_string_rep_reserve`] uses.
pub const MUTATE_GROWTH_FLOOR: u32 = 128;

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
/// An 8-byte C++ record containing two one-word COW string objects.
///
/// The fields are destroyed by [`cxx_string_pair_destroy`] in reverse member
/// order. On the ARM target they occupy offsets +0x00 and +0x04.
#[repr(C)]
pub struct CxxStringPair {
    /// First COW string object at target offset +0x00.
    pub first: *mut u8,
    /// Second COW string object at target offset +0x04.
    pub second: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(CxxStringPair, second)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x08] = [0; core::mem::size_of::<CxxStringPair>()];

/// One target-layout record consumed by [`cxx_string_pair_range_destroy`].
///
/// On ARM this is exactly 12 bytes: two one-word COW string objects at
/// +0x00/+0x04 followed by an unexamined word at +0x08. Host pointers are
/// wider, so the fields remain disjoint there while the iterator's target
/// stride is validated below.
#[repr(C)]
pub struct CxxStringPairRangeEntry {
    /// First COW string object at target offset +0x00.
    pub first: *mut u8,
    /// Second COW string object at target offset +0x04.
    pub second: *mut u8,
    /// Unexamined target word at +0x08.
    pub trailing: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x04] = [0; core::mem::offset_of!(CxxStringPairRangeEntry, second)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x0c] = [0; core::mem::size_of::<CxxStringPairRangeEntry>()];


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
/// crate writes, const-folds the no-op default, and deletes every
/// diagnostic report from the ARM build.
#[inline]
unsafe fn report(code: usize, a: u32, b: u32) {
    let stripped = core::ptr::addr_of!(STRIPPED_DIAGNOSTIC);
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(CXX_STRING_OPS));
    (ops.report_error)(code, stripped, stripped, a, b);
}

/// `report` with the length-error code (`mov r0, #8`).
#[inline]
unsafe fn report_error(a: u32, b: u32) {
    report(LENGTH_ERROR_CODE, a, b);
}

/// `report` with the out-of-range code (`mov r0, #9`).
#[inline]
unsafe fn report_range_error(index: u32, limit: u32) {
    report(RANGE_ERROR_CODE, index, limit);
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
#[inline(never)]
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
/// cxx_string_pair_copy_ctor — retailOS `FUN_083d7e98` @ `0x083d7e98`
/// (40 bytes; six direct, unconditional `bl` call sites at 0x0825c188,
/// 0x0825cd44, 0x083e360c, 0x083e36ac, 0x083e8de0, and 0x083e905c).
///
/// Raw ARM is ten instructions at 0x083d7e98..0x083d7ebc; the independent
/// two-word constructor begins at 0x083d7ec0. The unused r0 context is
/// discarded, a null destination returns unchanged without reading source,
/// and otherwise the constructor COW-copies first then second. Its tail call
/// returns the address of the destination's second string word. There are no
/// deliberate deviations.
///
/// # Safety
///
/// A non-null `destination` and `source` must designate valid two-string
/// records. `source` is dereferenced only after the destination null guard.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_pair_copy_ctor(
    _unused: *mut u8,
    destination: *mut *mut u8,
    source: *const *mut u8,
) -> *mut *mut u8 {
    if destination.is_null() {
        return destination.cast();
    }

    cxx_string_copy_ctor(destination, source);
    cxx_string_copy_ctor(destination.add(1), source.add(1))
}
/// cxx_string_pair_uninitialized_copy — retailOS `FUN_083e8dbc` @ `0x083e8dbc`
/// (64 bytes; three direct, unconditional `bl` call sites at 0x0825c684,
/// 0x083e37b4, and 0x083e3894; no predicated `bl` call sites).
///
/// Raw ARM spans 0x083e8dbc..0x083e8df8; the next independent function opens
/// with `push {r4-r6,lr}` at 0x083e8dfc. It uninitialized-copies the
/// half-open range of 8-byte COW string-pair records, passing its r3 context
/// to `cxx_string_pair_copy_ctor` for every record, and returns the output
/// cursor. There are no deliberate deviations.
///
/// # Safety
///
/// `first..last` must be a valid range of target-layout string pairs, and
/// `output` must provide one uninitialized pair for each source pair.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_pair_uninitialized_copy(
    first: *const *mut u8,
    last: *const *mut u8,
    output: *mut *mut u8,
    context: *mut u8,
) -> *mut *mut u8 {
    let mut source_cursor = first;
    let mut output_cursor = output;
    while source_cursor != last {
        cxx_string_pair_copy_ctor(context, output_cursor, source_cursor);
        source_cursor = source_cursor.add(2);
        output_cursor = output_cursor.add(2);
    }
    output_cursor
}



#[cfg(target_arch = "arm")]
unsafe extern "C" {
    #[link_name = "cxx_string_copy_ctor"]
    fn cxx_string_copy_ctor_opaque(
        destination: *mut *mut u8,
        source: *const *mut u8,
    ) -> *mut *mut u8;
}

/// cxx_string_pair_entry_copy_ctor — retailOS `FUN_083d7e58` @ `0x083d7e58`
/// (48 bytes; four direct, unconditional `bl` call sites at 0x081df428,
/// 0x083e2fb8, 0x083e3058, and 0x083e8fe4).
///
/// Raw ARM spans 0x083d7e58..0x083d7e84; the independent null-checking
/// sibling begins at 0x083d7e88. It discards the r0 owner, returns a null
/// destination without reading the source, COW-copies the two string words in
/// order, then copies the trailing word at +0x08. The return is the address
/// of the destination's second string word. Binary-wide ARM B/BL decoding
/// found four plain `bl` callers and no predicated, tail-branch, or data-word
/// references. No deliberate deviations.
///
/// # Safety
///
/// A non-null `destination` and `source` must designate valid 12-byte
/// target-layout entries.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_pair_entry_copy_ctor(
    _owner: *mut u8,
    destination: *mut CxxStringPairRangeEntry,
    source: *const CxxStringPairRangeEntry,
) -> *mut *mut u8 {
    if destination.is_null() {
        return destination.cast();
    }

    #[cfg(target_arch = "arm")]
    {
        cxx_string_copy_ctor_opaque(
            core::ptr::addr_of_mut!((*destination).first),
            core::ptr::addr_of!((*source).first),
        );
        let second = cxx_string_copy_ctor_opaque(
            core::ptr::addr_of_mut!((*destination).second),
            core::ptr::addr_of!((*source).second),
        );
        (second as *mut u8).add(4).cast::<u32>().write((*source).trailing);
        second
    }
    #[cfg(not(target_arch = "arm"))]
    {
        cxx_string_copy_ctor(
            core::ptr::addr_of_mut!((*destination).first),
            core::ptr::addr_of!((*source).first),
        );
        let second = cxx_string_copy_ctor(
            core::ptr::addr_of_mut!((*destination).second),
            core::ptr::addr_of!((*source).second),
        );
        (*destination).trailing = (*source).trailing;
        second
    }
}

/// cxx_string_pair_destroy — original @ 0x0825c8fc (32 bytes).
///
/// Source: `ipod-decomp/decomp/c/025/0825c8fc_FUN_0825c8fc.c`. The raw ARM
/// ABI accepts the 8-byte record in r0, calls [`cxx_string_release`] for its
/// +0x04 member and then its +0x00 member, restores the original record
/// pointer to r0, and returns it. The port uses the established release
/// implementation directly; neither field is rewritten.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_pair_destroy(
    record: *mut CxxStringPair,
) -> *mut CxxStringPair {
    cxx_string_release(core::ptr::addr_of_mut!((*record).second));
    cxx_string_release(core::ptr::addr_of_mut!((*record).first));
    record
}
/// cxx_string_pair_entry_destroy — original: `FUN_08257fa8` @ 0x08257fa8
/// (32 bytes; 8 direct, unconditional `bl` call sites and no predicated
/// forms, verified by decoding every ARM B/BL immediate in `osos.dec`).
///
/// The 12-byte record has COW string words at +0x00 and +0x04 followed by an
/// unexamined word at +0x08. It releases the second string, then the first,
/// and returns the original record pointer in r0.
///
/// Deliberate codegen-only deviation: this invokes the established
/// [`cxx_string_release`] port rather than preserving the raw `bl` sequence.
/// Its behavior is otherwise byte-for-byte equivalent to
/// [`cxx_string_pair_destroy`] @ 0x0825c8fc, so a distinct target text
/// section preserves this exported call target against LLVM's
/// identical-code folding.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.cxx_string_pair_entry_destroy")]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_pair_entry_destroy(
    record: *mut CxxStringPairRangeEntry,
) -> *mut CxxStringPairRangeEntry {
    cxx_string_release(core::ptr::addr_of_mut!((*record).second));
    cxx_string_release(core::ptr::addr_of_mut!((*record).first));
    record
}
/// cxx_string_pair_assign — original @ 0x0825c91c (36 bytes).
///
/// Source: `ipod-decomp/decomp/c/025/0825c91c_FUN_0825c91c.c`. The raw ARM
/// ABI accepts `destination` in r0 and `source` in r1, calls
/// [`cxx_string_assign`] on their +0x00 members and then their +0x04 members,
/// restores the saved destination pointer to r0, and returns it. Delegating
/// both calls preserves the COW string assignment's ownership and
/// self-assignment behavior without reimplementing it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_pair_assign(
    destination: *mut CxxStringPair,
    source: *const CxxStringPair,
) -> *mut CxxStringPair {
    cxx_string_assign(
        core::ptr::addr_of_mut!((*destination).first),
        core::ptr::addr_of!((*source).first),
    );
    cxx_string_assign(
        core::ptr::addr_of_mut!((*destination).second),
        core::ptr::addr_of!((*source).second),
    );
    destination
}


/// cxx_string_pair_range_destroy — original @ 0x083e2f48 (48 bytes).
///
/// Source: `ipod-decomp/decomp/c/038/083e2f48_FUN_083e2f48.c`. The raw ARM
/// ABI leaves `_unused` in r0 and accepts the half-open record range in r1/r2.
/// It walks `[first, last)` at the target's 12-byte stride and, for each
/// record, releases the +0x04 string before the +0x00 string. There is no
/// NULL or ordering guard: termination is pointer equality alone.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_pair_range_destroy(
    _unused: *mut u8,
    mut first: *mut CxxStringPairRangeEntry,
    last: *mut CxxStringPairRangeEntry,
) {
    while first != last {
        cxx_string_release(core::ptr::addr_of_mut!((*first).second));
        cxx_string_release(core::ptr::addr_of_mut!((*first).first));
        first = first.add(1);
    }
}

/// cxx_string_range_copy_construct — retailOS `FUN_083e8e7c` @ load address
/// **0x083e8e7c** (56 bytes, 0x083e8e7c..0x083e8eb0; the independent vector
/// range helper begins at 0x083e8eb4).
///
/// Raw ARM contains no plain `bl` and one predicated `blne`, to
/// [`cxx_string_copy_ctor`], rather than the three call sites Ghidra reports.
/// It copy-constructs each one-word COW string in `[first, last)` into
/// `destination`, advancing all cursors at the target's four-byte word stride,
/// and returns the end of the destination range. The `movs r0, r4` guard means
/// a null destination skips the constructor without reading its source; this
/// port uses `wrapping_add` so that zero-length and null-cursor behavior does
/// not introduce Rust pointer-arithmetic UB. No deliberate deviations.
///
/// # Safety
///
/// `first..last` must be a valid half-open range of COW string words. When
/// `destination` is non-null, it must have room for the same number of words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_range_copy_construct(
    mut first: *const *mut u8,
    last: *const *mut u8,
    mut destination: *mut *mut u8,
) -> *mut *mut u8 {
    while first != last {
        if !destination.is_null() {
            cxx_string_copy_ctor(destination, first);
        }
        first = first.wrapping_add(1);
        destination = destination.wrapping_add(1);
    }
    destination
}

#[cfg(test)]
#[test]
fn cxx_string_range_copy_constructs_each_word_and_returns_end() {
    let source = [empty_rep_data(), empty_rep_data(), empty_rep_data()];
    let mut destination = [core::ptr::null_mut(); 3];

    let end = unsafe {
        cxx_string_range_copy_construct(
            source.as_ptr(),
            source.as_ptr().wrapping_add(source.len()),
            destination.as_mut_ptr(),
        )
    };

    assert_eq!(destination, source);
    assert_eq!(end, destination.as_mut_ptr().wrapping_add(destination.len()));
}

#[cfg(test)]
#[test]
fn cxx_string_range_copy_empty_range_preserves_destination_cursor() {
    let mut destination = core::ptr::null_mut();

    let end = unsafe {
        cxx_string_range_copy_construct(
            core::ptr::null(),
            core::ptr::null(),
            core::ptr::addr_of_mut!(destination),
        )
    };

    assert_eq!(end, core::ptr::addr_of_mut!(destination));
    assert!(destination.is_null());
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
#[inline(never)]
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

/// string_object_copy_cstr_to_buffer — original: `FUN_080e9740` @
/// 0x080e9740 (72 bytes; source:
/// `ipod-decomp/decomp/c/008/080e9740_FUN_080e9740.c`).
///
/// Copies a [`StringObject`]'s C string into a caller-provided buffer and
/// replaces `*inout_length` with the full source length. The incoming word is
/// the `strncpy` byte limit: the copy stops at that many bytes and
/// zero-pads after a terminator, while the outgoing word is always `strlen`
/// of the untruncated source. The two calls to
/// [`string_object_c_str`] and the conditional gate are deliberately kept:
/// 0x080e9750 probes the accessor before copying, then 0x080e9778 obtains
/// it again for `strlen`. The current accessor never returns NULL (a NULL
/// payload becomes the shared empty C string), so the gate normally takes
/// the copy path; if an implementation returns NULL, the original leaves
/// `destination` untouched and writes zero to `*inout_length`.
///
/// The routine returns `void`; `inout_length` is its sole result location.
/// It has no ownership effect on the source or the returned C-string pointer.
///
/// The callee addresses are volatile-read function pointers to retain the
/// three `c_str` calls plus the `strncpy` and `strlen` call boundaries in
/// the ARM object; this is the same anti-inlining pattern used by
/// `string_object_len_plus1`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn string_object_copy_cstr_to_buffer(
    source: *const StringObject,
    destination: *mut u8,
    inout_length: *mut u32,
) {
    let c_str: unsafe extern "C" fn(*const StringObject) -> *const u8 =
        core::ptr::read_volatile(
            &(string_object_c_str as unsafe extern "C" fn(*const StringObject) -> *const u8),
        );
    let mut source_length = 0;
    if !c_str(source).is_null() {
        let cstr = c_str(source);
        let copy: unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8 =
            core::ptr::read_volatile(
                &(strncpy as unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8),
            );
        copy(destination, cstr, (*inout_length) as usize);
        let measure: unsafe extern "C" fn(*const u8) -> usize =
            core::ptr::read_volatile(&(strlen as unsafe extern "C" fn(*const u8) -> usize));
        source_length = measure(c_str(source)) as u32;
    }
    *inout_length = source_length;
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
    (*rep).refcount = (*rep).refcount.wrapping_add(1);
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
#[inline(never)]
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

/// cxx_string_replace_core — original: `FUN_083d865c` @ 0x083d865c
/// (552 bytes, 3 `bl` call sites — [`cxx_string_replace_cstr`],
/// [`cxx_string_append_substr`] and 0x083d8564's length-checked entry —
/// but every mutating member of the class funnels through those, so it
/// carries ~90 call sites of traffic).
///
/// The one mutation primitive: splice `n2` characters taken from
/// `source[source_pos ..]` over the `n1` characters at `string[pos ..]`.
/// This is libstdc++'s `_M_replace`, with the source described as
/// (base, length, offset, count) so a substring of another string can be
/// passed without materializing it.
///
/// Order of business, exactly as the original:
/// 1. Preconditions `pos <= size()` and `source_pos <= source_len`;
///    either violation reports code 9 and **falls through**.
/// 2. Clamp: `removed = min(n1, size() - pos)`,
///    `inserted = min(n2, source_len - source_pos)`.
/// 3. Length check `size() - removed <= MAX_CAPACITY - inserted`
///    (code 8, again falling through).
/// 4. An empty result releases the rep and parks on the shared empty
///    rep.
/// 5. Otherwise reallocate when the rep is shared (`refcount >= 1`),
///    too small (`capacity < new length`), or when `source` points
///    *into* our own buffer; else mutate in place.
///
/// Reallocation grows to `max(1.625 * old_length, old_length + 128,
/// new_length)` — a **different** policy from the construction path's
/// [`cxx_string_rep_reserve`], which floors at `+32` and works off the
/// old *capacity*.
///
/// Returns `string_data + pos`, i.e. an iterator to the splice point,
/// not `this`.
///
/// Faithful quirks:
/// - The tail copy sources from `data + pos + n1` using the **raw** `n1`,
///   not the clamped `removed`. Harmless: clamping can only bite when
///   `n1 >= size() - pos`, and then the tail length is 0 and no copy
///   happens at all.
/// - Falling through the code-9 report means `source_len - source_pos`
///   can wrap, and then the `inserted` clamp is a no-op: the splice
///   reads past the declared end of the source. Kept, wrapping and all.
/// - `refcount == -1` (leaked) counts as *not* shared here, so a leaked
///   rep is mutated in place — which is the point of leaking it.
/// - An allocation failure inside [`cxx_string_rep_create`] leaves a
///   NULL rep and the original then copies to address 12. The port does
///   not add a guard the original does not have.
/// - `size()` is re-read from the rep after each `bl` that could have
///   returned, as the original does.
#[cfg_attr(target_os = "none", no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn cxx_string_replace_core(
    string: *mut *mut u8,
    pos: u32,
    n1: u32,
    source: *const u8,
    source_len: u32,
    source_pos: u32,
    n2: u32,
) -> *mut u8 {
    let size = (*data_rep(*string)).length;
    if size < pos || source_pos > source_len {
        let limit = if size <= source_len { source_len } else { size };
        let index = if size >= pos { source_pos } else { pos };
        report_range_error(index, limit);
    }

    let size = (*data_rep(*string)).length;
    let available = source_len.wrapping_sub(source_pos);
    let room = size.wrapping_sub(pos);
    let removed = if n1 < room { n1 } else { room };
    let inserted = if n2 < available { n2 } else { available };
    let kept = size.wrapping_sub(removed);
    if kept > MAX_CAPACITY.wrapping_sub(inserted) {
        report_error(kept, MAX_CAPACITY.wrapping_sub(inserted));
    }

    let data = *string;
    let rep = data_rep(data);
    let size = (*rep).length;
    let kept = size.wrapping_sub(removed);
    let new_length = kept.wrapping_add(inserted);
    if new_length == 0 {
        cxx_string_release(string);
        *string = empty_rep_data();
        return (*string).add(pos as usize);
    }

    let tail = kept.wrapping_sub(pos);
    let insert_from = source.wrapping_add(source_pos as usize);
    let shared = ((*rep).refcount as u32).wrapping_add(1) > 1;
    let aliases_self = !source.is_null()
        && data as usize <= source as usize
        && (source as usize) < (data as usize).wrapping_add(size as usize);

    if shared || (*rep).capacity < new_length || aliases_self {
        let old_length = (*data_rep(*string)).length;
        let grown = old_length
            .wrapping_add(old_length >> 1)
            .wrapping_add(old_length >> 3);
        let floor = old_length.wrapping_add(MUTATE_GROWTH_FLOOR);
        let grown = if floor > grown { floor } else { grown };
        let capacity = if grown < new_length { new_length } else { grown };

        let fresh = rep_data(cxx_string_rep_create(string as *mut u8, capacity, new_length));
        if pos != 0 {
            __rt_memcpy(fresh, *string, pos as usize);
        }
        if inserted != 0 {
            __rt_memcpy(fresh.add(pos as usize), insert_from, inserted as usize);
        }
        if tail != 0 {
            __rt_memcpy(
                fresh.add(pos as usize).add(inserted as usize),
                (*string).add(pos as usize).add(n1 as usize),
                tail as usize,
            );
        }
        cxx_string_release(string);
        *string = fresh;
    } else {
        if tail != 0 {
            memmove(
                data.add(pos as usize).add(inserted as usize),
                data.add(pos as usize).add(n1 as usize),
                tail as usize,
            );
        }
        if inserted != 0 {
            memmove((*string).add(pos as usize), insert_from, inserted as usize);
        }
        (*data_rep(*string)).length = new_length;
        (*string).add(new_length as usize).write(0);
    }
    (*string).add(pos as usize)
}

/// cxx_string_replace_cstr — original: `FUN_083d8624` @ 0x083d8624
/// (56 bytes, 3 `bl` call sites).
///
/// `replace(pos, n1, const char *s, n2)`: hands
/// [`cxx_string_replace_core`] the whole of `s` as the source range
/// (`source_len = n2`, `source_pos = 0`), so nothing is clamped away.
/// Returns `string`, discarding the core's iterator.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_string_replace_cstr(
    string: *mut *mut u8,
    pos: u32,
    n1: u32,
    source: *const u8,
    n2: u32,
) -> *mut *mut u8 {
    cxx_string_replace_core(string, pos, n1, source, n2, 0, n2);
    string
}

/// cxx_string_append_substr — original: `FUN_083d8564` @ 0x083d8564
/// (188 bytes, 3 `bl` call sites).
///
/// `append(const basic_string &other, size_type pos, size_type n)`:
/// checks `pos <= other.size()` (code 9) and the resulting length
/// (code 8) itself — both falling through on failure, as everywhere else
/// in this class — then splices at `size()` with `n1 = 0`. The source
/// range handed to the core is `other`'s whole buffer plus the offset,
/// so the core clamps `n` against `other.size() - pos` a second time.
/// Returns `string`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_string_append_substr(
    string: *mut *mut u8,
    other: *const *mut u8,
    pos: u32,
    n: u32,
) -> *mut *mut u8 {
    let other_length = (*data_rep(*other)).length;
    if other_length < pos {
        report_range_error(pos, other_length);
    }
    let other_length = (*data_rep(*other)).length;
    let available = other_length.wrapping_sub(pos);
    let appended = if n < available { n } else { available };
    let size = (*data_rep(*string)).length;
    if size > MAX_CAPACITY.wrapping_sub(appended) {
        report_error(size, MAX_CAPACITY.wrapping_sub(appended));
    }
    let other_data = *other;
    let size = (*data_rep(*string)).length;
    cxx_string_replace_core(
        string,
        size,
        0,
        other_data,
        (*data_rep(other_data)).length,
        pos,
        n,
    );
    string
}

/// cxx_string_assign_cstr — original: `FUN_083d8ca0` @ 0x083d8ca0
/// (120 bytes, 20 `bl` + 4 `b` = 24 call sites).
///
/// `operator=(const char *)`. Assigning an empty string is special-cased
/// away from the mutation core: a *sole owner* (`refcount == 0`) is
/// truncated in place — length 0 and a NUL at `data[0]`, keeping the
/// buffer — while anything else (shared, or leaked at -1) is released
/// and parked on the shared empty rep. A non-empty source is
/// `replace(0, size(), s, strlen(s))`. Returns `string`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_assign_cstr(
    string: *mut *mut u8,
    source: *const u8,
) -> *mut *mut u8 {
    let length = strlen(source) as u32;
    let data = *string;
    if length != 0 {
        let size = (*data_rep(data)).length;
        return cxx_string_replace_cstr(string, 0, size, source, length);
    }
    if (*data_rep(data)).refcount == 0 {
        (*data_rep(data)).length = 0;
        (*string).write(0);
        return string;
    }
    cxx_string_release(string);
    *string = empty_rep_data();
    string
}

/// cxx_string_assign — original: `FUN_083d8d1c` @ 0x083d8d1c
/// (104 bytes, 42 `bl` + 4 `b` = 46 call sites).
///
/// `operator=(const basic_string &)`. A shareable source rep is grabbed
/// outright: bump its refcount, release ours, adopt its pointer — and
/// self-assignment survives that unguarded because the bump precedes the
/// release. A *leaked* source (`refcount == -1`) cannot be shared, so it
/// is copied through the mutation core instead, and only that path needs
/// (and has) the `this == &src` guard. Returns `string`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_assign(
    string: *mut *mut u8,
    src: *const *mut u8,
) -> *mut *mut u8 {
    let src_data = *src;
    let src_rep = data_rep(src_data);
    if (*src_rep).refcount != -1 {
        cxx_string_rep_add_ref(src_rep);
        cxx_string_release(string);
        *string = *src;
        return string;
    }
    if string as *const *mut u8 == src {
        return string;
    }
    let size = (*data_rep(*string)).length;
    let src_length = (*src_rep).length;
    cxx_string_replace_cstr(string, 0, size, src_data, src_length);
    string
}

/// cxx_string_append_cstr — original: `FUN_083d8d84` @ 0x083d8d84
/// (56 bytes, 20 `bl` + 1 `b` = 21 call sites).
///
/// `operator+=(const char *)` / `append(const char *)`: measures the
/// source, then `replace(size(), 0, s, len)`. `size()` is captured
/// *before* the `strlen` call, matching the original's register
/// scheduling. Returns `string`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_string_append_cstr(
    string: *mut *mut u8,
    source: *const u8,
) -> *mut *mut u8 {
    let size = (*data_rep(*string)).length;
    let length = strlen(source) as u32;
    cxx_string_replace_cstr(string, size, 0, source, length)
}

/// cxx_string_empty — original: `FUN_083d6f0c` @ 0x083d6f0c (20 bytes;
/// 7 direct, unconditional `bl` call sites, verified by decoding every ARM
/// B/BL immediate in `osos.dec`; no predicated forms).
///
/// `basic_string::empty()`: loads the one-word string object's data pointer,
/// then its `_Rep` length at `data - 4`, and returns true exactly when that
/// length is zero. The `rsbs` / `movcc` tail normalizes every nonzero
/// 32-bit length to false. It has no NULL guard, matching the raw body; no
/// deliberate deviations.
///
/// # Safety
/// `string` must point to a valid one-word COW string object whose data
/// pointer has a readable length word immediately before it.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_empty(string: *const *mut u8) -> bool {
    ((*string as *const u32).sub(1).read()) == 0
}

/// `cxx_string_empty` depends solely on the `_Rep` length word, including
/// lengths with their top bit set.
#[cfg(test)]
#[test]
fn cxx_string_empty_checks_only_rep_length() {
    #[repr(C)]
    struct StringStorage {
        rep: StringRep,
        data: [u8; 1],
    }

    let mut storage = StringStorage {
        rep: StringRep { refcount: 0, capacity: 0, length: 0 },
        data: [0],
    };
    let string = storage.data.as_mut_ptr();
    for (refcount, capacity, length, expected) in [
        (0, 0, 0, true),
        (-1, 1, 1, false),
        (37, u32::MAX, u32::MAX, false),
    ] {
        storage.rep = StringRep { refcount, capacity, length };
        assert_eq!(unsafe { cxx_string_empty(&string) }, expected);
    }
}

/// cxx_string_less — original: `FUN_083d74f4` @ 0x083d74f4
/// (116 bytes, 34 `bl` call sites; the only copy of this body).
///
/// `std::less<basic_string>::operator()(const basic_string &a, const
/// basic_string &b)` — lexicographic `a < b`, the ordering every
/// string-keyed container in the OS sorts on. `memcmp` over
/// `min(a.size(), b.size())` bytes first; on a tie the shorter string
/// wins. The original computes the full three-way result and then keeps
/// only its sign bit (`lsr r0, r0, #31`), so the return is 0 or 1.
///
/// Byte-safe: the comparison is length-driven, so embedded NULs order
/// correctly. `this` arrives in r0 and is overwritten by the first
/// load; it is kept in the signature so call sites transcribe
/// one-to-one. Both lengths are re-read after the `memcmp` call, as the
/// original does.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn cxx_string_less(
    _this: *const u8,
    a: *const *mut u8,
    b: *const *mut u8,
) -> u32 {
    let a_length = (*data_rep(*a)).length;
    let b_length = (*data_rep(*b)).length;
    let shortest = if b_length < a_length { b_length } else { a_length };
    let mut ordering = memcmp(*a, *b, shortest as usize);
    if ordering == 0 {
        let a_length = (*data_rep(*a)).length;
        let b_length = (*data_rep(*b)).length;
        ordering = match a_length.cmp(&b_length) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        };
    }
    (ordering as u32) >> 31
}
/// cxx_string_equals_cstr — original: `FUN_083eab9c` @ 0x083eab9c
/// (108 bytes; 9 direct incoming `bl` call sites, all unconditional,
/// binary-scanned).
///
/// `basic_string<char>::operator==(const char *)`: captures the COW
/// `_Rep` length from `data - 4`, measures the C string, reloads the COW
/// data and length, then `memcmp`s the shorter byte range. A byte tie is
/// resolved by comparing the COW length with the C-string length, and only
/// an exact zero three-way result returns the widened C++ bool 1. Therefore
/// embedded NUL bytes remain part of the COW string but terminate the C
/// string. Volatile function-pointer reads retain the retail `strlen` and
/// `memcmp` call boundaries; no behavioral deviations.
///
/// # Safety
/// `string` must point to a valid one-word COW string object whose data has
/// a readable length word immediately before it; `cstr` must be a readable,
/// NUL-terminated byte string.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_equals_cstr(
    string: *const *mut u8,
    cstr: *const u8,
) -> i32 {
    let initial_data = string.read();
    let initial_length = (initial_data as *const u32).sub(1).read();
    let measure: unsafe extern "C" fn(*const u8) -> usize =
        core::ptr::read_volatile(&(strlen as unsafe extern "C" fn(*const u8) -> usize));
    let cstr_length = measure(cstr) as u32;
    let data = string.read();
    let current_length = (data as *const u32).sub(1).read();
    let shared_length = if current_length < initial_length {
        current_length
    } else {
        initial_length
    };
    let compare: unsafe extern "C" fn(*const u8, *const u8, usize) -> i32 =
        core::ptr::read_volatile(
            &(memcmp as unsafe extern "C" fn(*const u8, *const u8, usize) -> i32),
        );
    let mut ordering = compare(data, cstr, shared_length as usize);
    if ordering == 0 {
        ordering = match shared_length.cmp(&cstr_length) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        };
    }
    i32::from(ordering == 0)
}


/// strstreambuf_has_input_and_output — original: `FUN_083d7008` @
/// 0x083d7008 (24 bytes: `ldr/mov/bics/movne/moveq/bx`; 2 direct `bl`
/// call sites).
///
/// Tests the `strstreambuf` mode word at `this + 4`: bits 0x4 and 0x8
/// independently mark an active input and output area. It returns true
/// only when both are set. Its two direct callers reallocate the put
/// buffer, then use this predicate to decide whether the get-area
/// pointers need to follow that relocation. `this` is dereferenced
/// unconditionally, as in the original. No deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn strstreambuf_has_input_and_output(this: *const u8) -> bool {
    const INPUT_AND_OUTPUT: u32 = 0x0c;
    ((this.add(4) as *const u32).read() & INPUT_AND_OUTPUT) == INPUT_AND_OUTPUT
}

/// `strstreambuf_has_input_and_output` reads the mode word at `this + 4`;
/// no other object field participates.
#[cfg(test)]
#[test]
fn strstreambuf_mode_requires_both_input_and_output_bits() {
    #[repr(C)]
    struct StrstreamBufferMode {
        vtable: u32,
        mode: u32,
        ignored: u32,
    }

    for mode in 0u32..16 {
        let object = StrstreamBufferMode {
            vtable: 0xfeed_face,
            mode,
            ignored: !mode,
        };
        let expected = mode & 0x0c == 0x0c;
        assert_eq!(
            unsafe { strstreambuf_has_input_and_output((&object as *const StrstreamBufferMode).cast()) },
            expected,
            "mode {mode:#x}"
        );
    }
}
/// strstreambuf_is_eof — original: `FUN_083d7044` @ 0x083d7044 (16 bytes:
/// `cmn/movne/moveq/bx`; 7 direct `bl` call sites).
///
/// Returns whether a `strstreambuf` character result is the signed EOF
/// sentinel, -1. The callback's `this` argument is deliberately ignored:
/// the raw ARM body only reads r1, comparing its full 32-bit signed value
/// against -1, and normalizes the result to a C++ `bool`. No deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn strstreambuf_is_eof(_this: *const u8, character: i32) -> bool {
    character == -1
}

/// `strstreambuf_is_eof` recognizes only the signed 32-bit EOF sentinel
/// and does not inspect its callback receiver.
#[cfg(test)]
#[test]
fn strstreambuf_is_eof_accepts_only_negative_one() {
    let ignored_receiver = 1usize as *const u8;
    for (character, expected) in [
        (-1, true),
        (0, false),
        (1, false),
        (i32::MIN, false),
        (i32::MAX, false),
    ] {
        assert_eq!(
            unsafe { strstreambuf_is_eof(ignored_receiver, character) },
            expected,
            "character {character}"
        );
    }
}

/// strstreambuf_is_eof_alias — original: `FUN_083d7054` @ 0x083d7054
/// (16 bytes: `cmn/movne/moveq/mov pc,lr`; 3 direct `bl` call sites).
///
/// Returns whether a `strstreambuf` character result is the signed EOF
/// sentinel, -1. This separately addressed callback has the same predicate
/// as [`strstreambuf_is_eof`] at 0x083d7044, but has its own export because
/// callers retain its original load-address identity. Its `this` argument is
/// deliberately ignored: the raw ARM body reads only r1, then normalizes the
/// comparison to a C++ `bool`. The only raw-code difference from 0x083d7044
/// is its semantically equivalent `mov pc,lr` return. No deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.strstreambuf_is_eof_alias"))]
#[inline(never)]
pub unsafe extern "C" fn strstreambuf_is_eof_alias(
    _this: *const u8,
    character: i32,
) -> bool {
    character == -1
}

/// `strstreambuf_is_eof_alias` is independently callable despite sharing
/// `strstreambuf_is_eof`'s EOF-only predicate.
#[cfg(test)]
#[test]
fn strstreambuf_is_eof_alias_accepts_only_negative_one() {
    let ignored_receiver = 1usize as *const u8;
    for (character, expected) in [
        (-1, true),
        (0, false),
        (1, false),
        (i32::MIN, false),
        (i32::MAX, false),
    ] {
        assert_eq!(
            unsafe { strstreambuf_is_eof_alias(ignored_receiver, character) },
            expected,
            "character {character}"
        );
    }
}



/// strstreambuf_input_available — original: `FUN_083d7020` @ 0x083d7020
/// (36 bytes: `ldr/and/lsrs/ldrne/cmpne/ldrne/moveq/subne/mov`; 1 direct
/// `bl` call site).
///
/// Returns the active input area's remaining span: the end cursor at
/// `this + 0x18` minus its current cursor at `this + 0x14`. Input mode is
/// bit 0x4 of the mode word at `this + 4`; with that bit clear, or with a
/// null end cursor, the result is zero. The conditional loads preserve the
/// original's behavior: the current cursor is read only when input mode is
/// active and the end cursor is non-null. No deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn strstreambuf_input_available(this: *const u8) -> i32 {
    const INPUT_ACTIVE: u32 = 0x04;
    if (this.add(4) as *const u32).read() & INPUT_ACTIVE == 0 {
        return 0;
    }

    let input_end = (this.add(0x18) as *const u32).read();
    if input_end == 0 {
        return 0;
    }

    let input_cursor = (this.add(0x14) as *const u32).read();
    (input_end as i32).wrapping_sub(input_cursor as i32)
}

/// `strstreambuf_input_available` only exposes an input area selected by
/// mode bit 0x4, and returns its end-minus-current span modulo 2^32.
#[cfg(test)]
#[test]
fn strstreambuf_input_available_honors_mode_and_cursors() {
    #[repr(C)]
    struct StrstreamBufferInput {
        vtable: u32,
        mode: u32,
        ignored: [u32; 3],
        input_cursor: u32,
        input_end: u32,
    }

    for (mode, input_cursor, input_end, expected) in [
        (0x00, 0x10, 0x40, 0),
        (0x08, 0x10, 0x40, 0),
        (0x04, 0x10, 0x40, 0x30),
        (0x0c, 0x40, 0x10, -0x30),
        (0x04, 0x10, 0x00, 0),
    ] {
        let object = StrstreamBufferInput {
            vtable: 0xfeed_face,
            mode,
            ignored: [0xa5a5_a5a5; 3],
            input_cursor,
            input_end,
        };
        assert_eq!(
            unsafe { strstreambuf_input_available((&object as *const StrstreamBufferInput).cast()) },
            expected,
            "mode {mode:#x}, cursor {input_cursor:#x}, end {input_end:#x}"
        );
    }
}

/// strstreambuf_active_buffer_capacity — original: `FUN_083d7134` @ load
/// address **0x083d7134** (36 bytes, 0x083d7134..0x083d7154; next sibling
/// starts at 0x083d7158). Whole-image ARM B/BL decoding finds five direct
/// call sites, all unconditional `bl`: 0x083d707c, 0x083d70a4, 0x083da878,
/// 0x083da8a8, and 0x083dabb0.
///
/// Selects a `strstreambuf` area's full capacity from its mode word. With
/// input bit 0x4 set, it returns `input_end (+0x1c) - input_begin (+0x14)`;
/// otherwise it returns `output_end (+0x28) - output_begin (+0x20)`. Raw
/// ARM dereferences all selected fields without null checks and performs a
/// wrapping 32-bit subtraction; this port preserves both behaviours. No
/// deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.strstreambuf_active_buffer_capacity"))]
#[inline(never)]
pub unsafe extern "C" fn strstreambuf_active_buffer_capacity(this: *const u8) -> i32 {
    const INPUT_ACTIVE: u32 = 0x04;
    let (begin, end) = if (this.add(4) as *const u32).read() & INPUT_ACTIVE != 0 {
        (
            (this.add(0x14) as *const u32).read(),
            (this.add(0x1c) as *const u32).read(),
        )
    } else {
        (
            (this.add(0x20) as *const u32).read(),
            (this.add(0x28) as *const u32).read(),
        )
    };
    (end as i32).wrapping_sub(begin as i32)
}

/// `strstreambuf_active_buffer_capacity` selects the full input area only
/// for mode bit 0x4; output fields must not affect that selected span.
#[cfg(test)]
#[test]
fn strstreambuf_active_buffer_capacity_selects_the_mode_area() {
    #[repr(C)]
    struct StrstreamBufferAreas {
        vtable: u32,
        mode: u32,
        allocation: u32,
        allocation_size: u32,
        flags: u32,
        input_begin: u32,
        input_current: u32,
        input_end: u32,
        output_begin: u32,
        output_current: u32,
        output_end: u32,
    }

    for (mode, input_begin, input_end, output_begin, output_end, expected) in [
        (0x00, 0x100, 0x180, 0x200, 0x260, 0x60),
        (0x08, 0x100, 0x180, 0x280, 0x300, 0x80),
        (0x04, 0x100, 0x180, 0x200, 0x260, 0x80),
        (0x0c, 0x180, 0x100, 0x200, 0x260, -0x80),
        (0x04, 4, 0, 0x200, 0x260, -4),
    ] {
        let object = StrstreamBufferAreas {
            vtable: 0xfeed_face,
            mode,
            allocation: 0,
            allocation_size: 0,
            flags: 0,
            input_begin,
            input_current: 0xdead_beef,
            input_end,
            output_begin,
            output_current: 0xcafe_babe,
            output_end,
        };
        assert_eq!(
            unsafe { strstreambuf_active_buffer_capacity((&object as *const StrstreamBufferAreas).cast()) },
            expected,
            "mode {mode:#x}"
        );
    }
}

/// strstreambuf_copy_active_buffer — retailOS `FUN_083d7064` @ load address
/// **0x083d7064** (208 bytes, 0x083d7064..0x083d7130; the next independent
/// helper begins at 0x083d7134).
///
/// Raw ARM contains four unconditional and four predicated `bl` instructions:
/// it obtains the selected area capacity twice through
/// [`strstreambuf_active_buffer_capacity`], allocates a temporary COW string
/// only for a nonzero capacity, copies the buffer at target word `this + 8`,
/// copy-constructs `destination`, then releases the temporary. Zero capacity
/// copy-constructs directly from the shared empty representation. The
/// temporary makes the returned string an owning COW value rather than an
/// alias of the stream buffer. No deliberate deviations.
///
/// # Safety
///
/// `destination` must point to uninitialized storage for one COW string.
/// `this` must be a valid target-layout strstreambuf whose selected buffer
/// covers its reported capacity.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn strstreambuf_copy_active_buffer(
    destination: *mut *mut u8,
    this: *const u8,
) {
    let capacity = strstreambuf_active_buffer_capacity(this) as u32;
    let mut temporary = empty_rep_data();

    if capacity != 0 {
        let source = (this.add(8) as *const u32).read() as usize as *const u8;
        temporary = cxx_string_rep_reserve(core::ptr::null_mut(), 0, capacity, capacity);
        core::ptr::copy_nonoverlapping(source, temporary, capacity as usize);
    }

    cxx_string_copy_ctor(destination, &temporary);
    cxx_string_release(&mut temporary);
}



/// `strstreambuf_set_buffer_owned` — original: `FUN_083da558` @ load address
/// **0x083da558** (24 bytes, 0x083da558..0x083da56c; the separately linked
/// bit-1 sibling begins at 0x083da570). Whole-image ARM B/BL decoding finds
/// five direct inbound calls, all unconditional plain `bl` forms at
/// 0x083d910c, 0x083da8d0, 0x083dac48, 0x083dad38, and 0x083daf34; there
/// are no predicated or tail-`b` calls.
///
/// Sets bit 0 of the strstream buffer's ownership word (word index 4) when
/// `owned` is nonzero and clears it when `owned` is zero, preserving every
/// other flag bit. The callers use this bit to decide whether replacing the
/// backing buffer releases the previous allocation. The raw `movs r2, r1`
/// makes this a zero/nonzero test, rather than a Rust `bool` ABI; no
/// deviations.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.strstreambuf_set_buffer_owned"))]
#[inline(never)]
pub unsafe extern "C" fn strstreambuf_set_buffer_owned(this: *mut u8, owned: u32) {
    let ownership = this.cast::<u32>().add(4);
    let flags = ownership.read();
    ownership.write(if owned == 0 { flags & !1 } else { flags | 1 });
}

/// The ownership helper must leave adjacent target words and every non-owner
/// flag untouched, while treating every nonzero input as true.
#[cfg(test)]
#[test]
fn strstreambuf_set_buffer_owned_preserves_adjacent_words_and_flag_bits() {
    #[repr(C)]
    struct StrstreamBufferOwnership {
        vtable: u32,
        mode: u32,
        buffer: u32,
        buffer_length: u32,
        ownership_flags: u32,
        trailing: [u32; 2],
    }

    for (initial_flags, owned, expected_flags) in [
        (0xffff_fffe, 0, 0xffff_fffe),
        (0xffff_ffff, 0, 0xffff_fffe),
        (0xffff_fffe, 1, 0xffff_ffff),
        (0x1234_5678, 2, 0x1234_5679),
        (0x8000_0000, u32::MAX, 0x8000_0001),
    ] {
        let mut buffer = StrstreamBufferOwnership {
            vtable: 0xfeed_face,
            mode: 0xa5a5_a5a5,
            buffer: 0x1020_3040,
            buffer_length: 0x5060_7080,
            ownership_flags: initial_flags,
            trailing: [0x1122_3344, 0x5566_7788],
        };

        unsafe { strstreambuf_set_buffer_owned((&mut buffer as *mut StrstreamBufferOwnership).cast(), owned) };

        assert_eq!(buffer.ownership_flags, expected_flags, "owned {owned:#x}");
        assert_eq!(buffer.vtable, 0xfeed_face);
        assert_eq!(buffer.mode, 0xa5a5_a5a5);
        assert_eq!(buffer.buffer, 0x1020_3040);
        assert_eq!(buffer.buffer_length, 0x5060_7080);
        assert_eq!(buffer.trailing, [0x1122_3344, 0x5566_7788]);
    }
}

/// Target ABI for the stream buffer's virtual underflow callback.
type StreambufUnderflow = unsafe extern "C" fn(*mut Streambuf) -> i32;

/// Target ABI for the stream buffer's virtual overflow callback.
type StreambufOverflow = unsafe extern "C" fn(*mut Streambuf, i32) -> i32;

/// The virtual-table slots reached by [`streambuf_sgetc`] and
/// [`streambuf_sputc`].
#[repr(C)]
struct StreambufVtable {
    /// Slots `+0x00..+0x1c` are not read by these helpers.
    opaque_before_underflow: [usize; 8],
    /// `+0x20`: virtual fallback for an exhausted get area.
    underflow: StreambufUnderflow,
    /// `+0x24` is not read by these helpers.
    opaque_before_overflow: [usize; 1],
    /// `+0x28`: virtual fallback for a full or inactive put area.
    overflow: StreambufOverflow,
}

/// The stream-buffer fields reached by [`streambuf_sgetc`] and
/// [`streambuf_sputc`].
#[repr(C)]
struct Streambuf {
    /// `+0x00`: virtual method table.
    vtable: *const StreambufVtable,
    /// `+0x04`: mode word; bit 0x8 enables the put area.
    mode: u32,
    /// `+0x08..+0x14`: fields not read by these helpers.
    opaque_before_input: [u32; 4],
    /// `+0x18`: next byte in the get area.
    input_current: *const u8,
    /// `+0x1c`: exclusive get-area bound.
    input_end: *const u8,
    /// `+0x20`: field not read by these helpers.
    opaque_before_output: [u32; 1],
    /// `+0x24`: next byte in the put area.
    output_current: *mut u8,
    /// `+0x28`: exclusive put-area bound.
    output_end: *mut u8,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x18] = [0; core::mem::offset_of!(Streambuf, input_current)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x1c] = [0; core::mem::offset_of!(Streambuf, input_end)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x24] = [0; core::mem::offset_of!(Streambuf, output_current)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x28] = [0; core::mem::offset_of!(Streambuf, output_end)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x20] = [0; core::mem::offset_of!(StreambufVtable, underflow)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x28] = [0; core::mem::offset_of!(StreambufVtable, overflow)];

#[cfg(not(target_arch = "arm"))]
pub(crate) type StreambufUnderflowHook = unsafe extern "C" fn(*mut u8) -> i32;

#[cfg(not(target_arch = "arm"))]
unsafe extern "C" fn unavailable_streambuf_underflow(_streambuf: *mut u8) -> i32 {
    -1
}

#[cfg(not(target_arch = "arm"))]
pub(crate) static mut STREAMBUF_UNDERFLOW: StreambufUnderflowHook = unavailable_streambuf_underflow;

#[cfg(target_arch = "arm")]
#[inline(always)]
unsafe fn streambuf_underflow(streambuf: *mut Streambuf) -> i32 {
    ((*(*streambuf).vtable).underflow)(streambuf)
}

#[cfg(not(target_arch = "arm"))]
#[inline(always)]
unsafe fn streambuf_underflow(streambuf: *mut Streambuf) -> i32 {
    core::ptr::read_volatile(core::ptr::addr_of!(STREAMBUF_UNDERFLOW))(streambuf.cast())
}

/// `streambuf_sgetc` — original: `FUN_083da5a8` @ load address
/// **0x083da5a8** (32 bytes).
///
/// Raw ARM fixes the exact extent at 0x083da5a8..0x083da5c4: the following
/// `bx lr` at 0x083da5c4 terminates this helper, and the separately linked
/// `streambuf_sputc` sibling begins at 0x083da5c8. Decoding every ARM
/// B/BL-immediate word in `osos.dec` finds five inbound direct calls, all
/// unconditional plain `bl` (zero predicated): 0x083d6524, 0x083d653c,
/// 0x083d716c, 0x083d8264, and 0x083d82fc.
///
/// Returns the zero-extended byte at `input_current` when its unsigned address
/// is below `input_end`; it does not advance the cursor. Otherwise it calls
/// the stream-buffer vtable word at `+0x20` and returns that `i32` result.
/// No ARM deviations. Non-ARM tests replace the target-width virtual callback
/// with a hook because a 32-bit vtable word cannot hold a native host pointer.
///
/// # Safety
///
/// `streambuf` must point to a valid stream buffer. When `input_current` is
/// below `input_end`, it must designate one readable byte. Otherwise its
/// vtable and `+0x20` underflow slot must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn streambuf_sgetc(streambuf: *mut u8) -> i32 {
    let streambuf = streambuf.cast::<Streambuf>();
    let input_current = (*streambuf).input_current;

    if (input_current as usize) < ((*streambuf).input_end as usize) {
        return input_current.read() as i32;
    }

    streambuf_underflow(streambuf)
}

/// `streambuf_sputc` — original: `FUN_083da5c8` @ load address
/// **0x083da5c8** (76 bytes).
///
/// Raw ARM establishes the exact extent 0x083da5c8..0x083da610: the `pop
/// {r2,r3,r4,pc}` at the latter address is followed by the separately linked
/// sibling at 0x083da614. Decoding every ARM B/BL-immediate word in
/// `osos.dec` finds five inbound direct calls, all unconditional plain `bl`
/// (zero predicated): 0x083d83b8, 0x083d91d4, 0x083d9530, 0x083da748, and
/// 0x083dacac.
///
/// If output mode bit 0x8 is set and `output_current != output_end`, stores
/// `character` at the current cursor, advances that cursor by one, and
/// returns the zero-extended byte. Otherwise it dispatches through the
/// stream-buffer vtable word at `+0x28` and returns the virtual result. No
/// deviations.
///
/// # Safety
///
/// `streambuf` must point to a valid stream buffer. When its output mode is
/// active and its cursors differ, `output_current` must designate one writable
/// byte and its successor must be representable. Otherwise its vtable and
/// `+0x28` overflow slot must be valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn streambuf_sputc(streambuf: *mut u8, character: u32) -> i32 {
    const OUTPUT_ACTIVE: u32 = 0x08;

    let character = (character & 0xff) as i32;
    let streambuf = streambuf.cast::<Streambuf>();
    if (*streambuf).mode & OUTPUT_ACTIVE != 0
        && (*streambuf).output_current != (*streambuf).output_end
    {
        let output_current = (*streambuf).output_current;
        (*streambuf).output_current = output_current.add(1);
        output_current.write(character as u8);
        return character;
    }

    ((*(*streambuf).vtable).overflow)(streambuf, character)
}

#[cfg(test)]
mod streambuf_sputc_tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static OVERFLOW: Mutex<OverflowRecord> = Mutex::new(OverflowRecord::new());

    #[derive(Clone, Copy)]
    struct OverflowRecord {
        calls: usize,
        streambuf: usize,
        character: i32,
    }

    impl OverflowRecord {
        const fn new() -> Self {
            Self {
                calls: 0,
                streambuf: 0,
                character: 0,
            }
        }
    }

    unsafe extern "C" fn unreachable_underflow(_streambuf: *mut Streambuf) -> i32 {
        -1
    }

    unsafe extern "C" fn record_overflow(streambuf: *mut Streambuf, character: i32) -> i32 {
        let mut record = OVERFLOW.lock().unwrap_or_else(|poison| poison.into_inner());
        record.calls += 1;
        record.streambuf = streambuf as usize;
        record.character = character;
        -1
    }

    fn streambuf(vtable: *const StreambufVtable) -> Streambuf {
        Streambuf {
            vtable,
            mode: 0,
            opaque_before_input: [0; 4],
            input_current: core::ptr::null(),
            input_end: core::ptr::null(),
            opaque_before_output: [0; 1],
            output_current: core::ptr::null_mut(),
            output_end: core::ptr::null_mut(),
        }
    }

    fn vtable() -> StreambufVtable {
        StreambufVtable {
            opaque_before_underflow: [0; 8],
            underflow: unreachable_underflow,
            opaque_before_overflow: [0; 1],
            overflow: record_overflow,
        }
    }

    fn reset_overflow() {
        *OVERFLOW.lock().unwrap_or_else(|poison| poison.into_inner()) = OverflowRecord::new();
    }

    #[test]
    fn sputc_writes_and_advances_an_active_put_area() {
        let _guard = TEST_LOCK.lock();
        reset_overflow();
        let vtable = vtable();
        let mut bytes = [0xa5, 0xa5, 0xa5];
        let mut buffer = streambuf(&vtable);
        buffer.mode = 0x08;
        buffer.output_current = unsafe { bytes.as_mut_ptr().add(1) };
        buffer.output_end = unsafe { bytes.as_mut_ptr().add(3) };

        assert_eq!(
            unsafe { streambuf_sputc((&mut buffer as *mut Streambuf).cast(), 0xffff_00fe) },
            0xfe
        );
        assert_eq!(bytes, [0xa5, 0xfe, 0xa5]);
        assert_eq!(buffer.output_current, unsafe { bytes.as_mut_ptr().add(2) });
        assert_eq!(OVERFLOW.lock().unwrap_or_else(|poison| poison.into_inner()).calls, 0);
    }

    #[test]
    fn sputc_dispatches_when_the_put_area_is_inactive() {
        let _guard = TEST_LOCK.lock();
        reset_overflow();
        let vtable = vtable();
        let mut buffer = streambuf(&vtable);

        assert_eq!(
            unsafe { streambuf_sputc((&mut buffer as *mut Streambuf).cast(), 0xffff_0081) },
            -1
        );
        let record = *OVERFLOW.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(record.calls, 1);
        assert_eq!(record.streambuf, &mut buffer as *mut Streambuf as usize);
        assert_eq!(record.character, 0x81);
    }

    #[test]
    fn sputc_dispatches_without_writing_when_the_put_area_is_full() {
        let _guard = TEST_LOCK.lock();
        reset_overflow();
        let vtable = vtable();
        let mut bytes = [0xa5, 0xa5];
        let mut buffer = streambuf(&vtable);
        buffer.mode = 0x08;
        buffer.output_current = unsafe { bytes.as_mut_ptr().add(2) };
        buffer.output_end = unsafe { bytes.as_mut_ptr().add(2) };

        assert_eq!(
            unsafe { streambuf_sputc((&mut buffer as *mut Streambuf).cast(), 0xffff_007f) },
            -1
        );
        assert_eq!(bytes, [0xa5, 0xa5]);
        assert_eq!(buffer.output_current, buffer.output_end);
        assert_eq!(OVERFLOW.lock().unwrap_or_else(|poison| poison.into_inner()).calls, 1);
    }
}

#[cfg(test)]
pub(crate) static STREAMBUF_UNDERFLOW_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(test)]
mod streambuf_sgetc_tests {
    extern crate std;

    use super::*;
    use std::sync::Mutex;

    static UNDERFLOW: Mutex<UnderflowRecord> = Mutex::new(UnderflowRecord::new());

    #[derive(Clone, Copy)]
    struct UnderflowRecord {
        calls: usize,
        streambuf: usize,
        result: i32,
    }

    impl UnderflowRecord {
        const fn new() -> Self {
            Self {
                calls: 0,
                streambuf: 0,
                result: -1,
            }
        }
    }

    unsafe extern "C" fn record_underflow(streambuf: *mut u8) -> i32 {
        let mut record = UNDERFLOW.lock().unwrap_or_else(|poison| poison.into_inner());
        record.calls += 1;
        record.streambuf = streambuf as usize;
        record.result
    }

    struct UnderflowReset(StreambufUnderflowHook);

    impl Drop for UnderflowReset {
        fn drop(&mut self) {
            unsafe { STREAMBUF_UNDERFLOW = self.0 };
        }
    }

    fn install_underflow(result: i32) -> UnderflowReset {
        *UNDERFLOW.lock().unwrap_or_else(|poison| poison.into_inner()) = UnderflowRecord {
            result,
            ..UnderflowRecord::new()
        };
        let previous = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(STREAMBUF_UNDERFLOW)) };
        unsafe { STREAMBUF_UNDERFLOW = record_underflow };
        UnderflowReset(previous)
    }

    fn streambuf(input_current: *const u8, input_end: *const u8) -> Streambuf {
        Streambuf {
            vtable: core::ptr::null(),
            mode: 0,
            opaque_before_input: [0; 4],
            input_current,
            input_end,
            opaque_before_output: [0; 1],
            output_current: core::ptr::null_mut(),
            output_end: core::ptr::null_mut(),
        }
    }

    #[test]
    fn sgetc_returns_an_unconsumed_zero_extended_input_byte() {
        let _guard = STREAMBUF_UNDERFLOW_TEST_LOCK.lock();
        let _reset = install_underflow(-1);
        let bytes = [0x4a, 0xff];
        let mut buffer = streambuf(unsafe { bytes.as_ptr().add(1) }, unsafe { bytes.as_ptr().add(2) });

        assert_eq!(unsafe { streambuf_sgetc((&mut buffer as *mut Streambuf).cast()) }, 0xff);
        assert_eq!(buffer.input_current, unsafe { bytes.as_ptr().add(1) });
        assert_eq!(UNDERFLOW.lock().unwrap_or_else(|poison| poison.into_inner()).calls, 0);
    }

    #[test]
    fn sgetc_dispatches_for_exhausted_or_inverted_get_areas() {
        let _guard = STREAMBUF_UNDERFLOW_TEST_LOCK.lock();
        let _reset = install_underflow(0x1234_5678);
        let bytes = [0x4a, 0xff];
        let mut buffer = streambuf(bytes.as_ptr(), bytes.as_ptr());

        assert_eq!(unsafe { streambuf_sgetc((&mut buffer as *mut Streambuf).cast()) }, 0x1234_5678);
        buffer.input_current = unsafe { bytes.as_ptr().add(2) };
        buffer.input_end = unsafe { bytes.as_ptr().add(1) };
        assert_eq!(unsafe { streambuf_sgetc((&mut buffer as *mut Streambuf).cast()) }, 0x1234_5678);

        let record = *UNDERFLOW.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(record.calls, 2);
        assert_eq!(record.streambuf, &mut buffer as *mut Streambuf as usize);
    }
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
    #[test]
    fn pair_copy_ctor_null_destination_returns_without_reading_source() {
        unsafe {
            assert!(cxx_string_pair_copy_ctor(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null(),
            )
            .is_null());
        }
    }

    #[test]
    fn pair_copy_ctor_shares_then_clones_and_returns_second_member() {
        let _guard = arena();
        unsafe {
            let mut source_first: *mut u8 = core::ptr::null_mut();
            let mut source_second: *mut u8 = core::ptr::null_mut();
            build(&mut source_first, b"shared");
            build(&mut source_second, b"leaked");
            (*data_rep(source_second)).refcount = -1;
            let source = CxxStringPair {
                first: source_first,
                second: source_second,
            };
            let mut destination = CxxStringPair {
                first: core::ptr::null_mut(),
                second: core::ptr::null_mut(),
            };
            let mut unused = 0_u32;

            assert_eq!(
                cxx_string_pair_copy_ctor(
                    core::ptr::addr_of_mut!(unused).cast(),
                    core::ptr::addr_of_mut!(destination.first),
                    core::ptr::addr_of!(source.first),
                ),
                core::ptr::addr_of_mut!(destination.second),
            );
            assert_eq!(destination.first, source.first);
            assert_eq!((*data_rep(source.first)).refcount, 1);
            assert_ne!(destination.second, source.second);
            assert_eq!(
                core::slice::from_raw_parts(destination.second, 7),
                b"leaked\0",
            );
            assert_eq!((*data_rep(source.second)).refcount, -1);
            assert_eq!((*data_rep(destination.second)).refcount, 0);
        }
    }

    #[test]
    fn pair_uninitialized_copy_constructs_every_pair_and_returns_end() {
        let _guard = arena();
        unsafe {
            let mut first: *mut u8 = core::ptr::null_mut();
            let mut second: *mut u8 = core::ptr::null_mut();
            build(&mut first, b"shared");
            build(&mut second, b"leaked");
            (*data_rep(second)).refcount = -1;
            let source = [
                CxxStringPair { first, second },
                CxxStringPair { first, second },
            ];
            let mut output = [
                CxxStringPair {
                    first: core::ptr::null_mut(),
                    second: core::ptr::null_mut(),
                },
                CxxStringPair {
                    first: core::ptr::null_mut(),
                    second: core::ptr::null_mut(),
                },
            ];

            assert_eq!(
                cxx_string_pair_uninitialized_copy(
                    source.as_ptr().cast(),
                    source.as_ptr().add(2).cast(),
                    output.as_mut_ptr().cast(),
                    core::ptr::null_mut(),
                ),
                output.as_mut_ptr().add(2).cast(),
            );
            assert_eq!((*data_rep(first)).refcount, 2);
            for pair in &output {
                assert_eq!(pair.first, first);
                assert_ne!(pair.second, second);
                assert_eq!(
                    core::slice::from_raw_parts(pair.second, 7),
                    b"leaked\0",
                );
            }
        }
    }

    #[test]
    fn pair_uninitialized_copy_empty_null_range_does_not_dereference() {
        unsafe {
            assert!(cxx_string_pair_uninitialized_copy(
                core::ptr::null(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
            .is_null());
        }
    }

    #[test]
    fn pair_entry_copy_ctor_copies_trailer_and_preserves_cow_semantics() {
        let _guard = arena();
        unsafe {
            let mut source_first: *mut u8 = core::ptr::null_mut();
            let mut source_second: *mut u8 = core::ptr::null_mut();
            build(&mut source_first, b"shared");
            build(&mut source_second, b"leaked");
            (*data_rep(source_second)).refcount = -1;
            let source = CxxStringPairRangeEntry {
                first: source_first,
                second: source_second,
                trailing: 0xa5a5_5a5a,
            };
            let mut destination = CxxStringPairRangeEntry {
                first: core::ptr::null_mut(),
                second: core::ptr::null_mut(),
                trailing: 0,
            };

            assert_eq!(
                cxx_string_pair_entry_copy_ctor(
                    core::ptr::null_mut(),
                    core::ptr::addr_of_mut!(destination),
                    core::ptr::addr_of!(source),
                ),
                core::ptr::addr_of_mut!(destination.second),
            );
            assert_eq!(destination.first, source.first);
            assert_eq!((*data_rep(source.first)).refcount, 1);
            assert_ne!(destination.second, source.second);
            assert_eq!(
                core::slice::from_raw_parts(destination.second, 7),
                b"leaked\0",
            );
            assert_eq!(destination.trailing, source.trailing);
        }
    }

    #[test]
    fn pair_entry_copy_ctor_null_destination_does_not_read_source() {
        unsafe {
            assert!(cxx_string_pair_entry_copy_ctor(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null(),
            )
            .is_null());
        }
    }

    #[test]
    fn pair_destroy_releases_second_before_first_and_returns_the_record() {
        let _guard = arena();
        unsafe {
            let mut first: *mut u8 = core::ptr::null_mut();
            let mut second: *mut u8 = core::ptr::null_mut();
            cxx_string_from_cstr(&mut first, b"first\0".as_ptr());
            cxx_string_from_cstr(&mut second, b"second\0".as_ptr());
            let first_rep = data_rep(first);
            let second_rep = data_rep(second);
            let mut record = CxxStringPair { first, second };
            let record_ptr = core::ptr::addr_of_mut!(record);

            assert_eq!(cxx_string_pair_destroy(record_ptr), record_ptr);
            assert_eq!(freed(), &[second_rep.cast(), first_rep.cast()]);
        }
    }
    #[test]
    fn pair_entry_destroy_releases_second_before_first_and_returns_the_record() {
        let _guard = arena();
        unsafe {
            let mut first: *mut u8 = core::ptr::null_mut();
            let mut second: *mut u8 = core::ptr::null_mut();
            cxx_string_from_cstr(&mut first, b"first\0".as_ptr());
            cxx_string_from_cstr(&mut second, b"second\0".as_ptr());
            let first_rep = data_rep(first);
            let second_rep = data_rep(second);
            let mut record = CxxStringPairRangeEntry {
                first,
                second,
                trailing: 0x5a5a_5a5a,
            };
            let record_ptr = core::ptr::addr_of_mut!(record);

            assert_eq!(cxx_string_pair_entry_destroy(record_ptr), record_ptr);
            assert_eq!(freed(), &[second_rep.cast(), first_rep.cast()]);
            assert_eq!(record.trailing, 0x5a5a_5a5a);
        }
    }
    #[test]
    fn pair_assigns_matching_members_in_first_then_second_order_and_returns_destination() {
        let _guard = arena();
        unsafe {
            let mut source_first: *mut u8 = core::ptr::null_mut();
            let mut source_second: *mut u8 = core::ptr::null_mut();
            let mut destination_first: *mut u8 = core::ptr::null_mut();
            let mut destination_second: *mut u8 = core::ptr::null_mut();
            build(&mut source_first, b"source first");
            build(&mut source_second, b"source second");
            build(&mut destination_first, b"destination first");
            build(&mut destination_second, b"destination second");
            let destination_first_rep = data_rep(destination_first);
            let destination_second_rep = data_rep(destination_second);
            let source = CxxStringPair {
                first: source_first,
                second: source_second,
            };
            let mut destination = CxxStringPair {
                first: destination_first,
                second: destination_second,
            };
            let destination_ptr = core::ptr::addr_of_mut!(destination);

            assert_eq!(
                cxx_string_pair_assign(destination_ptr, &source),
                destination_ptr
            );
            assert_eq!(destination.first, source.first);
            assert_eq!(destination.second, source.second);
            assert_eq!((*data_rep(source.first)).refcount, 1);
            assert_eq!((*data_rep(source.second)).refcount, 1);
            assert_eq!(
                freed(),
                &[destination_first_rep.cast(), destination_second_rep.cast()]
            );
        }
    }

    #[test]
    fn pair_assign_to_self_preserves_both_members() {
        let _guard = arena();
        unsafe {
            let mut first: *mut u8 = core::ptr::null_mut();
            let mut second: *mut u8 = core::ptr::null_mut();
            build(&mut first, b"first");
            build(&mut second, b"second");
            let first_data = first;
            let second_data = second;
            let mut record = CxxStringPair { first, second };
            let record_ptr = core::ptr::addr_of_mut!(record);

            assert_eq!(cxx_string_pair_assign(record_ptr, record_ptr), record_ptr);
            assert_eq!(record.first, first_data);
            assert_eq!(record.second, second_data);
            assert_eq!((*data_rep(record.first)).refcount, 0);
            assert_eq!((*data_rep(record.second)).refcount, 0);
            assert!(freed().is_empty());
        }
    }


    #[test]
    fn pair_range_destroy_leaves_an_empty_range_untouched() {
        let _guard = arena();
        unsafe {
            let mut first: *mut u8 = core::ptr::null_mut();
            cxx_string_from_cstr(&mut first, b"kept\0".as_ptr());
            let rep = data_rep(first);
            let mut record = CxxStringPairRangeEntry {
                first,
                second: empty_rep_data(),
                trailing: 0xa5a5_a5a5,
            };
            let boundary = core::ptr::addr_of_mut!(record);

            cxx_string_pair_range_destroy(core::ptr::null_mut(), boundary, boundary);

            assert_eq!((*rep).refcount, 0);
            assert!(freed().is_empty());
            cxx_string_release(core::ptr::addr_of_mut!(record.first));
        }
    }

    #[test]
    fn pair_range_destroy_releases_second_before_first() {
        let _guard = arena();
        unsafe {
            let mut first: *mut u8 = core::ptr::null_mut();
            let mut second: *mut u8 = core::ptr::null_mut();
            cxx_string_from_cstr(&mut first, b"first\0".as_ptr());
            cxx_string_from_cstr(&mut second, b"second\0".as_ptr());
            let first_rep = data_rep(first);
            let second_rep = data_rep(second);
            let mut record = CxxStringPairRangeEntry { first, second, trailing: 0 };
            let range_start = core::ptr::addr_of_mut!(record);

            cxx_string_pair_range_destroy(
                core::ptr::null_mut(),
                range_start,
                range_start.add(1),
            );

            assert_eq!(freed(), &[second_rep.cast(), first_rep.cast()]);
        }
    }

    #[test]
    fn pair_range_destroy_advances_through_multiple_records() {
        let _guard = arena();
        unsafe {
            let mut first0: *mut u8 = core::ptr::null_mut();
            let mut second0: *mut u8 = core::ptr::null_mut();
            let mut first1: *mut u8 = core::ptr::null_mut();
            let mut second1: *mut u8 = core::ptr::null_mut();
            cxx_string_from_cstr(&mut first0, b"first0\0".as_ptr());
            cxx_string_from_cstr(&mut second0, b"second0\0".as_ptr());
            cxx_string_from_cstr(&mut first1, b"first1\0".as_ptr());
            cxx_string_from_cstr(&mut second1, b"second1\0".as_ptr());
            let first0_rep = data_rep(first0);
            let second0_rep = data_rep(second0);
            let first1_rep = data_rep(first1);
            let second1_rep = data_rep(second1);
            let mut records = [
                CxxStringPairRangeEntry { first: first0, second: second0, trailing: 1 },
                CxxStringPairRangeEntry { first: first1, second: second1, trailing: 2 },
            ];
            let range_start = records.as_mut_ptr();

            cxx_string_pair_range_destroy(
                core::ptr::null_mut(),
                range_start,
                range_start.add(records.len()),
            );

            assert_eq!(
                freed(),
                &[
                    second0_rep.cast(),
                    first0_rep.cast(),
                    second1_rep.cast(),
                    first1_rep.cast(),
                ]
            );
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

    // ---- the mutation core -------------------------------------------

    /// Builds a string in the arena from arbitrary bytes.
    unsafe fn build(slot: *mut *mut u8, text: &[u8]) {
        cxx_string_from_buffer(slot, text.as_ptr(), text.len() as u32);
    }

    /// The stored characters (length from the rep, so embedded NULs and
    /// the terminator are both visible to the caller).
    unsafe fn text(slot: *mut *mut u8) -> Vec<u8> {
        let data = *slot;
        core::slice::from_raw_parts(data, (*data_rep(data)).length as usize).to_vec()
    }

    /// Reference splice: what `replace(pos, n1, src[src_pos..], n2)`
    /// must produce, written straight from the C++ semantics.
    fn reference_replace(s: &[u8], pos: u32, n1: u32, src: &[u8], src_pos: u32, n2: u32) -> Vec<u8> {
        let removed = n1.min(s.len() as u32 - pos) as usize;
        let inserted = n2.min(src.len() as u32 - src_pos) as usize;
        let mut out = Vec::new();
        out.extend_from_slice(&s[..pos as usize]);
        out.extend_from_slice(&src[src_pos as usize..src_pos as usize + inserted]);
        out.extend_from_slice(&s[pos as usize + removed..]);
        out
    }

    /// The mutation core's growth policy (`+128` floor, off the old
    /// *length*), transcribed from 0x083d8794..0x083d87b8.
    fn reference_mutate_capacity(old_length: u32, new_length: u32) -> u32 {
        let grown = (old_length + (old_length >> 1) + (old_length >> 3))
            .max(old_length + MUTATE_GROWTH_FLOOR);
        grown.max(new_length)
    }

    #[test]
    fn replace_core_matches_the_reference_in_place() {
        let _guard = arena();
        let base = b"0123456789";
        let src = b"ABCDE";
        unsafe {
            for pos in 0..=base.len() as u32 {
                for n1 in 0..=6u32 {
                    for n2 in 0..=5u32 {
                        ARENA_USED = 0;
                        let mut slot: *mut u8 = core::ptr::null_mut();
                        build(&mut slot, base);
                        let want = reference_replace(base, pos, n1, src, 0, n2);
                        let ret = cxx_string_replace_core(
                            &mut slot,
                            pos,
                            n1,
                            src.as_ptr(),
                            src.len() as u32,
                            0,
                            n2,
                        );
                        assert_eq!(text(&mut slot), want, "pos={pos} n1={n1} n2={n2}");
                        assert_eq!(ret, (*(&mut slot)).add(pos as usize), "returns data + pos");
                        if !want.is_empty() {
                            assert_eq!(
                                slot.add(want.len()).read(),
                                0,
                                "NUL terminated: pos={pos} n1={n1} n2={n2}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// A substring source (`src_pos`/`n2`) is clamped against the
    /// source's own length, not the destination's.
    #[test]
    fn replace_core_takes_a_substring_of_the_source() {
        let _guard = arena();
        let src = b"ABCDEFGH";
        unsafe {
            for src_pos in 0..=src.len() as u32 {
                for n2 in 0..=9u32 {
                    ARENA_USED = 0;
                    let mut slot: *mut u8 = core::ptr::null_mut();
                    build(&mut slot, b"xxxx");
                    let want = reference_replace(b"xxxx", 1, 2, src, src_pos, n2);
                    cxx_string_replace_core(
                        &mut slot,
                        1,
                        2,
                        src.as_ptr(),
                        src.len() as u32,
                        src_pos,
                        n2,
                    );
                    assert_eq!(text(&mut slot), want, "src_pos={src_pos} n2={n2}");
                }
            }
        }
    }

    #[test]
    fn replace_core_mutates_a_sole_owner_in_place() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            build(&mut slot, b"hello");
            let buffer = slot;
            let used = ARENA_USED;
            cxx_string_replace_core(&mut slot, 5, 0, b" world".as_ptr(), 6, 0, 6);
            assert_eq!(slot, buffer, "same buffer — capacity 32 has room");
            assert_eq!(text(&mut slot), b"hello world");
            assert_eq!(ARENA_USED, used, "no allocation");
            assert_eq!((*data_rep(slot)).capacity, 32, "capacity untouched");
        }
    }

    /// Outgrowing the capacity reallocates with the mutation core's own
    /// growth policy — `old_length + 128`, not the constructor's `+32`.
    #[test]
    fn replace_core_reallocates_with_the_plus_128_policy() {
        let _guard = arena();
        unsafe {
            let base = std::vec![b'x'; 100];
            let mut slot: *mut u8 = core::ptr::null_mut();
            build(&mut slot, &base);
            let old = slot;
            assert_eq!((*data_rep(slot)).capacity, 100);
            cxx_string_replace_core(&mut slot, 100, 0, b"12345".as_ptr(), 5, 0, 5);
            assert_ne!(slot, old, "fresh buffer");
            assert_eq!((*data_rep(slot)).length, 105);
            assert_eq!((*data_rep(slot)).capacity, reference_mutate_capacity(100, 105));
            assert_eq!((*data_rep(slot)).capacity, 228);
            assert_eq!(&text(&mut slot)[100..], b"12345");
            assert_eq!(freed(), &[data_rep(old) as *mut u8], "old rep released");
        }
    }

    /// A shared rep is never mutated in place — that is the whole of COW.
    #[test]
    fn replace_core_copies_a_shared_rep() {
        let _guard = arena();
        unsafe {
            let mut a: *mut u8 = core::ptr::null_mut();
            build(&mut a, b"shared");
            let mut b: *mut u8 = core::ptr::null_mut();
            cxx_string_copy_ctor(&mut b, &a);
            assert_eq!(a, b);
            cxx_string_replace_core(&mut b, 0, 6, b"other!".as_ptr(), 6, 0, 6);
            assert_ne!(a, b, "the shared buffer was left alone");
            assert_eq!(text(&mut a), b"shared");
            assert_eq!(text(&mut b), b"other!");
            assert_eq!((*data_rep(a)).refcount, 0, "the release dropped us back to one owner");
        }
    }

    /// A leaked rep (-1) is *not* shared, so it is mutated in place.
    #[test]
    fn replace_core_mutates_a_leaked_rep_in_place() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            build(&mut slot, b"leaked");
            let buffer = slot;
            (*data_rep(slot)).refcount = -1;
            cxx_string_replace_core(&mut slot, 0, 6, b"inplac".as_ptr(), 6, 0, 6);
            assert_eq!(slot, buffer);
            assert_eq!(text(&mut slot), b"inplac");
        }
    }

    /// A source pointing into our own buffer forces a reallocation, so a
    /// self-splice reads consistent bytes.
    #[test]
    fn replace_core_reallocates_when_the_source_aliases_the_buffer() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            build(&mut slot, b"abcdef");
            let buffer = slot;
            // Insert "abc" (our own first three bytes) at offset 3.
            cxx_string_replace_core(&mut slot, 3, 0, buffer, 6, 0, 3);
            assert_ne!(slot, buffer, "aliasing source forced a copy");
            assert_eq!(text(&mut slot), b"abcabcdef");
        }
    }

    /// One past the end of the buffer is *not* aliasing (`bls` on
    /// `data + size`), so it stays on the in-place path.
    #[test]
    fn replace_core_source_just_past_the_buffer_is_not_aliasing() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            build(&mut slot, b"abcdef");
            let buffer = slot;
            let past = buffer.add(6);
            past.add(0).write(b'Z');
            cxx_string_replace_core(&mut slot, 0, 1, past, 1, 0, 1);
            assert_eq!(slot, buffer, "no reallocation");
            assert_eq!(text(&mut slot), b"Zbcdef");
        }
    }

    #[test]
    fn replace_core_emptying_parks_on_the_singleton() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            build(&mut slot, b"gone");
            let rep = data_rep(slot);
            let ret = cxx_string_replace_core(&mut slot, 0, 4, b"".as_ptr(), 0, 0, 0);
            assert_eq!(slot, empty_rep_data());
            assert_eq!(ret, empty_rep_data());
            assert_eq!(freed(), &[rep as *mut u8]);
        }
    }

    /// `source_pos > source_len` reports code 9 and then falls straight
    /// through, like every other check in this class — and because
    /// `source_len - source_pos` wraps, nothing is clamped and the
    /// splice reads past the declared end of the source. The port keeps
    /// that (the source buffer here is padded so the read is defined).
    #[test]
    fn replace_core_reports_out_of_range_and_falls_through() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static CODES: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn recording(code: usize, _: *const u8, _: *const u8, _: u32, _: u32) {
            CODES.fetch_add(code, Ordering::SeqCst);
        }
        let _guard = arena();
        unsafe {
            let saved = CXX_STRING_OPS.report_error;
            (*core::ptr::addr_of_mut!(CXX_STRING_OPS)).report_error = recording;
            let mut slot: *mut u8 = core::ptr::null_mut();
            build(&mut slot, b"abc");
            let source = b"XY___Z__";
            cxx_string_replace_core(&mut slot, 0, 0, source.as_ptr(), 2, 5, 1);
            assert_eq!(CODES.load(Ordering::SeqCst), RANGE_ERROR_CODE);
            assert_eq!(text(&mut slot), b"Zabc", "no clamp: source[5] is spliced in");
            (*core::ptr::addr_of_mut!(CXX_STRING_OPS)).report_error = saved;
        }
    }

    // ---- the members built on the core --------------------------------

    #[test]
    fn append_cstr_appends() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            build(&mut slot, b"foo");
            let slot_ptr: *mut *mut u8 = &mut slot;
            assert_eq!(cxx_string_append_cstr(slot_ptr, b"bar\0".as_ptr()), slot_ptr);
            assert_eq!(text(slot_ptr), b"foobar");
            cxx_string_append_cstr(slot_ptr, b"\0".as_ptr());
            assert_eq!(text(slot_ptr), b"foobar", "appending nothing is a no-op");
        }
    }

    #[test]
    fn replace_cstr_returns_this_and_splices() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            build(&mut slot, b"a__d");
            let slot_ptr: *mut *mut u8 = &mut slot;
            assert_eq!(cxx_string_replace_cstr(slot_ptr, 1, 2, b"bc".as_ptr(), 2), slot_ptr);
            assert_eq!(text(slot_ptr), b"abcd");
        }
    }

    #[test]
    fn assign_cstr_replaces_the_whole_string() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            build(&mut slot, b"old value");
            let slot_ptr: *mut *mut u8 = &mut slot;
            assert_eq!(cxx_string_assign_cstr(slot_ptr, b"new\0".as_ptr()), slot_ptr);
            assert_eq!(text(slot_ptr), b"new");
        }
    }

    /// `s = ""` on a sole owner truncates in place and keeps the buffer;
    /// on a shared string it drops to the singleton instead.
    #[test]
    fn assign_empty_cstr_truncates_or_parks() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            build(&mut slot, b"content");
            let buffer = slot;
            cxx_string_assign_cstr(&mut slot, b"\0".as_ptr());
            assert_eq!(slot, buffer, "sole owner keeps its buffer");
            assert_eq!((*data_rep(slot)).length, 0);
            assert_eq!(slot.read(), 0);
            assert!(freed().is_empty());

            let mut other: *mut u8 = core::ptr::null_mut();
            build(&mut other, b"shared");
            let mut copy: *mut u8 = core::ptr::null_mut();
            cxx_string_copy_ctor(&mut copy, &other);
            cxx_string_assign_cstr(&mut copy, b"\0".as_ptr());
            assert_eq!(copy, empty_rep_data(), "shared drops to the singleton");
            assert_eq!(text(&mut other), b"shared", "the other owner is intact");
            assert_eq!((*data_rep(other)).refcount, 0);
        }
    }

    #[test]
    fn assign_shares_the_source_rep() {
        let _guard = arena();
        unsafe {
            let mut src: *mut u8 = core::ptr::null_mut();
            build(&mut src, b"source");
            let mut dst: *mut u8 = core::ptr::null_mut();
            build(&mut dst, b"dest");
            let dst_rep = data_rep(dst);
            let dst_ptr: *mut *mut u8 = &mut dst;
            assert_eq!(cxx_string_assign(dst_ptr, &src), dst_ptr);
            assert_eq!(dst, src);
            assert_eq!((*data_rep(src)).refcount, 1);
            assert_eq!(freed(), &[dst_rep as *mut u8], "the old rep was released");
        }
    }

    /// Self-assignment survives without a guard on the shared path: the
    /// refcount goes up before it comes down.
    #[test]
    fn assign_to_self_is_safe() {
        let _guard = arena();
        unsafe {
            let mut slot: *mut u8 = core::ptr::null_mut();
            build(&mut slot, b"itself");
            let buffer = slot;
            cxx_string_assign(&mut slot, &slot);
            assert_eq!(slot, buffer);
            assert_eq!((*data_rep(slot)).refcount, 0);
            assert!(freed().is_empty());
            assert_eq!(text(&mut slot), b"itself");
            // ...and on the leaked path the explicit `this == &src` guard
            // takes over.
            (*data_rep(slot)).refcount = -1;
            cxx_string_assign(&mut slot, &slot);
            assert_eq!(slot, buffer);
            assert_eq!(text(&mut slot), b"itself");
            assert!(freed().is_empty());
        }
    }

    /// A leaked source cannot be shared, so assignment copies through the
    /// mutation core.
    #[test]
    fn assign_from_a_leaked_source_copies() {
        let _guard = arena();
        unsafe {
            let mut src: *mut u8 = core::ptr::null_mut();
            build(&mut src, b"leaky");
            (*data_rep(src)).refcount = -1;
            let mut dst: *mut u8 = core::ptr::null_mut();
            build(&mut dst, b"dest");
            cxx_string_assign(&mut dst, &src);
            assert_ne!(dst, src);
            assert_eq!(text(&mut dst), b"leaky");
            assert_eq!((*data_rep(src)).refcount, -1, "source still leaked");
        }
    }

    #[test]
    fn append_substr_appends_a_clamped_slice() {
        let _guard = arena();
        unsafe {
            let mut other: *mut u8 = core::ptr::null_mut();
            build(&mut other, b"0123456789");
            let mut slot: *mut u8 = core::ptr::null_mut();
            build(&mut slot, b"<");
            let slot_ptr: *mut *mut u8 = &mut slot;
            assert_eq!(cxx_string_append_substr(slot_ptr, &other, 3, 4), slot_ptr);
            assert_eq!(text(slot_ptr), b"<3456");
            // `n` past the end of `other` is clamped, not an error.
            cxx_string_append_substr(slot_ptr, &other, 8, 99);
            assert_eq!(text(slot_ptr), b"<345689");
        }
    }

    /// Lexicographic order, checked against Rust's own slice ordering.
    #[test]
    fn less_matches_lexicographic_order() {
        let _guard = arena();
        let samples: [&[u8]; 8] = [b"", b"a", b"ab", b"abc", b"abd", b"b", b"ba", b"\0\0"];
        unsafe {
            for left in samples {
                for right in samples {
                    ARENA_USED = 0;
                    let mut a: *mut u8 = core::ptr::null_mut();
                    let mut b: *mut u8 = core::ptr::null_mut();
                    build(&mut a, left);
                    build(&mut b, right);
                    let want = u32::from(left < right);
                    assert_eq!(
                        cxx_string_less(core::ptr::null(), &a, &b),
                        want,
                        "{left:?} < {right:?}"
                    );
                }
            }
        }
    }

    /// Length-driven, so embedded NULs participate in the ordering
    /// rather than truncating it.
    #[test]
    fn less_orders_past_embedded_nuls() {
        let _guard = arena();
        unsafe {
            let mut a: *mut u8 = core::ptr::null_mut();
            let mut b: *mut u8 = core::ptr::null_mut();
            build(&mut a, b"x\0a");
            build(&mut b, b"x\0b");
            assert_eq!(cxx_string_less(core::ptr::null(), &a, &b), 1);
            assert_eq!(cxx_string_less(core::ptr::null(), &b, &a), 0);
            assert_eq!(cxx_string_less(core::ptr::null(), &a, &a), 0, "strict");
        }
    }

    /// The comparison is C-string-based only on the right: the COW length
    /// participates after the shared byte prefix, including bytes after an
    /// embedded NUL in the COW string.
    #[test]
    fn equals_cstr_requires_equal_bytes_and_lengths() {
        let _guard = arena();
        unsafe {
            for (left, right, expected) in [
                (b"".as_slice(), b"\0".as_slice(), 1),
                (b"ipod".as_slice(), b"ipod\0".as_slice(), 1),
                (b"ipod".as_slice(), b"ipo\0".as_slice(), 0),
                (b"ipo".as_slice(), b"ipod\0".as_slice(), 0),
                (b"ipod".as_slice(), b"ipad\0".as_slice(), 0),
                (b"x\0a".as_slice(), b"x\0".as_slice(), 0),
            ] {
                ARENA_USED = 0;
                let mut string = core::ptr::null_mut();
                build(&mut string, left);
                assert_eq!(
                    cxx_string_equals_cstr(&string, right.as_ptr()),
                    expected,
                    "{left:?} == {right:?}",
                );
            }
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

    #[test]
    fn string_object_copy_cstr_to_buffer_truncates_by_capacity_but_reports_full_length() {
        let mut source = *b"alphabet\0";
        let string = StringObject {
            vtable: core::ptr::null(),
            payload: source.as_mut_ptr(),
        };
        let mut destination = [0xa5; 10];
        let mut length = 4;

        unsafe {
            string_object_copy_cstr_to_buffer(&string, destination.as_mut_ptr(), &mut length);
        }

        assert_eq!(&destination[..4], b"alph");
        assert_eq!(&destination[4..], &[0xa5; 6]);
        assert_eq!(length, 8, "the output is strlen(source), not bytes copied");
    }

    #[test]
    fn string_object_copy_cstr_to_buffer_zero_pads_and_empty_payload_reports_zero() {
        let mut empty = [0u8; 4];
        let string = StringObject {
            vtable: core::ptr::null(),
            payload: empty.as_mut_ptr(),
        };
        let mut destination = [0xa5; 6];
        let mut length = destination.len() as u32;

        unsafe {
            string_object_copy_cstr_to_buffer(&string, destination.as_mut_ptr(), &mut length);
        }

        assert_eq!(destination, [0; 6], "strncpy zero-pads through the input capacity");
        assert_eq!(length, 0);

        let null_payload = StringObject {
            vtable: core::ptr::null(),
            payload: core::ptr::null_mut(),
        };
        let mut untouched = [0xa5; 2];
        let mut zero_capacity = 0;
        unsafe {
            string_object_copy_cstr_to_buffer(
                &null_payload,
                untouched.as_mut_ptr(),
                &mut zero_capacity,
            );
        }
        assert_eq!(untouched, [0xa5; 2], "zero-capacity strncpy writes nothing");
        assert_eq!(zero_capacity, 0, "the accessor's empty fallback has strlen zero");
    }
    /// `strstreambuf_copy_active_buffer` copies the selected target-width buffer
    /// into an owning COW string, including embedded NUL bytes, and maps a zero
    /// capacity to the shared empty representation.
    #[test]
    fn strstreambuf_copy_active_buffer_owns_selected_capacity() {
        use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

        let _arena = arena();
        let Some(fixture) = try_map_u32_slab(hints::STRSTREAMBUF_COPY_ACTIVE_BUFFER, 0x1000) else {
            assert!(note_missing_u32_fixture("cxx/strstreambuf_copy_active_buffer"));
            return;
        };
        unsafe {
            fixture.write_bytes(0, 0x1000);
            let source = fixture.add(0x100);
            source.copy_from_nonoverlapping(b"a\0b".as_ptr(), 3);
            (fixture.add(4) as *mut u32).write(0x04);
            (fixture.add(8) as *mut u32).write(source as usize as u32);
            (fixture.add(0x14) as *mut u32).write(source as usize as u32);
            (fixture.add(0x1c) as *mut u32).write(source.add(3) as usize as u32);

            let mut copied = core::ptr::null_mut();
            strstreambuf_copy_active_buffer(&mut copied, fixture);
            assert_eq!(core::slice::from_raw_parts(copied, 3), b"a\0b");
            assert_eq!((*data_rep(copied)).length, 3);
            cxx_string_release(&mut copied);

            (fixture.add(0x1c) as *mut u32).write(source as usize as u32);
            strstreambuf_copy_active_buffer(&mut copied, fixture);
            assert_eq!(copied, empty_rep_data());
            cxx_string_release(&mut copied);
        }
    }
}

/// cxx_string_vector_entry_copy_ctor — original: `FUN_083d7df4` @
/// 0x083d7df4.
///
/// **40 bytes**, 0x083d7df4..0x083d7e1c, bounded by the next `movs r0, r1`
/// constructor at 0x083d7e1c. There are **four direct, unconditional `bl`**
/// callers (0x08197bf8, 0x083c1610, 0x083e2634, and 0x083e2714) and no
/// predicated `bl` callers, verified from `osos.dec`. The owner is ignored;
/// a NULL destination returns immediately. Otherwise this copy-constructs
/// the COW string at +0x00, then tail-calls the vector copy constructor at
/// 0x083e5b00 for the three-word vector head at +0x04. The tail constructor's
/// return, destination + 4, is this function's result.
///
/// Deliberate deviation: both direct calls use volatile dispatch slots. This
/// preserves the target calls without requiring the unported vector copy
/// constructor to be linked into the payload and permits target-layout
/// (four-byte pointer) host fixtures.
pub const CXX_STRING_VECTOR_ENTRY_COPY_CTOR_ADDRESS: usize = 0x083d_7df4;
const CXX_STRING_VECTOR_ENTRY_VECTOR_COPY_CTOR_ADDRESS: usize = 0x083e_5b00;

pub type CxxStringCopyConstruct =
    unsafe extern "C" fn(*mut *mut u8, *const *mut u8) -> *mut *mut u8;
pub type VectorCopyConstruct = unsafe extern "C" fn(*mut u8, *const u8) -> *mut u8;

#[derive(Clone, Copy)]
pub struct CxxStringVectorEntryCopyCtorOps {
    pub copy_string: CxxStringCopyConstruct,
    pub copy_vector: VectorCopyConstruct,
}

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_vector_copy_construct(
    destination: *mut u8,
    source: *const u8,
) -> *mut u8 {
    let function: VectorCopyConstruct =
        core::mem::transmute(CXX_STRING_VECTOR_ENTRY_VECTOR_COPY_CTOR_ADDRESS);
    function(destination, source)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn host_vector_copy_construct(
    destination: *mut u8,
    _source: *const u8,
) -> *mut u8 {
    destination
}

pub const DEFAULT_CXX_STRING_VECTOR_ENTRY_COPY_CTOR_OPS: CxxStringVectorEntryCopyCtorOps =
    CxxStringVectorEntryCopyCtorOps {
        copy_string: cxx_string_copy_ctor,
        copy_vector: {
            #[cfg(target_os = "none")]
            {
                firmware_vector_copy_construct
            }
            #[cfg(not(target_os = "none"))]
            {
                host_vector_copy_construct
            }
        },
    };

pub static mut CXX_STRING_VECTOR_ENTRY_COPY_CTOR_OPS: CxxStringVectorEntryCopyCtorOps =
    DEFAULT_CXX_STRING_VECTOR_ENTRY_COPY_CTOR_OPS;

#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(
    target_os = "none",
    link_section = ".text.cxx_string_vector_entry_copy_ctor"
)]
#[inline(never)]
pub unsafe extern "C" fn cxx_string_vector_entry_copy_ctor(
    _owner: *mut u8,
    destination: *mut u8,
    source: *const u8,
) -> *mut u8 {
    if destination.is_null() {
        return destination;
    }

    let ops = core::ptr::read_volatile(core::ptr::addr_of!(
        CXX_STRING_VECTOR_ENTRY_COPY_CTOR_OPS
    ));
    (ops.copy_string)(destination.cast(), source.cast());
    (ops.copy_vector)(destination.add(4), source.add(4))
}

#[cfg(test)]
mod cxx_string_vector_entry_copy_ctor_tests {
    use super::*;
    use parking_lot::Mutex;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut STRING_CALL: (*mut u8, *const u8) = (core::ptr::null_mut(), core::ptr::null());
    static mut VECTOR_CALL: (*mut u8, *const u8) = (core::ptr::null_mut(), core::ptr::null());

    unsafe extern "C" fn record_string(destination: *mut *mut u8, source: *const *mut u8) -> *mut *mut u8 {
        STRING_CALL = (destination.cast(), source.cast());
        destination
    }

    unsafe extern "C" fn record_vector(destination: *mut u8, source: *const u8) -> *mut u8 {
        VECTOR_CALL = (destination, source);
        destination
    }

    struct OpsReset;

    impl Drop for OpsReset {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(CXX_STRING_VECTOR_ENTRY_COPY_CTOR_OPS)
                    .write_volatile(DEFAULT_CXX_STRING_VECTOR_ENTRY_COPY_CTOR_OPS);
            }
        }
    }

    #[test]
    fn null_destination_returns_without_reading_source_or_dispatching() {
        let _lock = OPS_LOCK.lock();
        let _reset = OpsReset;
        unsafe {
            STRING_CALL = (core::ptr::null_mut(), core::ptr::null());
            VECTOR_CALL = (core::ptr::null_mut(), core::ptr::null());
            core::ptr::addr_of_mut!(CXX_STRING_VECTOR_ENTRY_COPY_CTOR_OPS).write_volatile(
                CxxStringVectorEntryCopyCtorOps {
                    copy_string: record_string,
                    copy_vector: record_vector,
                },
            );

            assert!(cxx_string_vector_entry_copy_ctor(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null(),
            )
            .is_null());
            assert!(STRING_CALL.0.is_null());
            assert!(VECTOR_CALL.0.is_null());
        }
    }

    #[test]
    fn copies_string_then_vector_at_target_word_offsets() {
        let _lock = OPS_LOCK.lock();
        let _reset = OpsReset;
        let mut destination = [0u8; 16];
        let source = [0u8; 16];
        unsafe {
            core::ptr::addr_of_mut!(CXX_STRING_VECTOR_ENTRY_COPY_CTOR_OPS).write_volatile(
                CxxStringVectorEntryCopyCtorOps {
                    copy_string: record_string,
                    copy_vector: record_vector,
                },
            );

            let returned = cxx_string_vector_entry_copy_ctor(
                0xfeed_faceusize as *mut u8,
                destination.as_mut_ptr(),
                source.as_ptr(),
            );

            assert_eq!(STRING_CALL, (destination.as_mut_ptr(), source.as_ptr()));
            assert_eq!(
                VECTOR_CALL,
                (destination.as_mut_ptr().add(4), source.as_ptr().add(4))
            );
            assert_eq!(returned, destination.as_mut_ptr().add(4));
        }
    }
}
