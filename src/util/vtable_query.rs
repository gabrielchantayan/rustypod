//! vtable_query_4c_kind4 — original: `FUN_0811d46c` @ 0x0811d46c (12
//! bytes; 29 `bl` call sites, all in the query-interface family around
//! 0x0810aa58 / 0x0811afb0 / 0x081bc620 / 0x081d0e18 / ...).
//!
//! A three-instruction thunk:
//!
//! ```text
//! mov r2, r1        @ arg = out
//! mov r1, #0x4      @ kind = 4
//! b   0x0811d7b0    @ tail: vtable slot +0x4c dispatch
//! ```
//!
//! It binds the constant 4 as the middle (kind) argument of the generic
//! dispatcher `FUN_0811d7b0` @ 0x0811d7b0 (28 bytes, 16 `bl` call
//! sites, NOT ported — a neighbour with its own entry), which is:
//!
//! ```text
//! stmdb sp!, {r3, lr}     @ spill the caller's 4th argument
//! ldr   r0, [r0, #0x0]    @ object = *handle
//! ldr   r3, [r0, #0x0]    @ vtable  = *object
//! ldr   r12, [r3, #0x4c]  @ method  = vtable->slot_4c
//! mov   r3, sp            @ extra = &spilled_r3
//! blx   r12               @ method(object, kind, arg, extra)
//! ldmia sp!, {r12, pc}    @ return the method's r0
//! ```
//!
//! So `handle` is a pointer to the object pointer (every call site
//! forms it with `add r0, rX, #off` or `add r0, sp, #off`), the call
//! sites pass a pointer to a local out-word in r1 (`add r1, sp, #4`),
//! and the vtable method at slot +0x4c is invoked as
//! `method(object, 4, out, &forwarded)` where `forwarded` is the word
//! the caller happened to have in r3 (no call site sets it deliberately
//! — the thunk neither reads nor writes it; the dispatcher spills it
//! verbatim and hands the method a pointer to the spilled word). The
//! method's return value propagates back in r0; every call site treats
//! it as an error code (`movs rN, r0; bne fail`, 0 = success) and then
//! inspects the out word — masking off a 0xc0 tag byte (`bic r0, r1,
//! #0xff000000`, the same tag family the ported `is_tagged_c0` @
//! 0x0811d208 tests) or testing flag bits (`tst #0x39` / `#0x43` /
//! `#0x16`). Kind 4 is therefore a property/attribute query answered
//! through the object's vtable; the object's concrete class is not
//! identified and the function is ported on observable behavior. The
//! neighbour @ 0x0811d7fc is the identical dispatcher shape on vtable
//! slot +0x50.
//!
//! Deviations: the tail target `FUN_0811d7b0` is unported firmware and
//! stays unported (not this function's entry), so the whole dispatch
//! sits behind the [`VTABLE_SLOT_4C_DISPATCH`] slot (the
//! util/inner_state.rs `INNER_MATERIALIZE_COUNT` pattern). The default
//! stub models the dispatcher body exactly — the double dereference,
//! the slot +0x4c load and the indirect call — so on firmware the
//! behavior is identical; host tests install a recording mock. The
//! dispatcher's `stmdb sp!,{r3}` spill is modeled by passing a pointer
//! to a stack local holding the thunk's third live argument. The slot
//! +0x4c method-pointer load uses `read_unaligned` so the layout stays
//! byte-exact on a 64-bit test host (0x4c is 4-aligned but not
//! 8-aligned).

/// Byte offset of the queried method inside the object's vtable.
const VTABLE_SLOT_4C: usize = 0x4c;

/// The kind argument this thunk always binds.
const QUERY_KIND_4: u32 = 4;

/// The vtable method signature: `method(object, kind, arg, extra)`,
/// returning an error code (0 = success).
type VtableQueryMethod =
    unsafe extern "C" fn(object: *mut u8, kind: u32, arg: usize, extra: *const usize) -> u32;

/// Default [`VTABLE_SLOT_4C_DISPATCH`] stub: the exact body of the
/// unported dispatcher `FUN_0811d7b0` @ 0x0811d7b0 — dereference the
/// handle to the object, the object to its vtable, load the method
/// pointer from vtable slot +0x4c and call it (see the module header).
unsafe extern "C" fn vtable_slot_4c_dispatch(
    handle: *mut *mut u8,
    kind: u32,
    arg: usize,
    extra: *const usize,
) -> u32 {
    let object = handle.read();
    let vtable = (object as *const *const u8).read();
    let method =
        (vtable.add(VTABLE_SLOT_4C) as *const VtableQueryMethod).read_unaligned();
    method(object, kind, arg, extra)
}

/// Indirect dispatch for the unported vtable slot +0x4c dispatcher
/// `FUN_0811d7b0` @ 0x0811d7b0 (the util/inner_state.rs
/// `INNER_MATERIALIZE_COUNT` pattern). The default stub is the
/// dispatcher's exact body; host tests install a recording mock via
/// `core::ptr::addr_of_mut!`.
pub static mut VTABLE_SLOT_4C_DISPATCH: unsafe extern "C" fn(
    handle: *mut *mut u8,
    kind: u32,
    arg: usize,
    extra: *const usize,
) -> u32 = vtable_slot_4c_dispatch;

/// vtable_query_4c_kind4 — original: `FUN_0811d46c` @ 0x0811d46c (12
/// bytes).
///
/// Queries kind 4 through the object's vtable slot +0x4c: the method is
/// invoked as `method(*handle, 4, out, &forwarded)` and its error code
/// (0 = success) is returned. `out` points at the caller's result word.
/// `_unused` is the caller's r2 — dead on entry (the first instruction
/// overwrites it with r1); `forwarded` is the caller's r3, which the
/// tail target spills and exposes to the method by pointer (no call
/// site sets it deliberately; forwarded verbatim for faithfulness).
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn vtable_query_4c_kind4(
    handle: *mut *mut u8,
    out: *mut u32,
    _unused: usize,
    forwarded: usize,
) -> u32 {
    // Volatile slot read — the inner_state.rs rationale: the slot is
    // meant to be swapped at runtime, and a build in which nothing
    // swaps it must not constant-fold the default in.
    let dispatch = core::ptr::read_volatile(core::ptr::addr_of!(VTABLE_SLOT_4C_DISPATCH));
    // The tail target's `stmdb sp!,{r3}`: the caller's r3 is spilled
    // and the method receives a pointer to the spilled word.
    let forwarded_slot = forwarded;
    dispatch(
        handle,
        QUERY_KIND_4,
        out as usize,
        core::ptr::addr_of!(forwarded_slot),
    )
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Mutex;

    const SENTINEL: u8 = 0xa5;
    const MOCK_OK: u32 = 0;
    const MOCK_ERR: u32 = 0x1bad_b002;

    /// Serializes the tests that swap `VTABLE_SLOT_4C_DISPATCH` (the
    /// inner_state.rs `SLOT_TEST_LOCK` precedent).
    static SLOT_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Restores the default stub on drop, even when a test panics.
    struct SlotGuard;
    impl Drop for SlotGuard {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(VTABLE_SLOT_4C_DISPATCH)
                    .write_volatile(vtable_slot_4c_dispatch)
            };
        }
    }

    // ---- recording mock for the dispatch slot -------------------------

    static mut MOCK_HANDLE: *mut *mut u8 = core::ptr::null_mut();
    static mut MOCK_KIND: u32 = 0;
    static mut MOCK_ARG: usize = 0;
    static mut MOCK_EXTRA_WORD: usize = 0;
    static mut MOCK_CALLS: u32 = 0;
    static mut MOCK_RESULT: u32 = MOCK_OK;

    unsafe extern "C" fn recording_dispatch(
        handle: *mut *mut u8,
        kind: u32,
        arg: usize,
        extra: *const usize,
    ) -> u32 {
        MOCK_HANDLE = handle;
        MOCK_KIND = kind;
        MOCK_ARG = arg;
        MOCK_EXTRA_WORD = extra.read();
        MOCK_CALLS += 1;
        MOCK_RESULT
    }

    unsafe fn reset_mock() {
        MOCK_HANDLE = core::ptr::null_mut();
        MOCK_KIND = 0;
        MOCK_ARG = 0;
        MOCK_EXTRA_WORD = 0;
        MOCK_CALLS = 0;
        MOCK_RESULT = MOCK_OK;
        core::ptr::addr_of_mut!(VTABLE_SLOT_4C_DISPATCH)
            .write_volatile(recording_dispatch);
    }

    /// A stand-in handle: one pointer-sized slot pointing at a stand-in
    /// object, both sentinel-filled.
    struct Fixture {
        handle: usize,
        object: [u8; 8],
    }

    impl Fixture {
        fn new() -> Self {
            let mut fixture = Fixture { handle: 0, object: [SENTINEL; 8] };
            fixture.handle = fixture.object.as_mut_ptr() as usize;
            fixture
        }
        fn handle_ptr(&mut self) -> *mut *mut u8 {
            core::ptr::addr_of_mut!(self.handle) as *mut *mut u8
        }
    }

    #[test]
    fn binds_kind_4_and_forwards_every_argument() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0xdead_beef;
        unsafe {
            reset_mock();
            MOCK_RESULT = MOCK_ERR;

            let result = vtable_query_4c_kind4(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                0x1111_2222,
                0x3333_4444,
            );

            assert_eq!(result, MOCK_ERR, "the method's error code propagates");
            assert_eq!(MOCK_CALLS, 1, "exactly one dispatch");
            assert_eq!(MOCK_HANDLE, fixture.handle_ptr(), "handle forwarded verbatim");
            assert_eq!(MOCK_KIND, QUERY_KIND_4, "the constant 4 is bound as the kind");
            assert_eq!(
                MOCK_ARG,
                core::ptr::addr_of_mut!(out) as usize,
                "r1 becomes the arg (mov r2, r1)"
            );
            assert_eq!(
                MOCK_EXTRA_WORD, 0x3333_4444,
                "the method sees the caller's r3 through the spilled-word pointer"
            );
        }
    }

    #[test]
    fn the_third_argument_is_dead() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            reset_mock();
            let first = vtable_query_4c_kind4(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                0,
                0xaaaa,
            );
            let seen_arg = MOCK_ARG;
            let seen_extra = MOCK_EXTRA_WORD;
            let second = vtable_query_4c_kind4(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                usize::MAX,
                0xaaaa,
            );
            assert_eq!(first, second);
            assert_eq!(MOCK_CALLS, 2);
            assert_eq!(MOCK_ARG, seen_arg, "r2 never reaches the dispatch");
            assert_eq!(MOCK_EXTRA_WORD, seen_extra);
        }
    }

    #[test]
    fn success_result_is_zero() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard;
        let mut fixture = Fixture::new();
        let mut out: u32 = 0;
        unsafe {
            reset_mock();
            let result = vtable_query_4c_kind4(
                fixture.handle_ptr(),
                core::ptr::addr_of_mut!(out),
                0,
                0,
            );
            assert_eq!(result, 0, "the call sites' success convention");
        }
    }

    // ---- default stub: the modeled vtable dispatch ---------------------

    static mut METHOD_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut METHOD_KIND: u32 = 0;
    static mut METHOD_ARG: usize = 0;
    static mut METHOD_EXTRA_WORD: usize = 0;
    static mut METHOD_CALLS: u32 = 0;

    /// A host stand-in for a firmware vtable method: answers the kind-4
    /// query by writing a 0xc0-tagged attribute word through the out
    /// pointer, like the firmware methods whose results the call sites
    /// mask and bit-test.
    unsafe extern "C" fn fake_vtable_method(
        object: *mut u8,
        kind: u32,
        arg: usize,
        extra: *const usize,
    ) -> u32 {
        METHOD_OBJECT = object;
        METHOD_KIND = kind;
        METHOD_ARG = arg;
        METHOD_EXTRA_WORD = extra.read();
        METHOD_CALLS += 1;
        (arg as *mut u32).write(0xc000_003a);
        0
    }

    /// Byte length of a vtable that reaches slot +0x4c, plus one word.
    const VTABLE_LEN: usize = VTABLE_SLOT_4C + core::mem::size_of::<usize>();

    #[test]
    fn default_stub_dispatches_through_vtable_slot_4c() {
        let _lock = SLOT_TEST_LOCK.lock().unwrap();
        let _restore = SlotGuard; // slot left at the default stub
        let mut vtable = [SENTINEL; VTABLE_LEN];
        let mut object = [SENTINEL; 8];
        let mut out: u32 = 0;
        unsafe {
            // Plant the vtable pointer at object+0 and the method
            // pointer at vtable+0x4c (byte-exact, hence unaligned).
            (object.as_mut_ptr() as *mut *const u8).write(vtable.as_ptr());
            (vtable.as_mut_ptr().add(VTABLE_SLOT_4C) as *mut VtableQueryMethod)
                .write_unaligned(fake_vtable_method);
            let mut handle = object.as_mut_ptr();
            METHOD_CALLS = 0;

            let result = vtable_query_4c_kind4(
                core::ptr::addr_of_mut!(handle),
                core::ptr::addr_of_mut!(out),
                0x7777,
                0x5555_6666,
            );

            assert_eq!(result, 0);
            assert_eq!(METHOD_CALLS, 1, "one indirect call through slot +0x4c");
            assert_eq!(
                METHOD_OBJECT,
                object.as_mut_ptr(),
                "the method receives *handle, not the handle"
            );
            assert_eq!(METHOD_KIND, QUERY_KIND_4);
            assert_eq!(METHOD_ARG, core::ptr::addr_of_mut!(out) as usize);
            assert_eq!(METHOD_EXTRA_WORD, 0x5555_6666);
            assert_eq!(out, 0xc000_003a, "the out-parameter round trip");
        }
    }
}
