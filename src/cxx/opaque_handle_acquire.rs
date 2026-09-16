//! Acquisition of the opaque virtual handle released by
//! `opaque_handle_release_if_valid`.
//!
//! `opaque_handle_acquire` — retailOS `FUN_0805a634` at **0x0805a634**
//! (180 bytes). Raw osos.dec establishes the exact extent: 45 ARM words
//! from `stmdb sp!,{r1-r7,lr}` at 0x0805a634 through `ldmia
//! sp!,{r1-r7,pc}` at 0x0805a6e4; the next independently linked
//! function begins at 0x0805a6e8 (`mov r12,r1; cmn r0,#1`).
//! Decoding every immediate ARM B/BL word in osos.dec finds exactly
//! five inbound calls, all unconditional plain `bl` at 0x0805b798,
//! 0x0806e538, 0x080a7504, 0x080aa648, and 0x080bec90 — no predicated
//! BL forms, no tail branches, and no aligned raw data-word references.
//!
//! Reference `decomp/osos.asm` @ 0x0805a634-0x0805a6e4:
//!
//! ```text
//! stmdb sp!,{r1-r7,lr} ; movs r4,r0 ; mov r6,r3 ; cmpne r6,#0
//! beq  fail                            @ request/out NULL -> -50
//! cmp  r2,#1 ; moveq r5,#1 ; beq alloc @ mode 1: exclusive flag = 1
//! cmp  r2,#2 ; cmpne r2,#3 ; bne fail  @ modes 2/3: flag = 0
//! mov  r5,#0
//! alloc: mov r0,#0x54 ; bl 0x082aadd4  @ operator_new — ported, direct
//! mov  r3,#0 ; mov r2,#1 ; mov r1,#0x400 ; stmia sp,{r1,r2,r3}
//! ldrh r1,[r4] ; mov r2,r5
//! mov  r3,r1,lsl #24 ; mov r3,r3,asr #24  @ sext8 of u16 low byte
//! add  r1,r4,#2 ; bl 0x08278dc4       @ silver_controller_.._construct
//! ldr  r4,[r0,#0x1c]                  @ status word
//! cmp  r5,#0 ; beq shared
//!   cmp r4,#0 ; bne fail_obj          @ mode 1 accepts only 0
//! shared: cmp r4,#0 ; cmpne r4,#7 ; bne fail_obj @ modes 2/3: 0 or 7
//! str  r0,[r6] ; mov r0,#0 ; pop      @ success: *out = object
//! fail_obj: cmp r0,#0 ; ldrne r1,[r0] ; ldrne r1,[r1,#4] ; blxne r1
//! mov  r0,r4 ; bl 0x0809da3c ; pop    @ map_status_code(status)
//! fail: mvn r0,#0x31 ; pop            @ -50
//! ```
//!
//! Algorithm: validates both pointers and the mode, allocates the
//! 0x54-byte handle with tag-2 `operator new` @ 0x082aadd4, then
//! constructs it in place from the request record `{u16 hint; char
//! path[]}`: the path C string at +0x02, the mode-derived flag, the
//! sign-extended low byte of the leading u16 as `base_hint`, and the
//! fixed trailing triple `(0x400, 1, 0)`. The constructed object's
//! status word at +0x1c decides ownership: mode 1 accepts only status
//! 0, modes 2 and 3 accept status 0 or 7. On acceptance the object is
//! stored through the out pointer and zero returned. Otherwise the
//! object is released through its vtable's +0x04 slot (NULL-gated,
//! matching the sibling `opaque_handle_release_if_valid`) and the
//! status is returned through `map_status_code` @ 0x0809da3c. The
//! second argument (r1) is spilled by the prologue but never read —
//! kept in the signature for ABI fidelity. The status word is read
//! unconditionally: a NULL allocation faults exactly as retailOS does.
//!
//! The five callers pair the result with
//! `opaque_handle_release_if_valid` @ 0x0805a594 and the request
//! producers around 0x0805a5b4, so this is the acquire half of that
//! opaque-handle protocol; the request's u16 hint semantics remain
//! unrecovered and are deliberately not invented.
//!
//! Deliberate deviations:
//!
//! - The constructor @ 0x08278dc4 is ported
//!   ([`silver_controller_transition_addon_construct_from_cstr`]) but
//!   rides the [`OPAQUE_HANDLE_CONSTRUCT`] dispatch slot — whose wired
//!   default IS the port — because its own host fixtures demand
//!   incompatible alignments, so host tests install a recording mock
//!   (the `TRANSITION_ADDON_CONSTRUCT_OPS` precedent). `operator new`
//!   and `map_status_code` are ported and called directly.
//! - The target stores four-byte vtable words; host fixtures use the
//!   sibling module's typed native-width callback slots.

use core::ptr::{addr_of, read_volatile, write_volatile};

use crate::cxx::opaque_handle_release::OpaqueHandle;
use crate::cxx::transition_addon::silver_controller_transition_addon_construct_from_cstr;
use crate::heap::veneers::operator_new;
use crate::util::status_code_map::map_status_code;

/// Allocation size of the handle object (`mov r0, #0x54`).
pub const OPAQUE_HANDLE_SIZE: usize = 0x54;

/// Offset of the constructed object's status word (`ldr r4,[r0,#0x1c]`).
pub const OPAQUE_HANDLE_STATUS_OFFSET: usize = 0x1c;

/// Argument-rejection status (`mvn r0,#0x31` — bitwise NOT, i.e. -50).
const STATUS_INVALID_ARGUMENT: i32 = !0x31;

/// The in-place constructor the original calls at 0x08278dc4.
pub type OpaqueHandleConstruct = unsafe extern "C" fn(
    this: *mut u8,
    source: *const u8,
    flag: u32,
    base_hint: u32,
    quantum_arg: u32,
    scale_arg: u32,
    context: u32,
) -> *mut u8;

/// The active constructor (original: the direct `bl 0x08278dc4`). The
/// wired default is the real port; host tests install a recording mock
/// because the port's own fixture alignment constraints prevent it from
/// running inside this wrapper on 64-bit hosts.
pub static mut OPAQUE_HANDLE_CONSTRUCT: OpaqueHandleConstruct =
    silver_controller_transition_addon_construct_from_cstr;

/// `opaque_handle_acquire` — original: `FUN_0805a634` @ 0x0805a634
/// (180 bytes; five verified plain `bl` call sites, none predicated).
///
/// Acquires the opaque handle described by `request` (a leading u16
/// hint followed by a NUL-terminated path) into `out_handle`. `mode`
/// 1 constructs with flag 1 and accepts only status 0; modes 2 and 3
/// construct with flag 0 and accept status 0 or 7; any other mode, a
/// NULL `request`, or a NULL `out_handle` returns -50 without
/// allocating. Rejected constructions are released through vtable slot
/// +0x04 and the raw status is returned via `map_status_code`.
///
/// # Safety
/// `request` must point to a readable u16 followed by a readable C
/// string, and `out_handle` to a writable word. The constructed object
/// must expose a readable status word at +0x1c and, on the failure
/// path, a callable release entry at vtable +0x04.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_handle_acquire(
    request: *const u8,
    _reserved: u32,
    mode: u32,
    out_handle: *mut *mut u8,
) -> i32 {
    if request.is_null() || out_handle.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    let flag = match mode {
        1 => 1,
        2 | 3 => 0,
        _ => return STATUS_INVALID_ARGUMENT,
    };

    let block = unsafe { operator_new(OPAQUE_HANDLE_SIZE) };
    let hint = unsafe { read_volatile(request as *const u16) };
    let base_hint = (hint as u8) as i8 as i32 as u32;
    let construct = unsafe { read_volatile(addr_of!(OPAQUE_HANDLE_CONSTRUCT)) };
    let object = unsafe {
        construct(block, request.add(2), flag, base_hint, 0x400, 1, 0)
    };

    // Unconditional like the original's `ldr r4,[r0,#0x1c]`: a NULL
    // allocation faults here exactly as it does on retailOS.
    let status = unsafe { read_volatile(object.add(OPAQUE_HANDLE_STATUS_OFFSET) as *const u32) };
    let accepted = if flag != 0 { status == 0 } else { status == 0 || status == 7 };
    if accepted {
        unsafe { write_volatile(out_handle, object) };
        return 0;
    }

    if !object.is_null() {
        let handle = object as *mut OpaqueHandle;
        let vtable = unsafe { read_volatile(addr_of!((*handle).vtable)) };
        let release = unsafe { read_volatile(addr_of!((*vtable).release)) };
        unsafe { release(handle) };
    }
    map_status_code(status as i32)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ptr;

    use parking_lot::{Mutex, MutexGuard};
    use std::vec::Vec;

    use super::{
        opaque_handle_acquire, OPAQUE_HANDLE_CONSTRUCT,
        OPAQUE_HANDLE_SIZE, OPAQUE_HANDLE_STATUS_OFFSET,
    };
    use crate::cxx::opaque_handle_release::{OpaqueHandle, OpaqueHandleVtable};
    use crate::cxx::transition_addon::silver_controller_transition_addon_construct_from_cstr;
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor, DEFAULT_HEAP};
    use crate::heap::veneers::{DEFAULT_HEAP_OPS, HEAP_OPS};

    /// Serializes every test that swaps the globals below (the
    /// drivers/surface_new.rs pattern).
    static ACQUIRE_LOCK: Mutex<()> = Mutex::new(());

    /// The block the stub allocator hands out; word-aligned like a real
    /// `operator new` result.
    #[repr(align(8))]
    struct Arena([u8; OPAQUE_HANDLE_SIZE]);
    static mut ARENA: Arena = Arena([0xa5; OPAQUE_HANDLE_SIZE]);

    #[derive(Debug, Eq, PartialEq)]
    struct ConstructCall {
        this: usize,
        source: usize,
        flag: u32,
        base_hint: u32,
        quantum_arg: u32,
        scale_arg: u32,
        context: u32,
    }

    static mut ALLOC_SIZES: Vec<usize> = Vec::new();
    static mut CONSTRUCT_CALLS: Vec<ConstructCall> = Vec::new();
    static mut RELEASE_CALLS: Vec<usize> = Vec::new();
    static mut CTOR_STATUS: u32 = 0;
    static mut CTOR_INSTALL_VTABLE: bool = true;

    fn arena() -> *mut u8 {
        ptr::addr_of_mut!(ARENA) as *mut u8
    }

    unsafe extern "C" fn stub_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        (*ptr::addr_of_mut!(ALLOC_SIZES)).push(size);
        arena()
    }

    unsafe extern "C" fn stub_create(
        _desc: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        unreachable!("DEFAULT_HEAP is pre-seeded, so the lazy init must not run");
    }

    unsafe extern "C" fn recording_release(handle: *mut OpaqueHandle) -> usize {
        unsafe { (*ptr::addr_of_mut!(RELEASE_CALLS)).push(handle as usize) };
        0xdead_beef
    }

    static RECORDING_VTABLE: OpaqueHandleVtable = OpaqueHandleVtable {
        unresolved_slot_00: 0,
        release: recording_release,
    };

    /// Records the arguments, plants the configured status word at
    /// +0x1c and a recording vtable at +0x00, and returns `this` —
    /// exactly the observable contract of the real constructor.
    unsafe extern "C" fn recording_construct(
        this: *mut u8,
        source: *const u8,
        flag: u32,
        base_hint: u32,
        quantum_arg: u32,
        scale_arg: u32,
        context: u32,
    ) -> *mut u8 {
        unsafe {
            (*ptr::addr_of_mut!(CONSTRUCT_CALLS)).push(ConstructCall {
                this: this as usize,
                source: source as usize,
                flag,
                base_hint,
                quantum_arg,
                scale_arg,
                context,
            });
            if ptr::read_volatile(ptr::addr_of!(CTOR_INSTALL_VTABLE)) {
                (this as *mut *const OpaqueHandleVtable)
                    .write_unaligned(ptr::addr_of!(RECORDING_VTABLE));
            }
            (this.add(OPAQUE_HANDLE_STATUS_OFFSET) as *mut u32)
                .write_unaligned(ptr::read_volatile(ptr::addr_of!(CTOR_STATUS)));
        }
        this
    }

    /// A non-NULL dummy heap handle so `lazy_init_default_heap` is a
    /// no-op and `stub_create` is never reached.
    static mut FAKE_HEAP: usize = 0;

    fn mock(status: u32) -> MutexGuard<'static, ()> {
        let guard = ACQUIRE_LOCK.lock();
        unsafe {
            let mut ops = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            ops.alloc = stub_alloc;
            ops.create = stub_create;
            HEAP_OPS = ops;
            DEFAULT_HEAP = ptr::addr_of_mut!(FAKE_HEAP) as *mut HeapDescriptorDescriptor;
            OPAQUE_HANDLE_CONSTRUCT = recording_construct;
            CTOR_STATUS = status;
            CTOR_INSTALL_VTABLE = true;
            (*ptr::addr_of_mut!(ALLOC_SIZES)).clear();
            (*ptr::addr_of_mut!(CONSTRUCT_CALLS)).clear();
            (*ptr::addr_of_mut!(RELEASE_CALLS)).clear();
        }
        guard
    }

    /// Restores every wired default. Takes the guard by value so it
    /// cannot be re-locked while still held (the seek_core.rs rule).
    fn restore(guard: MutexGuard<'static, ()>) {
        unsafe {
            HEAP_OPS = DEFAULT_HEAP_OPS;
            DEFAULT_HEAP = ptr::null_mut();
            OPAQUE_HANDLE_CONSTRUCT = silver_controller_transition_addon_construct_from_cstr;
        }
        drop(guard);
    }

    /// A request record: leading u16 hint 0x1234, then the path.
    fn request() -> [u8; 10] {
        let mut r = [0u8; 10];
        r[0..2].copy_from_slice(&0x1234u16.to_le_bytes());
        r[2..9].copy_from_slice(b"::disk\0");
        r
    }

    #[test]
    fn mode_1_success_stores_object_and_returns_zero() {
        let guard = mock(0);
        let request = request();
        let mut out: *mut u8 = ptr::null_mut();
        unsafe {
            let result = opaque_handle_acquire(request.as_ptr(), 0xdead, 1, ptr::addr_of_mut!(out));
            assert_eq!(result, 0);
            assert_eq!(out, arena());
            assert_eq!(*ptr::addr_of!(ALLOC_SIZES), std::vec![OPAQUE_HANDLE_SIZE]);
            assert_eq!(
                *ptr::addr_of!(CONSTRUCT_CALLS),
                std::vec![ConstructCall {
                    this: arena() as usize,
                    source: request.as_ptr().add(2) as usize,
                    flag: 1,
                    base_hint: 0x34,
                    quantum_arg: 0x400,
                    scale_arg: 1,
                    context: 0,
                }],
                "mode 1: flag 1, fixed (0x400, 1, 0) triple, path at +2"
            );
            assert!((*ptr::addr_of!(RELEASE_CALLS)).is_empty());
        }
        restore(guard);
    }

    #[test]
    fn modes_2_and_3_accept_status_0_and_7_with_flag_0() {
        for (mode, status) in [(2, 0), (2, 7), (3, 0), (3, 7)] {
            let guard = mock(status);
            let request = request();
            let mut out: *mut u8 = ptr::null_mut();
            unsafe {
                let result = opaque_handle_acquire(request.as_ptr(), 0, mode, ptr::addr_of_mut!(out));
                assert_eq!(result, 0, "mode {mode} status {status} must succeed");
                assert_eq!(out, arena());
                assert_eq!((&*ptr::addr_of!(CONSTRUCT_CALLS))[0].flag, 0);
                assert!((*ptr::addr_of!(RELEASE_CALLS)).is_empty());
            }
            restore(guard);
        }
    }

    #[test]
    fn mode_1_rejects_status_7_releases_and_maps() {
        let guard = mock(7);
        let request = request();
        let mut out: *mut u8 = 1usize as *mut u8;
        unsafe {
            let result = opaque_handle_acquire(request.as_ptr(), 0, 1, ptr::addr_of_mut!(out));
            assert_eq!(result, -42, "map_status_code(7)");
            assert_eq!(out, 1usize as *mut u8, "the out pointer is untouched on failure");
            assert_eq!(
                *ptr::addr_of!(RELEASE_CALLS),
                std::vec![arena() as usize],
                "the rejected object is released through vtable slot +0x04"
            );
        }
        restore(guard);
    }

    #[test]
    fn unmapped_status_passes_through_map_status_code() {
        let guard = mock(9);
        let request = request();
        let mut out: *mut u8 = ptr::null_mut();
        unsafe {
            let result = opaque_handle_acquire(request.as_ptr(), 0, 2, ptr::addr_of_mut!(out));
            assert_eq!(result, 9, "map_status_code preserves unmapped inputs");
            assert_eq!((*ptr::addr_of!(RELEASE_CALLS)).len(), 1);
        }
        restore(guard);
    }

    #[test]
    fn base_hint_is_the_sign_extended_low_byte() {
        let guard = mock(0);
        let mut request = request();
        request[0] = 0xff;
        request[1] = 0x7f; // the high byte is ignored entirely
        let mut out: *mut u8 = ptr::null_mut();
        unsafe {
            opaque_handle_acquire(request.as_ptr(), 0, 2, ptr::addr_of_mut!(out));
            assert_eq!(
                (&*ptr::addr_of!(CONSTRUCT_CALLS))[0].base_hint,
                -1i32 as u32,
                "lsl #24/asr #24 sign-extends only the low byte"
            );
        }
        restore(guard);
    }

    #[test]
    fn null_pointers_and_bad_modes_fail_without_allocating() {
        let guard = mock(0);
        let request = request();
        let mut out: *mut u8 = ptr::null_mut();
        unsafe {
            assert_eq!(opaque_handle_acquire(ptr::null(), 0, 1, ptr::addr_of_mut!(out)), -50);
            assert_eq!(opaque_handle_acquire(request.as_ptr(), 0, 1, ptr::null_mut()), -50);
            for mode in [0, 4, 0xffff_ffff] {
                assert_eq!(
                    opaque_handle_acquire(request.as_ptr(), 0, mode, ptr::addr_of_mut!(out)),
                    -50,
                    "mode {mode} is rejected by the cmp/cmpne chain"
                );
            }
            assert!((*ptr::addr_of!(ALLOC_SIZES)).is_empty(), "no allocation on rejection");
            assert!((*ptr::addr_of!(CONSTRUCT_CALLS)).is_empty());
        }
        restore(guard);
    }
}
