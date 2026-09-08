//! Acquire a context child handle — retailOS `FUN_08371418` at
//! `0x08371418` (96 bytes).
//!
//! Raw ARM establishes the exact extent: its `pop {r3-r7,pc}` is at
//! `0x08371474`, followed by the separate `push {r3-r11,lr}` prologue at
//! `0x08371478`. Decoding every ARM B/BL word in `osos.dec` finds 18 direct
//! call sites, all unconditional plain `bl`; no predicated call reaches this
//! function. It is statically bound (no data word contains its address).
//!
//! The owner contains a context pointer at +0x00. The function forwards that
//! context, `child_id`, output slot, and opaque `prepare_mode` to the still
//! retailOS-owned lease wrapper at `0x0837dc38`. On a zero status it maps the
//! returned child record to its +0x38 handle, then initializes that handle's
//! owner (+0x40), payload (+0x44), record (+0x48), child ID (+0x4c), and byte
//! +0x08 (100 only for child ID 1). Any nonzero wrapper status passes through
//! without mapping or writing the handle.
//!
//! Deliberate deviations: `0x0837dc38` and its context-child resolver remain
//! unported, so target builds call it at its retailOS load address. Host tests
//! replace only that external boundary with a recording callback; the wrapper
//! and all handle writes remain this port's real behavior.

/// Width of a target pointer field: four bytes on ARMv5TE, pointer-sized in
/// host fixtures so adjacent target pointer fields cannot overlap.
const WORD: usize = core::mem::size_of::<*mut u8>();

const HANDLE_PRIORITY: usize = 0x08;
const HANDLE_OWNER: usize = 0x40;
const HANDLE_PAYLOAD: usize = 0x44;
const HANDLE_RECORD: usize = 0x48;
const HANDLE_CHILD_ID: usize = 0x4c;
#[cfg(test)]
const RECORD_CONTEXT: usize = 0x00;
const RECORD_PAYLOAD: usize = 0x34;
const RECORD_HANDLE: usize = 0x38;

type ContextChildPrepare = unsafe extern "C" fn(*mut u8, u32, *mut *mut u8, u32) -> u32;

#[inline(always)]
const fn pointer_offset(target_offset: usize) -> usize {
    target_offset / 4 * WORD
}

#[inline(always)]
unsafe fn read_pointer(base: *mut u8, target_offset: usize) -> *mut u8 {
    (base.add(pointer_offset(target_offset)) as *const *mut u8).read_volatile()
}

#[inline(always)]
unsafe fn write_pointer(base: *mut u8, target_offset: usize, value: *mut u8) {
    (base.add(pointer_offset(target_offset)) as *mut *mut u8).write_volatile(value);
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn prepare_context_child(
    context: *mut u8,
    child_id: u32,
    out_record: *mut *mut u8,
    prepare_mode: u32,
) -> u32 {
    let prepare: ContextChildPrepare = core::mem::transmute(0x0837_dc38usize);
    prepare(context, child_id, out_record, prepare_mode)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct ContextChildHostOps {
    prepare: ContextChildPrepare,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_context_child(
    _context: *mut u8,
    _child_id: u32,
    _out_record: *mut *mut u8,
    _prepare_mode: u32,
) -> u32 {
    11
}

#[cfg(not(target_os = "none"))]
const DEFAULT_CONTEXT_CHILD_HOST_OPS: ContextChildHostOps = ContextChildHostOps {
    prepare: unavailable_context_child,
};

#[cfg(not(target_os = "none"))]
static mut CONTEXT_CHILD_HOST_OPS: ContextChildHostOps = DEFAULT_CONTEXT_CHILD_HOST_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn prepare_context_child(
    context: *mut u8,
    child_id: u32,
    out_record: *mut *mut u8,
    prepare_mode: u32,
) -> u32 {
    let ops = core::ptr::read_volatile(core::ptr::addr_of!(CONTEXT_CHILD_HOST_OPS));
    (ops.prepare)(context, child_id, out_record, prepare_mode)
}

/// context_child_handle_acquire — original: `FUN_08371418` @ `0x08371418`
/// (96 bytes; 18 direct plain-`bl` call sites).
///
/// Resolves `child_id` in `owner`'s context and returns its +0x38 handle via
/// `out_handle`. `prepare_mode` is forwarded unchanged to the resolver. A
/// zero resolver status requires a live record whose +0x00 context pointer is
/// non-NULL, matching the unguarded retailOS +0x38 adapter; otherwise the
/// original would fault before returning.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.context_child_handle_acquire")]
#[inline(never)]
pub unsafe extern "C" fn context_child_handle_acquire(
    owner: *mut u8,
    child_id: u32,
    out_handle: *mut *mut u8,
    prepare_mode: u32,
) -> u32 {
    let context = read_pointer(owner, 0);
    let status = prepare_context_child(context, child_id, out_handle, prepare_mode);
    if status != 0 {
        return status;
    }

    let record = out_handle.read_volatile();
    let handle = record.add(pointer_offset(RECORD_HANDLE));
    let payload = read_pointer(record, RECORD_PAYLOAD);
    write_pointer(handle, HANDLE_RECORD, record);
    (handle.add(pointer_offset(HANDLE_CHILD_ID)) as *mut u32).write_volatile(child_id);
    write_pointer(handle, HANDLE_PAYLOAD, payload);
    let priority = if child_id == 1 { 100 } else { 0 };
    write_pointer(handle, HANDLE_OWNER, owner);
    handle.add(pointer_offset(HANDLE_PRIORITY)).write_volatile(priority);
    out_handle.write_volatile(handle);
    0
}
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};

    static OPS_LOCK: AtomicBool = AtomicBool::new(false);
    static mut LAST_CALL: Option<(*mut u8, u32, *mut *mut u8, u32)> = None;
    static mut STATUS: u32 = 0;
    static mut RECORD: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_prepare(
        context: *mut u8,
        child_id: u32,
        out_record: *mut *mut u8,
        prepare_mode: u32,
    ) -> u32 {
        LAST_CALL = Some((context, child_id, out_record, prepare_mode));
        if STATUS == 0 {
            out_record.write(RECORD);
        }
        STATUS
    }

    struct TestLock;

    fn lock_ops() -> TestLock {
        while OPS_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while OPS_LOCK.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        TestLock
    }

    impl Drop for TestLock {
        fn drop(&mut self) {
            OPS_LOCK.store(false, Ordering::Release);
        }
    }

    struct Bench {
        _lock: TestLock,
    }

    fn bench(status: u32, record: *mut u8) -> Bench {
        let lock = lock_ops();
        unsafe {
            LAST_CALL = None;
            STATUS = status;
            RECORD = record;
            core::ptr::addr_of_mut!(CONTEXT_CHILD_HOST_OPS).write_volatile(ContextChildHostOps {
                prepare: recording_prepare,
            });
        }
        Bench { _lock: lock }
    }

    impl Drop for Bench {
        fn drop(&mut self) {
            unsafe {
                core::ptr::addr_of_mut!(CONTEXT_CHILD_HOST_OPS)
                    .write_volatile(DEFAULT_CONTEXT_CHILD_HOST_OPS);
            }
        }
    }

    #[repr(align(8))]
    struct Fixture {
        owner: [u8; WORD],
        context: [u8; 8],
        payload: [u8; 8],
        record: [u8; pointer_offset(RECORD_HANDLE + HANDLE_CHILD_ID + 4)],
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                owner: [0; WORD],
                context: [0; 8],
                payload: [0; 8],
                record: [0; pointer_offset(RECORD_HANDLE + HANDLE_CHILD_ID + 4)],
            }
        }

        fn initialize(&mut self) {
            unsafe {
                write_pointer(self.owner.as_mut_ptr(), 0, self.context.as_mut_ptr());
                write_pointer(self.record.as_mut_ptr(), RECORD_CONTEXT, self.context.as_mut_ptr());
                write_pointer(self.record.as_mut_ptr(), RECORD_PAYLOAD, self.payload.as_mut_ptr());
            }
        }
    }

    #[test]
    fn successful_acquisition_initializes_every_handle_field() {
        let mut fixture = Fixture::new();
        fixture.initialize();
        let _bench = bench(0, fixture.record.as_mut_ptr());
        let mut out = core::ptr::null_mut();

        let status = unsafe {
            context_child_handle_acquire(fixture.owner.as_mut_ptr(), 1, &mut out, 0xa5a5_5a5a)
        };

        let handle = unsafe { fixture.record.as_mut_ptr().add(pointer_offset(RECORD_HANDLE)) };
        assert_eq!(status, 0);
        assert_eq!(out, handle);
        assert_eq!(unsafe { LAST_CALL }, Some((fixture.context.as_mut_ptr(), 1, &mut out as *mut *mut u8, 0xa5a5_5a5a)));
        assert_eq!(unsafe { handle.add(pointer_offset(HANDLE_PRIORITY)).read() }, 100);
        assert_eq!(unsafe { read_pointer(handle, HANDLE_OWNER) }, fixture.owner.as_mut_ptr());
        assert_eq!(unsafe { read_pointer(handle, HANDLE_PAYLOAD) }, fixture.payload.as_mut_ptr());
        assert_eq!(unsafe { read_pointer(handle, HANDLE_RECORD) }, fixture.record.as_mut_ptr());
        assert_eq!(unsafe { (handle.add(pointer_offset(HANDLE_CHILD_ID)) as *const u32).read() }, 1);
    }

    #[test]
    fn nonprimary_child_clears_priority_and_forwards_mode() {
        let mut fixture = Fixture::new();
        fixture.initialize();
        let _bench = bench(0, fixture.record.as_mut_ptr());
        let mut out = core::ptr::null_mut();

        let status = unsafe {
            context_child_handle_acquire(fixture.owner.as_mut_ptr(), 57, &mut out, 1)
        };

        assert_eq!(status, 0);
        assert_eq!(unsafe { out.add(pointer_offset(HANDLE_PRIORITY)).read() }, 0);
        assert_eq!(unsafe { LAST_CALL }, Some((fixture.context.as_mut_ptr(), 57, &mut out as *mut *mut u8, 1)));
    }

    #[test]
    fn resolver_error_passes_through_without_writing_output() {
        let mut fixture = Fixture::new();
        fixture.initialize();
        let _bench = bench(13, fixture.record.as_mut_ptr());
        let mut out = fixture.payload.as_mut_ptr();

        let status = unsafe {
            context_child_handle_acquire(fixture.owner.as_mut_ptr(), 2, &mut out, 0)
        };

        assert_eq!(status, 13);
        assert_eq!(out, fixture.payload.as_mut_ptr());
        assert_eq!(unsafe { LAST_CALL }, Some((fixture.context.as_mut_ptr(), 2, &mut out as *mut *mut u8, 0)));
    }
}
