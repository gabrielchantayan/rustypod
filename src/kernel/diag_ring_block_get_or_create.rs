//! Per-task diagnostic-ring block lookup and creation.
//!
//! `diag_ring_block_get_or_create` — original: `FUN_080498f8` @ 0x080498f8
//! (208 bytes: 0x080498f8..0x080499c8; the two literal-pool words follow at
//! 0x080499c8/0x080499cc and the next function starts at 0x080499d0). Raw
//! A32 decoding finds four plain `bl` call sites and one predicated `blne`
//! site. The indirect `blx` calls are table slots +0x1c/+0x20.
//!
//! It prepares the task-indexed table, obtains the current context id, and
//! looks up its 332-byte diagnostic ring. On a miss it allocates the ring,
//! stamps the owner id, clears head/tail and the pointer/flag arrays, then
//! registers it. If registration does not retain that exact ring it releases
//! the candidate and returns the firmware fallback pointer.
//!
//! Deliberate deviation: host builds use an operation-table seam for the
//! unported task-index table and release service. Firmware builds call their
//! verified fixed addresses and use the target's u32 pointer layout.

use crate::drivers::ata_cmd::traced_alloc;
use crate::kernel::diag_ring_record::{DiagEventRing, RING_CAPACITY};
use crate::kernel::resource_op::current_context_id;

const DIAG_RING_SIZE: i32 = 0x14c;
#[cfg(target_os = "none")]
const TASK_TABLE_GLOBAL: *const u32 = 0x08a0_ea08usize as *const u32;
#[cfg(target_os = "none")]
const DIAG_RING_FALLBACK: *mut DiagEventRing = 0x08b2_10b0usize as *mut DiagEventRing;
#[cfg(target_os = "none")]
unsafe fn task_table_prepare() {
    let function: unsafe extern "C" fn() = core::mem::transmute(0x0808_475cusize);
    function();
}
#[cfg(target_os = "none")]
unsafe fn task_table_release(value: *mut u8) {
    let function: unsafe extern "C" fn(*mut u8) = core::mem::transmute(0x0808_6a88usize);
    function(value);
}

type TaskTableLookup = unsafe extern "C" fn(*mut u32) -> *mut DiagEventRing;
type TaskTableRegister = unsafe extern "C" fn(*mut DiagEventRing) -> *mut u8;

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct DiagRingBlockOps {
    pub prepare: unsafe extern "C" fn(),
    pub current_context: unsafe extern "C" fn() -> u32,
    pub lookup: unsafe extern "C" fn(*mut u32) -> *mut DiagEventRing,
    pub allocate: unsafe extern "C" fn() -> *mut DiagEventRing,
    pub register: unsafe extern "C" fn(*mut DiagEventRing) -> *mut u8,
    pub release: unsafe extern "C" fn(*mut u8),
    pub fallback: unsafe extern "C" fn() -> *mut DiagEventRing,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_void() { panic!("diagnostic ring task service unavailable") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_id() -> u32 { panic!("diagnostic ring task service unavailable") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_lookup(_: *mut u32) -> *mut DiagEventRing { panic!("diagnostic ring task service unavailable") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_alloc() -> *mut DiagEventRing { panic!("diagnostic ring task service unavailable") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_register(_: *mut DiagEventRing) -> *mut u8 { panic!("diagnostic ring task service unavailable") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_release(_: *mut u8) { panic!("diagnostic ring task service unavailable") }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_fallback() -> *mut DiagEventRing { panic!("diagnostic ring task service unavailable") }

#[cfg(not(target_os = "none"))]
pub const DEFAULT_DIAG_RING_BLOCK_OPS: DiagRingBlockOps = DiagRingBlockOps {
    prepare: unavailable_void, current_context: unavailable_id, lookup: unavailable_lookup,
    allocate: unavailable_alloc, register: unavailable_register, release: unavailable_release,
    fallback: unavailable_fallback,
};
#[cfg(not(target_os = "none"))]
pub static mut DIAG_RING_BLOCK_OPS: DiagRingBlockOps = DEFAULT_DIAG_RING_BLOCK_OPS;

#[cfg(target_os = "none")]
unsafe fn lookup(owner: *mut u32) -> *mut DiagEventRing {
    let table = core::ptr::read_volatile(TASK_TABLE_GLOBAL) as *mut u32;
    let vtable = table.read() as *const u32;
    let function: TaskTableLookup = core::mem::transmute(vtable.add(7).read() as usize);
    function(owner)
}
#[cfg(target_os = "none")]
unsafe fn register(ring: *mut DiagEventRing) -> *mut u8 {
    let table = core::ptr::read_volatile(TASK_TABLE_GLOBAL) as *mut u32;
    let vtable = table.read() as *const u32;
    let function: TaskTableRegister = core::mem::transmute(vtable.add(8).read() as usize);
    function(ring)
}

/// Returns the current context's diagnostic event ring, creating and
/// registering it on first use. The stock fallback is returned if registration
/// selects a different object.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn diag_ring_block_get_or_create() -> *mut DiagEventRing {
    #[cfg(target_os = "none")]
    {
        task_table_prepare();
        let mut owner = current_context_id();
        let ring = lookup(&mut owner);
        if !ring.is_null() { return ring; }
        let candidate = traced_alloc(DIAG_RING_SIZE, 0, 0).cast::<DiagEventRing>();
        if candidate.is_null() { return DIAG_RING_FALLBACK; }
        (*candidate).owner = owner;
        (*candidate).head = 0;
        (*candidate).tail = 0;
        let pointers = core::ptr::addr_of_mut!((*candidate).pointers).cast::<u32>();
        let flags = core::ptr::addr_of_mut!((*candidate).flags).cast::<u32>();
        for index in 0..RING_CAPACITY {
            core::ptr::write_volatile(pointers.add(index), 0);
            core::ptr::write_volatile(flags.add(index), 0);
        }
        let registration = register(candidate);
        let found = lookup(candidate.cast());
        if found == candidate {
            if !registration.is_null() { task_table_release(registration); }
            candidate
        } else {
            task_table_release(candidate.cast());
            DIAG_RING_FALLBACK
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        let ops = core::ptr::read_volatile(core::ptr::addr_of!(DIAG_RING_BLOCK_OPS));
        (ops.prepare)();
        let mut owner = (ops.current_context)();
        let ring = (ops.lookup)(&mut owner);
        if !ring.is_null() { return ring; }
        let candidate = (ops.allocate)();
        if candidate.is_null() { return (ops.fallback)(); }
        (*candidate).owner = owner;
        (*candidate).head = 0;
        (*candidate).tail = 0;
        for index in 0..RING_CAPACITY {
            (*candidate).pointers[index] = 0;
            (*candidate).flags[index] = 0;
        }
        let registration = (ops.register)(candidate);
        let found = (ops.lookup)(candidate.cast());
        if found == candidate {
            if !registration.is_null() { (ops.release)(registration); }
            candidate
        } else {
            (ops.release)(candidate.cast());
            (ops.fallback)()
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut RING: DiagEventRing = DiagEventRing { owner: 0, tags: [0; 16], pointers: [0; 16], flags: [0; 16], data0: [0; 16], data1: [0; 16], head: 9, tail: 8 };
    static mut STORED: *mut DiagEventRing = core::ptr::null_mut();
    static mut RELEASED: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn prepare() {}
    unsafe extern "C" fn context() -> u32 { 0x42 }
    unsafe extern "C" fn lookup(_: *mut u32) -> *mut DiagEventRing { STORED }
    unsafe extern "C" fn allocate() -> *mut DiagEventRing { core::ptr::addr_of_mut!(RING) }
    unsafe extern "C" fn register(ring: *mut DiagEventRing) -> *mut u8 { STORED = ring; 0x1234usize as *mut u8 }
    unsafe extern "C" fn release(value: *mut u8) { RELEASED = value }
    unsafe extern "C" fn fallback() -> *mut DiagEventRing { 0x5678usize as *mut DiagEventRing }

    unsafe fn install() {
        DIAG_RING_BLOCK_OPS = DiagRingBlockOps { prepare, current_context: context, lookup, allocate, register, release, fallback };
    }

    #[test]
    fn creates_initializes_and_registers_a_missing_ring() {
        let _guard = LOCK.lock();
        unsafe {
            STORED = core::ptr::null_mut();
            RELEASED = core::ptr::null_mut();
            RING.tags = [0xfeed; 16];
            RING.pointers = [1; 16];
            RING.flags = [2; 16];
            RING.head = 9;
            RING.tail = 8;
            install();
            let ring = diag_ring_block_get_or_create();
            assert_eq!(ring, core::ptr::addr_of_mut!(RING));
            assert_eq!((*ring).owner, 0x42);
            assert_eq!((*ring).head, 0);
            assert_eq!((*ring).tail, 0);
            assert_eq!((*ring).pointers, [0; 16]);
            assert_eq!((*ring).flags, [0; 16]);
            assert_eq!(RELEASED, 0x1234usize as *mut u8);
            DIAG_RING_BLOCK_OPS = DEFAULT_DIAG_RING_BLOCK_OPS;
        }
    }

    #[test]
    fn returns_existing_ring_without_allocating_or_releasing() {
        let _guard = LOCK.lock();
        unsafe {
            STORED = core::ptr::addr_of_mut!(RING);
            RELEASED = core::ptr::null_mut();
            install();
            assert_eq!(diag_ring_block_get_or_create(), STORED);
            assert!(RELEASED.is_null());
            DIAG_RING_BLOCK_OPS = DEFAULT_DIAG_RING_BLOCK_OPS;
        }
    }
}
