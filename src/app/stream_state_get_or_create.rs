//! Lazy stream-state singleton accessor.
//!
//! `stream_state_get_or_create` — original: `FUN_081559ac` @ `0x081559ac`
//! (204 bytes, ending with its literal global word at `0x08155a78`; the next
//! real function starts at `0x08155a7c`).
//!
//! # Verified calls and algorithm
//!
//! Raw ARM decoding finds nine plain outbound `bl` calls and no predicated
//! outbound `bl`: `operator_new(0x4c)`, two opaque cursor initializers, two
//! opaque cursor copies, an opaque range insertion, an opaque cursor destroy,
//! two `condvar_init` calls, and an unported six-entry state initializer. Full
//! A32 decoding finds three plain inbound `bl` calls (`0x08155990`,
//! `0x08155a84`, and `0x08155aa8`) and no predicated forms. The global word at
//! `0x089d00a8` caches a 76-byte state object. A NULL cache allocates it,
//! initializes the embedded 40-byte cursor/container at +4, clears +44,
//! inserts the default range, initializes condition variables at +48 and +64,
//! initializes the six-entry state at +60, publishes, and returns it.
//!
//! # Deliberate deviations
//!
//! The opaque cursor and state routines have no recovered semantic identities;
//! target builds call their verified retailOS addresses. Host builds use a
//! narrow operation table and a host cache in place of the live global.

pub const STREAM_STATE_GLOBAL: usize = 0x089d_00a8;
pub const STREAM_STATE_SIZE: usize = 0x4c;
const CURSOR_WORDS: usize = 10;

pub type StreamStateAllocate = unsafe extern "C" fn(usize) -> *mut u8;
pub type CursorInitialize = unsafe extern "C" fn(*mut u32);
pub type CursorCopy = unsafe extern "C" fn(*mut u32, *const u32) -> *mut u32;
pub type CursorInsertRange = unsafe extern "C" fn(u32, u32, u32, u32, u32, u32, u32, u32, u32);
pub type CursorDestroy = unsafe extern "C" fn(*mut u32);
pub type CondvarInitialize = unsafe extern "C" fn(*mut u8);
pub type SixEntryStateInitialize = unsafe extern "C" fn(*mut u8);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_allocate(_size: usize) -> *mut u8 { core::ptr::null_mut() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cursor_initialize(_cursor: *mut u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cursor_copy(dst: *mut u32, _src: *const u32) -> *mut u32 { dst }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cursor_insert_range(_: u32, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_cursor_destroy(_cursor: *mut u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_condvar_initialize(_condvar: *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_six_entry_state_initialize(_state: *mut u8) {}
/// Operations used by the target implementation and replaceable on the host.
pub struct StreamStateGetOrCreateOps {
    pub allocate: StreamStateAllocate,
    pub cursor_initialize: CursorInitialize,
    pub cursor_copy: CursorCopy,
    pub cursor_insert_range: CursorInsertRange,
    pub cursor_destroy: CursorDestroy,
    pub condvar_initialize: CondvarInitialize,
    pub six_entry_state_initialize: SixEntryStateInitialize,
}

unsafe extern "C" fn target_condvar_initialize(condvar: *mut u8) {
    unsafe { crate::kernel::condvar::condvar_init(condvar.cast()) }
}

#[cfg(not(target_os = "none"))]
pub static mut STREAM_STATE_GET_OR_CREATE_OPS: StreamStateGetOrCreateOps = StreamStateGetOrCreateOps {
    allocate: missing_allocate, cursor_initialize: missing_cursor_initialize,
    cursor_copy: missing_cursor_copy, cursor_insert_range: missing_cursor_insert_range,
    cursor_destroy: missing_cursor_destroy, condvar_initialize: missing_condvar_initialize,
    six_entry_state_initialize: missing_six_entry_state_initialize,
};
#[cfg(not(target_os = "none"))]
static mut HOST_STREAM_STATE: *mut u8 = core::ptr::null_mut();

#[cfg(target_os = "none")]
unsafe fn target_ops() -> StreamStateGetOrCreateOps {
    StreamStateGetOrCreateOps {
        allocate: crate::heap::veneers::operator_new,
        cursor_initialize: core::mem::transmute(0x083d_ee30usize),
        cursor_copy: core::mem::transmute(0x083d_a21cusize),
        cursor_insert_range: core::mem::transmute(0x083e_a230usize),
        cursor_destroy: core::mem::transmute(0x083d_eeccusize),
        condvar_initialize: target_condvar_initialize,
        six_entry_state_initialize: core::mem::transmute(0x081c_9470usize),
    }
}

/// Returns the lazy stream-state singleton, constructing it only on first use.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_state_get_or_create() -> *mut u8 {
    #[cfg(target_os = "none")]
    let cache = STREAM_STATE_GLOBAL as *mut *mut u8;
    #[cfg(not(target_os = "none"))]
    let cache = core::ptr::addr_of_mut!(HOST_STREAM_STATE);
    if unsafe { cache.read() }.is_null() {
        #[cfg(target_os = "none")]
        let ops = unsafe { target_ops() };
        #[cfg(not(target_os = "none"))]
        let ops = unsafe { core::ptr::addr_of!(STREAM_STATE_GET_OR_CREATE_OPS).read_volatile() };
        let state = unsafe { (ops.allocate)(STREAM_STATE_SIZE) };
        let mut stack = core::mem::MaybeUninit::<[u32; 24]>::uninit();
        let cursor = unsafe { state.add(4).cast::<u32>() };
        let stack = unsafe { stack.assume_init_mut() };
        let initial_cursor = unsafe { stack.as_mut_ptr().add(9) };
        let temporary_cursor = unsafe { stack.as_mut_ptr().add(1) };
        unsafe {
            (ops.cursor_initialize)(initial_cursor);
            state.add(44).cast::<u32>().write(0);
            (ops.cursor_initialize)(cursor.cast());
            (ops.cursor_copy)(temporary_cursor, initial_cursor.add(4));
            for index in 0..4 { stack[5 + index] = stack[1 + index]; }
            (ops.cursor_copy)(temporary_cursor, cursor.cast());
            (ops.cursor_insert_range)(stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7], stack[8], cursor as usize as u32);
            (ops.cursor_destroy)(initial_cursor);
            (ops.condvar_initialize)(state.add(48));
            (ops.six_entry_state_initialize)(state.add(60));
            (ops.condvar_initialize)(state.add(64));
            cache.write(state);
        }
    }
    unsafe { cache.read() }
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    #[repr(align(4))]
    struct State([u8; STREAM_STATE_SIZE]);
    static mut STATE: State = State([0; STREAM_STATE_SIZE]);
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    static mut CALLS: [usize; 7] = [0; 7];
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 { assert_eq!(size, STREAM_STATE_SIZE); unsafe { CALLS[0] += 1; ptr::addr_of_mut!(STATE).cast() } }
    unsafe extern "C" fn initialize(cursor: *mut u32) { unsafe { CALLS[1] += 1; cursor.write(CALLS[1] as u32); } }
    unsafe extern "C" fn copy(dst: *mut u32, src: *const u32) -> *mut u32 { unsafe { CALLS[2] += 1; core::ptr::copy_nonoverlapping(src, dst, CURSOR_WORDS); dst } }
    unsafe extern "C" fn insert(_: u32, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32, _: u32) { unsafe { CALLS[3] += 1; } }
    unsafe extern "C" fn destroy(_: *mut u32) { unsafe { CALLS[4] += 1; } }
    unsafe extern "C" fn condvar(_: *mut u8) { unsafe { CALLS[5] += 1; } }
    unsafe extern "C" fn six(_: *mut u8) { unsafe { CALLS[6] += 1; } }
    #[test]
    fn initializes_once_and_returns_cached_state() {
        let _lock = LOCK.lock();
        unsafe {
            HOST_STREAM_STATE = ptr::null_mut(); STATE = State([0; STREAM_STATE_SIZE]); CALLS = [0; 7];
            STREAM_STATE_GET_OR_CREATE_OPS = StreamStateGetOrCreateOps { allocate, cursor_initialize: initialize, cursor_copy: copy, cursor_insert_range: insert, cursor_destroy: destroy, condvar_initialize: condvar, six_entry_state_initialize: six };
            let first = stream_state_get_or_create(); let second = stream_state_get_or_create();
            assert_eq!(first, ptr::addr_of_mut!(STATE).cast()); assert_eq!(second, first);
            assert_eq!(CALLS, [1, 2, 2, 1, 1, 2, 1]); assert_eq!(first.add(44).cast::<u32>().read(), 0);
        }
    }
}
