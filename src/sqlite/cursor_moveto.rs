//! Applying a deferred VDBE cursor seek.
//!
//! `vdbe_cursor_moveto` — retailOS `FUN_08386c90` @ `0x08386c90` (148 bytes;
//! `0x08386c90..0x08386d24`, followed by a distinct prologue). Binary decoding
//! finds four unconditional plain-`bl` callers (0x0838816c, 0x08389918,
//! 0x083899d0, 0x08389aa0) and no predicated callers.
//!
//! SQLite's `sqlite3VdbeCursorMoveto`: when a cursor has a deferred target,
//! seek its B-tree cursor by rowid, invalidate its rowid cache, copy the target
//! to `lastRowid`, and advance once when the seek lands before a row. The B-tree
//! movement helpers at 0x08371e54 and 0x08372288 are unported, so host builds
//! use a dispatch seam; device builds call their verified retail addresses.
//!
//! Deliberate host-only deviation: target pointer fields remain little-endian
//! `u32` words, and the two unported calls are volatile dispatches.

const DEFERRED_MOVETO: usize = 0x20;
const LAST_ROWID: usize = 0x08;
const MOVETO_TARGET: usize = 0x28;
const ROWID_IS_VALID: usize = 0x19;
const BTREE_CURSOR: usize = 0x00;
const ROWID_CACHE_VALID: usize = 0x48;
const CACHE_STATUS: usize = 0x68;

type BtreeMoveto = unsafe extern "C" fn(*mut u8, *mut u8, u32, *mut i32, u32, u32, u32, *mut i32) -> i32;
type BtreeNext = unsafe extern "C" fn(*mut u8, *mut i32) -> i32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn btree_moveto(cursor: *mut u8, result: *mut i32, target_lo: u32, target_hi: u32) -> i32 {
    let call: BtreeMoveto = core::mem::transmute(0x0837_1e54usize);
    call(cursor, core::ptr::null_mut(), 0, result, target_lo, target_hi, 0, result)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn btree_next(cursor: *mut u8, result: *mut i32) -> i32 {
    let call: BtreeNext = core::mem::transmute(0x0837_2288usize);
    call(cursor, result)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_moveto(
    _cursor: *mut u8,
    _key: *mut u8,
    _zero: u32,
    _result: *mut i32,
    _target_lo: u32,
    _target_hi: u32,
    _bias: u32,
    _result_again: *mut i32,
) -> i32 { 11 }

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_next(_cursor: *mut u8, _result: *mut i32) -> i32 { 11 }

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct CursorMovetoOps { moveto: BtreeMoveto, next: BtreeNext }

#[cfg(not(target_os = "none"))]
const DEFAULT_CURSOR_MOVETO_OPS: CursorMovetoOps = CursorMovetoOps {
    moveto: unavailable_moveto,
    next: unavailable_next,
};

#[cfg(not(target_os = "none"))]
static mut CURSOR_MOVETO_OPS: CursorMovetoOps = DEFAULT_CURSOR_MOVETO_OPS;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> CursorMovetoOps {
    core::ptr::read_volatile(core::ptr::addr_of!(CURSOR_MOVETO_OPS))
}

#[inline(always)]
unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    u32::from_le(base.add(offset).cast::<u32>().read())
}

/// `sqlite3VdbeCursorMoveto` — retailOS `FUN_08386c90` @ `0x08386c90`
/// (148 bytes; 4 direct unconditional plain-`bl` callers).
///
/// Applies a pending rowid seek. A failed seek leaves `deferredMoveto` and the
/// cache status untouched. A negative comparison result advances exactly once;
/// only successful completion clears the deferred state and cache status.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vdbe_cursor_moveto(cursor: *mut u8) -> i32 {
    if *cursor.add(DEFERRED_MOVETO) == 0 { return 0; }

    let btree_cursor = read_u32(cursor, BTREE_CURSOR) as usize as *mut u8;
    let mut result = 0i32;
    let rc = {
        #[cfg(target_os = "none")]
        { btree_moveto(btree_cursor, &mut result, read_u32(cursor, MOVETO_TARGET), read_u32(cursor, MOVETO_TARGET + 4)) }
        #[cfg(not(target_os = "none"))]
        { (host_ops().moveto)(btree_cursor, core::ptr::null_mut(), 0, &mut result, read_u32(cursor, MOVETO_TARGET), read_u32(cursor, MOVETO_TARGET + 4), 0, &mut result) }
    };
    if rc != 0 { return rc; }

    *(read_u32(cursor, ROWID_CACHE_VALID) as usize as *mut u8) = 0;
    cursor.add(LAST_ROWID).cast::<u32>().write(read_u32(cursor, MOVETO_TARGET).to_le());
    cursor.add(LAST_ROWID + 4).cast::<u32>().write(read_u32(cursor, MOVETO_TARGET + 4).to_le());
    *cursor.add(ROWID_IS_VALID) = (result == 0) as u8;
    if result < 0 {
        let rc = {
            #[cfg(target_os = "none")]
            { btree_next(btree_cursor, &mut result) }
            #[cfg(not(target_os = "none"))]
            { (host_ops().next)(btree_cursor, &mut result) }
        };
        if rc != 0 { return rc; }
    }
    *cursor.add(DEFERRED_MOVETO) = 0;
    cursor.add(CACHE_STATUS).cast::<u32>().write(0);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::{LazyLock, Mutex, MutexGuard};
    use std::sync::atomic::{AtomicI32, Ordering};

    const SLAB_LEN: usize = 0x10000;
    const OFF_CURSOR: usize = 0x1000;
    const OFF_BTREE: usize = 0x2000;
    const OFF_VALID: usize = 0x3000;
    static SLAB: LazyLock<Option<usize>> = LazyLock::new(|| try_map_u32_slab(hints::VDBE_CURSOR_MOVETO, SLAB_LEN).map(|p| p as usize));
    static LOCK: Mutex<()> = Mutex::new(());
    static MOVETO_RC: AtomicI32 = AtomicI32::new(0);
    static MOVETO_RESULT: AtomicI32 = AtomicI32::new(0);
    static NEXT_RC: AtomicI32 = AtomicI32::new(0);
    static NEXT_CALLS: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" fn mock_moveto(_cursor: *mut u8, _key: *mut u8, _zero: u32, result: *mut i32, _lo: u32, _hi: u32, _bias: u32, _again: *mut i32) -> i32 { *result = MOVETO_RESULT.load(Ordering::Relaxed); MOVETO_RC.load(Ordering::Relaxed) }
    unsafe extern "C" fn mock_next(_cursor: *mut u8, result: *mut i32) -> i32 { NEXT_CALLS.fetch_add(1, Ordering::Relaxed); *result = 0; NEXT_RC.load(Ordering::Relaxed) }

    struct Fixture { _guard: MutexGuard<'static, ()>, base: *mut u8 }
    impl Fixture {
        fn new() -> Option<Self> {
            let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let base = match *SLAB { Some(base) => base as *mut u8, None => { note_missing_u32_fixture("sqlite::cursor_moveto_tests"); return None; } };
            MOVETO_RC.store(0, Ordering::Relaxed); MOVETO_RESULT.store(0, Ordering::Relaxed); NEXT_RC.store(0, Ordering::Relaxed); NEXT_CALLS.store(0, Ordering::Relaxed);
            unsafe { core::ptr::write_bytes(base, 0, SLAB_LEN); (*core::ptr::addr_of_mut!(CURSOR_MOVETO_OPS)) = CursorMovetoOps { moveto: mock_moveto, next: mock_next }; }
            Some(Self { _guard: guard, base })
        }
        fn cursor(&self) -> *mut u8 { unsafe { self.base.add(OFF_CURSOR) } }
        unsafe fn write_u32(&self, offset: usize, value: u32) { self.cursor().add(offset).cast::<u32>().write(value.to_le()); }
        unsafe fn read_u32(&self, offset: usize) -> u32 { u32::from_le(self.cursor().add(offset).cast::<u32>().read()) }
        unsafe fn initialize(&self) { *self.cursor().add(DEFERRED_MOVETO) = 1; self.write_u32(BTREE_CURSOR, self.base.add(OFF_BTREE) as usize as u32); self.write_u32(ROWID_CACHE_VALID, self.base.add(OFF_VALID) as usize as u32); self.write_u32(MOVETO_TARGET, 0x89ab_cdef); self.write_u32(MOVETO_TARGET + 4, 0x0123_4567); *self.base.add(OFF_VALID) = 1; }
    }
    impl Drop for Fixture { fn drop(&mut self) { unsafe { (*core::ptr::addr_of_mut!(CURSOR_MOVETO_OPS)) = DEFAULT_CURSOR_MOVETO_OPS; } } }

    #[test]
    fn inactive_cursor_does_not_call_btree() { let Some(f) = Fixture::new() else { return }; assert_eq!(unsafe { vdbe_cursor_moveto(f.cursor()) }, 0); assert_eq!(NEXT_CALLS.load(Ordering::Relaxed), 0); }
    #[test]
    fn failed_seek_preserves_deferred_state() { let Some(f) = Fixture::new() else { return }; unsafe { f.initialize(); *f.cursor().add(CACHE_STATUS) = 0x55; } MOVETO_RC.store(5, Ordering::Relaxed); assert_eq!(unsafe { vdbe_cursor_moveto(f.cursor()) }, 5); assert_eq!(unsafe { *f.cursor().add(DEFERRED_MOVETO) }, 1); assert_eq!(unsafe { *f.cursor().add(CACHE_STATUS) }, 0x55); assert_eq!(unsafe { *f.base.add(OFF_VALID) }, 1); }
    #[test]
    fn successful_seek_updates_caches_and_clears_deferred_state() { let Some(f) = Fixture::new() else { return }; unsafe { f.initialize(); } assert_eq!(unsafe { vdbe_cursor_moveto(f.cursor()) }, 0); assert_eq!(unsafe { f.read_u32(LAST_ROWID) }, 0x89ab_cdef); assert_eq!(unsafe { f.read_u32(LAST_ROWID + 4) }, 0x0123_4567); assert_eq!(unsafe { *f.cursor().add(ROWID_IS_VALID) }, 1); assert_eq!(unsafe { *f.base.add(OFF_VALID) }, 0); assert_eq!(unsafe { *f.cursor().add(DEFERRED_MOVETO) }, 0); assert_eq!(unsafe { f.read_u32(CACHE_STATUS) }, 0); }
    #[test]
    fn before_row_seek_advances_once_before_completion() { let Some(f) = Fixture::new() else { return }; unsafe { f.initialize(); } MOVETO_RESULT.store(-1, Ordering::Relaxed); assert_eq!(unsafe { vdbe_cursor_moveto(f.cursor()) }, 0); assert_eq!(NEXT_CALLS.load(Ordering::Relaxed), 1); assert_eq!(unsafe { *f.cursor().add(ROWID_IS_VALID) }, 0); }
}
