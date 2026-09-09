//! Lazy Tdat payload allocation.
//!
//! - `ensure_tdat_payload` — original: `FUN_0803c328` @ `0x0803c328`
//!   (104 bytes; 16 direct `bl` call sites, all unconditional).
//!
//! Raw ARM decoded from `work/firmware/osos.dec` places this function at
//! `0x0803c328..0x0803c390`; the adjacent `push {r4-r9, lr}` at `0x0803c390`
//! starts the next independently linked function.

use core::ptr;

use super::tdat_class_check::ui_element_is_tdat_class;

/// Word index of the pool descriptor in a Tdat UI element (`ldr r0, [r2,#72]`).
const TDAT_PAYLOAD_POOL_WORD: usize = 18;

/// 32-bit retailOS layout of the owner passed to [`ensure_tdat_payload`].
///
/// The original loads the UI element at word 0 and its lazy payload at word 4.
/// Pointer words deliberately remain `u32`: native host pointers are eight
/// bytes wide, while the target's fields are four bytes apart.
#[repr(C)]
pub struct TdatPayloadOwner {
    pub element: u32,
    _unknown_04: u32,
    _unknown_08: u32,
    _unknown_0c: u32,
    pub payload: u32,
}

/// ABI of the still-unported fixed-pool allocation engine at `0x0805de1c`.
pub type TdatPayloadAcquire = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_tdat_payload_acquire(pool: *mut u8) -> *mut u8 {
    let acquire: TdatPayloadAcquire = core::mem::transmute(0x0805_de1cusize);
    acquire(pool)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_tdat_payload_acquire(_pool: *mut u8) -> *mut u8 {
    ptr::null_mut()
}

/// Calls outside this one-function port.
///
/// Target builds dispatch to the unported pool allocator at `0x0805de1c`.
/// Host tests replace this boundary to observe the original allocation path.
#[derive(Clone, Copy)]
pub struct TdatPayloadOps {
    pub acquire: TdatPayloadAcquire,
}

/// Production dispatch boundary for the Tdat payload pool allocator.
pub const DEFAULT_TDAT_PAYLOAD_OPS: TdatPayloadOps = TdatPayloadOps {
    acquire: retail_tdat_payload_acquire,
};

/// Active Tdat payload allocation boundary.
///
/// This is intentionally a separate seam: `0x0805de1c` has no `ported` ledger
/// entry, whereas its class predicate dependency is the existing Rust port at
/// `0x0806aa3c`.
pub static mut TDAT_PAYLOAD_OPS: TdatPayloadOps = DEFAULT_TDAT_PAYLOAD_OPS;

#[inline(always)]
fn tdat_payload_ops() -> TdatPayloadOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(TDAT_PAYLOAD_OPS)) }
}

/// ensure_tdat_payload — original: `FUN_0803c328` @ `0x0803c328` (104 bytes).
///
/// Decoding the raw ARM words at `0x0803c328..0x0803c390` finds an already
/// initialized payload when its first byte has bit 0 set. Otherwise this calls
/// the ported `ui_element_is_tdat_class` predicate at `0x0806aa3c`; only a
/// `'tdat'` element reaches the unported pool allocator at `0x0805de1c`, with
/// the descriptor from element word 18 (`+0x48`). The returned payload pointer
/// is stored in owner word 4, marked initialized by storing byte 1 at its
/// start, and reported as success. Allocation failure stores and returns zero.
///
/// Every ARM B/BL encoding in `osos.dec` that targets this function gives 16
/// direct calls: 16 unconditional `bl`, zero predicated forms. The callers do
/// not flag-gate this routine, consistent with its own initialization fast
/// path and strict zero/one result.
///
/// Deliberate deviation: `0x0805de1c` is not ported, so its retail call is an
/// explicit `TDAT_PAYLOAD_OPS` dispatch seam. The port calls the existing Rust
/// `ui_element_is_tdat_class` instead of branching to stock `0x0806aa3c`; its
/// aligned word load and NULL predicate behavior are unchanged.
///
/// # Safety
///
/// `owner` and `owner.payload` must be non-NULL and readable, matching the
/// unconditional `ldr`/`ldrb` at function entry. If the payload is not already
/// initialized, `owner.element` must either be NULL or address a readable Tdat
/// class object through word 18; a successful allocator result must be writable
/// for one byte.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.ensure_tdat_payload")]
#[inline(never)]
pub unsafe extern "C" fn ensure_tdat_payload(owner: *mut TdatPayloadOwner) -> u32 {
    let existing_payload = (*owner).payload as *mut u8;
    if existing_payload.read() & 1 != 0 {
        return 1;
    }

    let element = (*owner).element as *mut u8;
    if ui_element_is_tdat_class(element) == 0 {
        return 0;
    }

    let pool = element.cast::<u32>().add(TDAT_PAYLOAD_POOL_WORD).read() as *mut u8;
    let payload = (tdat_payload_ops().acquire)(pool);
    (*owner).payload = payload as u32;
    if payload.is_null() {
        return 0;
    }

    payload.write(1);
    u32::from((*owner).payload != 0)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use std::sync::Mutex;

    const SLAB_LEN: usize = 0x4000;
    const ELEMENT_OFFSET: usize = 0x400;
    const OLD_PAYLOAD_OFFSET: usize = 0x800;
    const NEW_PAYLOAD_OFFSET: usize = 0xc00;
    const POOL_OFFSET: usize = 0x1000;
    const TDAT_CLASS_TAG: u32 = 0x7464_6174;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut ACQUIRE_CALLS: u32 = 0;
    static mut ACQUIRE_POOL: u32 = 0;
    static mut ACQUIRE_RESULT: u32 = 0;

    unsafe extern "C" fn record_acquire(pool: *mut u8) -> *mut u8 {
        ACQUIRE_CALLS += 1;
        ACQUIRE_POOL = pool as u32;
        ACQUIRE_RESULT as *mut u8
    }

    struct OpsGuard(TdatPayloadOps);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { TDAT_PAYLOAD_OPS = self.0 };
        }
    }

    fn fixture() -> Option<*mut u8> {
        try_map_u32_slab(hints::TDAT_PAYLOAD, SLAB_LEN)
    }

    unsafe fn install_recorder(result: *mut u8) -> OpsGuard {
        let previous = TDAT_PAYLOAD_OPS;
        TDAT_PAYLOAD_OPS = TdatPayloadOps {
            acquire: record_acquire,
        };
        ACQUIRE_CALLS = 0;
        ACQUIRE_POOL = 0;
        ACQUIRE_RESULT = result as u32;
        OpsGuard(previous)
    }

    unsafe fn owner(base: *mut u8, element: *mut u8, payload: *mut u8) -> *mut TdatPayloadOwner {
        let owner = base.cast::<TdatPayloadOwner>();
        owner.write(TdatPayloadOwner {
            element: element as u32,
            _unknown_04: 0,
            _unknown_08: 0,
            _unknown_0c: 0,
            payload: payload as u32,
        });
        owner
    }

    unsafe fn prepare_tdat_element(element: *mut u8, pool: *mut u8) {
        ptr::write_bytes(element, 0, 0x100);
        element.cast::<u32>().add(1).write(TDAT_CLASS_TAG);
        element.cast::<u32>().add(TDAT_PAYLOAD_POOL_WORD).write(pool as u32);
    }

    #[test]
    fn initialized_payload_skips_class_check_and_allocator() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = fixture() else {
            note_missing_u32_fixture("ui::tdat_payload");
            return;
        };
        unsafe {
            let element = base.add(ELEMENT_OFFSET);
            let old_payload = base.add(OLD_PAYLOAD_OFFSET);
            old_payload.write(0x81);
            let owner = owner(base, element, old_payload);
            let _ops = install_recorder(base.add(NEW_PAYLOAD_OFFSET));

            assert_eq!(ensure_tdat_payload(owner), 1);
            assert_eq!((*owner).payload, old_payload as u32);
            assert_eq!(ACQUIRE_CALLS, 0);
        }
    }

    #[test]
    fn non_tdat_element_leaves_existing_payload_unmodified() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = fixture() else {
            note_missing_u32_fixture("ui::tdat_payload");
            return;
        };
        unsafe {
            let element = base.add(ELEMENT_OFFSET);
            let old_payload = base.add(OLD_PAYLOAD_OFFSET);
            ptr::write_bytes(element, 0, 0x100);
            element.cast::<u32>().add(1).write(0x706c_7374);
            old_payload.write(0);
            let owner = owner(base, element, old_payload);
            let _ops = install_recorder(base.add(NEW_PAYLOAD_OFFSET));

            assert_eq!(ensure_tdat_payload(owner), 0);
            assert_eq!(ACQUIRE_CALLS, 0);
            assert_eq!((*owner).payload, old_payload as u32);
            assert_eq!(old_payload.read(), 0);
        }
    }

    #[test]
    fn allocation_failure_stores_zero_payload() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = fixture() else {
            note_missing_u32_fixture("ui::tdat_payload");
            return;
        };
        unsafe {
            let element = base.add(ELEMENT_OFFSET);
            let old_payload = base.add(OLD_PAYLOAD_OFFSET);
            let pool = base.add(POOL_OFFSET);
            prepare_tdat_element(element, pool);
            old_payload.write(0);
            let owner = owner(base, element, old_payload);
            let _ops = install_recorder(ptr::null_mut());

            assert_eq!(ensure_tdat_payload(owner), 0);
            assert_eq!(ACQUIRE_CALLS, 1);
            assert_eq!(ACQUIRE_POOL, pool as u32);
            assert_eq!((*owner).payload, 0);
        }
    }

    #[test]
    fn tdat_element_acquires_marks_and_stores_payload() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some(base) = fixture() else {
            note_missing_u32_fixture("ui::tdat_payload");
            return;
        };
        unsafe {
            let element = base.add(ELEMENT_OFFSET);
            let old_payload = base.add(OLD_PAYLOAD_OFFSET);
            let new_payload = base.add(NEW_PAYLOAD_OFFSET);
            let pool = base.add(POOL_OFFSET);
            prepare_tdat_element(element, pool);
            old_payload.write(0);
            new_payload.write(0xa5);
            let owner = owner(base, element, old_payload);
            let _ops = install_recorder(new_payload);

            assert_eq!(ensure_tdat_payload(owner), 1);
            assert_eq!(ACQUIRE_CALLS, 1);
            assert_eq!(ACQUIRE_POOL, pool as u32);
            assert_eq!((*owner).payload, new_payload as u32);
            assert_eq!(new_payload.read(), 1);
        }
    }
}
