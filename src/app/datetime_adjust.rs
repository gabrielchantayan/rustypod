//! `datetime_adjust_and_store` — original: `FUN_081dd858` @ `0x081dd858`
//! (92 bytes, `0x081dd858..0x081dd8b4`; the next function begins at
//! `0x081dd8b4`). Raw A32 decoding finds three plain inbound `bl` calls
//! (`0x081dd744`, `0x081dd7f4`, `0x081dd84c`) and no predicated `bl` forms.
//!
//! Selects the active date/time field from the controller's mode-dependent
//! selector object, adjusts the packed ten-byte DateTime at `+0x14c`, then
//! writes the copied record as the controller's `"DtTm"` resource. The raw
//! register flow supplies `delta` in both r2 and r3 to the adjustment call;
//! Ghidra drops its fourth argument. Deliberate deviations: the unported
//! direct callee is a typed fixed-address call on target and an injectable host
//! seam; the retail memcpy is an explicit ten-byte volatile copy.

use crate::app::resource_chain::{ResourceKind, ResourceProvider};
#[cfg(target_os = "none")]
use crate::app::resource_chain::resource_chain_write;

const ACTIVE_MODE_OFFSET: usize = 0x138;
const SELECTOR_OBJECT_OFFSETS: [usize; 3] = [0x140, 0x144, 0x148];
const SELECTOR_VALUE_OFFSET: usize = 0x44;
const DATETIME_OFFSET: usize = 0x14c;
const DATETIME_RESOURCE_OFFSET: usize = 0x164;
const RESOURCE_PROVIDER_OFFSET: usize = 0x38;
const RESOURCE_ID_OFFSET: usize = 0x44;
const RESOURCE_KIND_DTTM: ResourceKind = ResourceKind(0x4474_546d);

type DateTimeAdjust = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> u32;

#[cfg(not(target_os = "none"))]
type DateTimeResourceWrite = unsafe extern "C" fn(*mut ResourceProvider, ResourceKind, u32, *const u8, u32) -> u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn date_time_adjust() -> DateTimeAdjust {
    core::mem::transmute(0x081e_8f78usize)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_date_time_adjust(_: *mut u8, _: u32, _: u32, _: u32) -> u32 {
    panic!("datetime_adjust_and_store requires a date-time adjustment fixture")
}

#[cfg(not(target_os = "none"))]
pub static mut DATETIME_ADJUST: DateTimeAdjust = missing_date_time_adjust;
#[cfg(not(target_os = "none"))]
pub static mut DATETIME_RESOURCE_WRITE: DateTimeResourceWrite = missing_date_time_resource_write;

unsafe extern "C" fn missing_date_time_resource_write(_: *mut ResourceProvider, _: ResourceKind, _: u32, _: *const u8, _: u32) -> u32 {
    panic!("datetime_adjust_and_store requires a resource-write fixture")
}

#[inline(always)]
unsafe fn word(object: *const u8, offset: usize) -> u32 {
    (object.add(offset) as *const u32).read_volatile()
}

#[inline(always)]
unsafe fn active_datetime_field(controller: *const u8) -> u32 {
    let mode = word(controller, ACTIVE_MODE_OFFSET);
    if mode > 2 {
        return 0;
    }
    let selector = word(controller, SELECTOR_OBJECT_OFFSETS[mode as usize]);
    word(selector as usize as *const u8, SELECTOR_VALUE_OFFSET)
}

/// Adjusts the active packed date/time field and publishes its ten-byte record.
///
/// # Safety
/// `controller` must point to the retail controller layout through `+0x16d`.
/// Its selector and provider words must be valid target pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn datetime_adjust_and_store(controller: *mut u8, delta: u32) -> u32 {
    let active_field = active_datetime_field(controller);

    #[cfg(target_os = "none")]
    let adjusted = date_time_adjust()(controller.add(DATETIME_OFFSET), active_field, delta, delta);
    #[cfg(not(target_os = "none"))]
    let adjusted = DATETIME_ADJUST(controller.add(DATETIME_OFFSET), active_field, delta, delta);

    let mut record = [0u8; 10];
    for (index, byte) in record.iter_mut().enumerate() {
        *byte = controller.add(DATETIME_RESOURCE_OFFSET + index).read_volatile();
    }
    #[cfg(target_os = "none")]
    resource_chain_write(
        word(controller, RESOURCE_PROVIDER_OFFSET) as usize as *mut ResourceProvider,
        RESOURCE_KIND_DTTM,
        word(controller, RESOURCE_ID_OFFSET),
        record.as_ptr() as usize as u32,
        10,
    );
    #[cfg(not(target_os = "none"))]
    DATETIME_RESOURCE_WRITE(
        word(controller, RESOURCE_PROVIDER_OFFSET) as usize as *mut ResourceProvider,
        RESOURCE_KIND_DTTM,
        word(controller, RESOURCE_ID_OFFSET),
        record.as_ptr(),
        10,
    );
    adjusted
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::ptr;
    use parking_lot::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ADJUST_ARGS: (*mut u8, u32, u32, u32) = (ptr::null_mut(), 0, 0, 0);
    static mut WRITTEN: (ResourceKind, u32, [u8; 10], u32) = (ResourceKind(0), 0, [0; 10], 0);

    unsafe extern "C" fn adjust(record: *mut u8, field: u32, first_delta: u32, second_delta: u32) -> u32 {
        ADJUST_ARGS = (record, field, first_delta, second_delta);
        0x55
    }

    unsafe extern "C" fn write(_: *mut ResourceProvider, kind: ResourceKind, id: u32, value: *const u8, flags: u32) -> u32 {
        let mut bytes = [0; 10];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = value.add(index).read();
        }
        WRITTEN = (kind, id, bytes, flags);
        1
    }

    #[test]
    fn adjusts_selected_field_and_writes_exact_datetime_record() {
        let _guard: MutexGuard<'_, ()> = LOCK.lock();
        let Some(controller) = try_map_u32_slab(hints::DATETIME_ADJUST_AND_STORE, 0x400) else { return };
        unsafe {
            let selector = controller.add(0x200);
            let provider = controller.add(0x280) as *mut ResourceProvider;
            ptr::write_bytes(controller, 0, 0x400);
            (controller.add(ACTIVE_MODE_OFFSET) as *mut u32).write(1);
            (controller.add(SELECTOR_OBJECT_OFFSETS[1]) as *mut u32).write(selector as usize as u32);
            (selector.add(SELECTOR_VALUE_OFFSET) as *mut u32).write(0x2d05);
            (controller.add(RESOURCE_PROVIDER_OFFSET) as *mut u32).write(provider as usize as u32);
            (controller.add(RESOURCE_ID_OFFSET) as *mut u32).write(0x80aa);
            for index in 0..10 { controller.add(DATETIME_RESOURCE_OFFSET + index).write(0xa0 + index as u8); }
            DATETIME_ADJUST = adjust;
            DATETIME_RESOURCE_WRITE = write;
            assert_eq!(datetime_adjust_and_store(controller, 0xffff_ffff), 0x55);
            assert_eq!(ADJUST_ARGS, (controller.add(DATETIME_OFFSET), 0x2d05, 0xffff_ffff, 0xffff_ffff));
            assert_eq!(WRITTEN, (RESOURCE_KIND_DTTM, 0x80aa, [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9], 10));
        }
    }

    #[test]
    fn invalid_mode_passes_zero_selector_to_adjustment() {
        let _guard: MutexGuard<'_, ()> = LOCK.lock();
        let Some(controller) = try_map_u32_slab(hints::DATETIME_ADJUST_AND_STORE_INVALID_MODE, 0x400) else { return };
        unsafe {
            let provider = controller.add(0x280) as *mut ResourceProvider;
            ptr::write_bytes(controller, 0, 0x400);
            (controller.add(ACTIVE_MODE_OFFSET) as *mut u32).write(3);
            (controller.add(RESOURCE_PROVIDER_OFFSET) as *mut u32).write(provider as usize as u32);
            DATETIME_ADJUST = adjust;
            DATETIME_RESOURCE_WRITE = write;
            datetime_adjust_and_store(controller, 4);
            assert_eq!(ADJUST_ARGS.1, 0);
            assert_eq!(ADJUST_ARGS.2, 4);
            assert_eq!(ADJUST_ARGS.3, 4);
        }
    }
}

