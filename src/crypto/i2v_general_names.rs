//! X.509v3 GENERAL_NAMES configuration-value conversion.

use crate::cxx::object_flags::{namespace_provider_count, namespace_provider_at};
use crate::drivers::ata_cmd::ata_call_with_zero;

/// i2v_general_names — original: `FUN_082d3bfc` @ `0x082d3bfc` (92 bytes,
/// true extent `0x082d3bfc..0x082d3c58`; `smulbb r5,r0,r1` at `0x082d3c5c`
/// starts the next function, so Ghidra's 96-byte extent includes one word of
/// it). Raw A32 decoding finds three plain outbound `bl` instructions
/// (`namespace_provider_at`, `i2v_general_name`, and
/// `namespace_provider_count`) and no predicated `bl` instructions; complete
/// image branch decoding finds two inbound plain `bl` sites and no predicated
/// inbound sites.
///
/// Calls `i2v_GENERAL_NAME` for every GENERAL_NAME in the signed-count
/// provider stack, threading its configuration-value stack result through each
/// call. If the result is NULL, it returns a new empty stack through the
/// existing `ata_call_with_zero` stack-factory port.
///
/// Deliberate deviation: `i2v_GENERAL_NAME` at `0x082d3a30` is not yet ported,
/// so host builds dispatch it through a test seam while target builds call its
/// verified retailOS address directly. Target-width provider fields remain
/// `u32` words; host tests map them below 4 GiB.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn i2v_general_names(
    method: *mut u8,
    names: *const u32,
    mut values: *mut u32,
) -> *mut u32 {
    let mut index = 0i32;
    while (namespace_provider_count(names) as i32) > index {
        let name = namespace_provider_at(names, index as u32) as *const u32;
        values = i2v_general_name(method, name, values);
        index += 1;
    }
    if values.is_null() {
        ata_call_with_zero()
    } else {
        values
    }
}

type I2vGeneralName = unsafe extern "C" fn(*mut u8, *const u32, *mut u32) -> *mut u32;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn i2v_general_name(method: *mut u8, name: *const u32, values: *mut u32) -> *mut u32 {
    let convert: I2vGeneralName = unsafe { core::mem::transmute(0x082d_3a30usize) };
    unsafe { convert(method, name, values) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_i2v_general_name(
    _method: *mut u8,
    _name: *const u32,
    _values: *mut u32,
) -> *mut u32 {
    panic!("i2v_general_names requires i2v_GENERAL_NAME at 0x082d3a30")
}

#[cfg(not(target_os = "none"))]
static mut I2V_GENERAL_NAME: I2vGeneralName = missing_i2v_general_name;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn i2v_general_name(method: *mut u8, name: *const u32, values: *mut u32) -> *mut u32 {
    let convert = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(I2V_GENERAL_NAME)) };
    unsafe { convert(method, name, values) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: [(usize, usize, usize); 2] = [(0, 0, 0); 2];
    static mut CALL_COUNT: usize = 0;

    struct SeamReset(I2vGeneralName);

    impl Drop for SeamReset {
        fn drop(&mut self) {
            unsafe { I2V_GENERAL_NAME = self.0; }
        }
    }

    unsafe extern "C" fn record_conversion(
        method: *mut u8,
        name: *const u32,
        values: *mut u32,
    ) -> *mut u32 {
        CALLS[CALL_COUNT] = (method as usize, name as usize, values as usize);
        CALL_COUNT += 1;
        values
    }

    #[test]
    fn converts_each_name_in_order_and_threads_the_existing_stack() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::I2V_GENERAL_NAMES, 0x1000) else { return; };
        let previous = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(I2V_GENERAL_NAME)) };
        let _reset = SeamReset(previous);
        unsafe {
            I2V_GENERAL_NAME = record_conversion;
            CALL_COUNT = 0;
            let providers = slab.cast::<u32>();
            let entries = slab.add(0x40).cast::<u32>();
            let method = slab.add(0x100);
            let values = slab.add(0x200).cast::<u32>();
            core::ptr::write_unaligned(providers.add(1).cast::<*const u32>(), entries);
            providers.add(0).write(2);
            core::ptr::write_unaligned(entries.cast::<*const u32>(), slab.add(0x300).cast::<u32>());
            core::ptr::write_unaligned(entries.add(2).cast::<*const u32>(), slab.add(0x400).cast::<u32>());

            assert_eq!(i2v_general_names(method, providers, values), values);
            assert_eq!(CALL_COUNT, 2);
            assert_eq!(CALLS[0], (method as usize, slab.add(0x300) as usize, values as usize));
            assert_eq!(CALLS[1], (method as usize, slab.add(0x400) as usize, values as usize));
        }
    }

    #[test]
    fn skips_a_negative_provider_count_and_preserves_existing_values() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::I2V_GENERAL_NAMES_NEGATIVE, 0x1000) else { return; };
        let previous = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(I2V_GENERAL_NAME)) };
        let _reset = SeamReset(previous);
        unsafe {
            I2V_GENERAL_NAME = record_conversion;
            CALL_COUNT = 0;
            let providers = slab.cast::<u32>();
            let values = slab.add(0x200).cast::<u32>();
            providers.write(u32::MAX);

            assert_eq!(i2v_general_names(core::ptr::null_mut(), providers, values), values);
            assert_eq!(CALL_COUNT, 0);
        }
    }
}
