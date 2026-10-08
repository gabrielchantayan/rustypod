//! Complete-object Coverflow constructor — `FUN_08142d84` @ `0x08142d84`.
//!
//! True extent [0x08142d84,0x08142dac): 40 bytes, ten A32 words;
//! the next entry starts with push {r4,r5,r6,r7,r8,lr}. Two incoming
//! plain BLs (0x081423d0,0x081dfef0), zero predicated BLs. One outgoing
//! plain BL to 0x08142dac, zero predicated BLs. Insert a NULL construction
//! table between storage and the four opaque constructor arguments. Return
//! the callee's r0 unchanged, unlike Ghidra's inferred void signature.
//! The callee initializes a view named "Coverflow" and uses its default
//! construction table when NULL is supplied. No target behavioral deviations;
//! the unported constructor remains at its verified retail address. Host use
//! requires an explicit constructor implementation, never a no-op fallback.

pub type CoverflowConstructor = unsafe extern "C" fn(
    *mut u8, *const u32, u32, u32, u32, *const u8,
) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_constructor(
    _storage: *mut u8, _table: *const u32, _argument: u32,
    _first: u32, _second: u32, _descriptor: *const u8,
) -> *mut u8 {
    panic!("Coverflow constructor at 0x08142dac requires a host implementation")
}

#[cfg(not(target_os = "none"))]
pub static mut COVERFLOW_CONSTRUCTOR: CoverflowConstructor = unavailable_constructor;

/// # Safety
/// Storage and all opaque arguments must satisfy retail constructor 0x08142dac.
/// Host callers must install a compatible constructor under external synchronization.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn coverflow_construct(
    storage: *mut u8, argument: u32, first: u32, second: u32, descriptor: *const u8,
) -> *mut u8 {
    #[cfg(target_os = "none")]
    let construct: CoverflowConstructor = core::mem::transmute(0x0814_2dacusize);
    #[cfg(not(target_os = "none"))]
    let construct = core::ptr::addr_of!(COVERFLOW_CONSTRUCTOR).read();
    construct(storage, core::ptr::null(), argument, first, second, descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal constructor model: NULL selects the default construction table.
    unsafe extern "C" fn construct_model(
        storage: *mut u8, table: *const u32, argument: u32,
        first: u32, second: u32, descriptor: *const u8,
    ) -> *mut u8 {
        let words = storage.cast::<u32>();
        words.write(if table.is_null() { 0xc0fe_0001 } else { table.read() });
        words.add(1).write(argument);
        words.add(2).write(first);
        words.add(3).write(second);
        words.add(4).write(if descriptor.is_null() { 0 } else { descriptor.read() as u32 });
        storage.add(4)
    }

    #[test]
    fn complete_construction_selects_default_table_and_preserves_adjusted_return() {
        unsafe {
            let saved = COVERFLOW_CONSTRUCTOR;
            COVERFLOW_CONSTRUCTOR = construct_model;
            for (argument, first, second) in [(0, 0, 0), (u32::MAX, 0x8000_0000, 1), (1, 2, u32::MAX)] {
                for descriptor in [core::ptr::null(), &0xa5u8 as *const u8] {
                    let mut storage = [0xdead_beefu32; 7];
                    let object = storage.as_mut_ptr().add(1).cast::<u8>();
                    let result = coverflow_construct(object, argument, first, second, descriptor);
                    assert_eq!(result, object.add(4));
                    assert_eq!(storage, [0xdead_beef, 0xc0fe_0001, argument, first, second,
                        if descriptor.is_null() { 0 } else { 0xa5 }, 0xdead_beef]);
                }
            }
            COVERFLOW_CONSTRUCTOR = saved;
        }
    }
}
