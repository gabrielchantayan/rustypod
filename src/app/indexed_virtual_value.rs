//! `indexed_virtual_value` — original: `FUN_083d69d8` @ `0x083d69d8`.
//!
//! **24 bytes** (`0x083d69d8..0x083d69ec`); `0x083d69f0` starts the next
//! independently entered body. Raw ARM has no direct plain or predicated `bl`
//! instructions and one indirect `blx` through the object's vtable `+0x40`
//! slot. Whole-image decoding finds three incoming plain `bl` calls and no
//! predicated `bl` calls.
//!
//! # Algorithm
//!
//! Call the object's unidentified vtable `+0x40` method with `object` and
//! `index`. That method returns a pointer to a word; return that word. The
//! retail function has no NULL or bounds guards.
//!
//! Deliberate deviation: the vtable method has no established identity. Target
//! builds dispatch through its verified slot; host builds use a typed seam.

#[cfg(not(target_os = "none"))]
use core::ptr::addr_of;

/// Host substitute for the unidentified indexed vtable method.
#[cfg(not(target_os = "none"))]
pub struct IndexedVirtualValueOps {
    pub value_at: unsafe extern "C" fn(*mut u8, i32) -> *const u32,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_value_at(_object: *mut u8, _index: i32) -> *const u32 {
    panic!("install indexed virtual value host operations before calling")
}

#[cfg(not(target_os = "none"))]
pub const DEFAULT_INDEXED_VIRTUAL_VALUE_OPS: IndexedVirtualValueOps = IndexedVirtualValueOps {
    value_at: missing_value_at,
};

#[cfg(not(target_os = "none"))]
pub static mut INDEXED_VIRTUAL_VALUE_OPS: IndexedVirtualValueOps = DEFAULT_INDEXED_VIRTUAL_VALUE_OPS;

/// Return the word selected by an object's vtable `+0x40` method.
///
/// # Safety
///
/// `object` must identify readable storage whose first target-width word is a
/// vtable address. Its `+0x40` entry must be callable with `object` and
/// `index`, and the returned word pointer must be readable. RetailOS checks
/// none of these conditions.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn indexed_virtual_value(object: *mut u8, index: i32) -> u32 {
    #[cfg(target_os = "none")]
    let value = {
        type ValueAt = unsafe extern "C" fn(*mut u8, i32) -> *const u32;
        let vtable = unsafe { object.cast::<u32>().read_volatile() as usize as *const u8 };
        let value_at: ValueAt = unsafe { vtable.add(0x40).cast::<ValueAt>().read_volatile() };
        unsafe { value_at(object, index).read() }
    };
    #[cfg(not(target_os = "none"))]
    let value = {
        let ops = unsafe { core::ptr::read_volatile(addr_of!(INDEXED_VIRTUAL_VALUE_OPS)) };
        unsafe { (ops.value_at)(object, index).read() }
    };
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut EXPECTED_OBJECT: *mut u8 = core::ptr::null_mut();
    static mut EXPECTED_INDEX: i32 = 0;
    static mut VALUE: u32 = 0;
    static mut CALLS: u32 = 0;

    unsafe extern "C" fn value_at(object: *mut u8, index: i32) -> *const u32 {
        unsafe {
            assert_eq!(object, EXPECTED_OBJECT);
            assert_eq!(index, EXPECTED_INDEX);
            CALLS += 1;
            core::ptr::addr_of!(VALUE)
        }
    }

    fn install(object: *mut u8, index: i32, value: u32) {
        unsafe {
            EXPECTED_OBJECT = object;
            EXPECTED_INDEX = index;
            VALUE = value;
            CALLS = 0;
            INDEXED_VIRTUAL_VALUE_OPS = IndexedVirtualValueOps { value_at };
        }
    }

    #[test]
    fn forwards_object_and_index_to_the_vtable_slot() {
        let _guard = TEST_LOCK.lock();
        let mut object = [0u32; 1];
        install(object.as_mut_ptr().cast(), 7, 0xc001_d00d);

        assert_eq!(unsafe { indexed_virtual_value(object.as_mut_ptr().cast(), 7) }, 0xc001_d00d);
        assert_eq!(unsafe { CALLS }, 1);
    }

    #[test]
    fn returns_zero_when_the_selected_word_is_zero() {
        let _guard = TEST_LOCK.lock();
        let mut object = [0u32; 1];
        install(object.as_mut_ptr().cast(), -1, 0);

        assert_eq!(unsafe { indexed_virtual_value(object.as_mut_ptr().cast(), -1) }, 0);
        assert_eq!(unsafe { CALLS }, 1);
    }
}
