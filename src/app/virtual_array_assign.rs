//! Virtual array assignment — `FUN_08271d88` @ `0x08271d88`, 92 bytes.
//!
//! Raw extent ends at the next PUSH at 0x08271de4. Whole-image ARM decoding
//! finds two incoming plain BLs (0x081376cc, 0x081376d8), no predicated BLs.
//! The body has one plain BL, no predicated BLs, and two plain indirect BLXs.
//! Dispatch slot +0xbc with the source count, reload and store that count,
//! dispatch the current vtable's +0x18 slot for element width, memmove the
//! wrapping 32-bit count * width bytes, clear word +0x0c, and return self.
//! The direct veneer at 0x08037e00 contains E51FF004, 220000D4: the IRAM
//! mirror of the existing memmove port at 0x080000d4, reused here.
//! Slot roles are inferred from data flow, not concrete callee identities.
//! Deliberate deviation: repr(C) native pointer fields/slots widen on hosts;
//! on ARM the object words and virtual slots retain their exact offsets.

use core::ptr::{addr_of, addr_of_mut};

#[repr(C)]
pub struct VirtualArray {
    pub vtable: *const VirtualArrayVtable,
    pub count: u32,
    pub data: *mut u8,
    pub state: u32,
}

#[repr(C)]
pub struct VirtualArrayVtable {
    pub unresolved_00_14: [usize; 6],
    pub element_width: unsafe extern "C" fn(*mut VirtualArray) -> u32,
    pub unresolved_1c_b8: [usize; 40],
    pub prepare_count: unsafe extern "C" fn(*mut VirtualArray, u32),
}

/// # Safety
/// Both objects and destination virtual entries must be valid. The prepared
/// data buffers must support memmove for the wrapping product of count and
/// width. Callbacks may update fields/vtables; those changes are reloaded.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn virtual_array_assign(
    destination: *mut VirtualArray,
    source: *const VirtualArray,
) -> *mut VirtualArray {
    let table = addr_of!((*destination).vtable).read();
    ((*table).prepare_count)(destination, addr_of!((*source).count).read());
    addr_of_mut!((*destination).count).write(addr_of!((*source).count).read());
    let table = addr_of!((*destination).vtable).read();
    let width = ((*table).element_width)(destination);
    let bytes = width.wrapping_mul(addr_of!((*destination).count).read());
    crate::libc::memmove::memmove(
        addr_of!((*destination).data).read(),
        addr_of!((*source).data).read(),
        bytes as usize,
    );
    addr_of_mut!((*destination).state).write(0);
    destination
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        array: VirtualArray,
        width: u32,
        expected_count: u32,
        calls: u32,
    }

    unsafe extern "C" fn prepare(array: *mut VirtualArray, count: u32) {
        let fixture = &mut *array.cast::<Fixture>();
        assert_eq!(count, fixture.expected_count);
        fixture.calls = 1;
        fixture.array.count = 0xdead_beef;
        fixture.array.vtable = &READY;
    }

    unsafe extern "C" fn width(array: *mut VirtualArray) -> u32 {
        let fixture = &mut *array.cast::<Fixture>();
        assert_eq!(fixture.calls, 1);
        assert_eq!(fixture.array.count, fixture.expected_count);
        fixture.calls = 2;
        fixture.width
    }

    unsafe extern "C" fn stale_width(_: *mut VirtualArray) -> u32 {
        panic!("assignment failed to reload the vtable")
    }

    static INITIAL: VirtualArrayVtable = VirtualArrayVtable {
        unresolved_00_14: [0; 6], element_width: stale_width,
        unresolved_1c_b8: [0; 40], prepare_count: prepare,
    };
    static READY: VirtualArrayVtable = VirtualArrayVtable {
        unresolved_00_14: [0; 6], element_width: width,
        unresolved_1c_b8: [0; 40], prepare_count: prepare,
    };

    #[test]
    fn copies_scaled_ranges_including_overlap_and_preserves_padding() {
        for &(count, width) in &[(0, 4), (1, 1), (3, 4), (17, 2)] {
            for &(src, dst) in &[(0, 48), (8, 11), (11, 8), (8, 8)] {
                let mut data = [0u8; 128];
                for (i, byte) in data.iter_mut().enumerate() { *byte = i as u8; }
                let mut expected = data;
                expected.copy_within(src..src + (count * width) as usize, dst);
                let source = VirtualArray { vtable: core::ptr::null(), count,
                    data: unsafe { data.as_mut_ptr().add(src) }, state: 99 };
                let mut destination = Fixture {
                    array: VirtualArray { vtable: &INITIAL, count: 77,
                        data: unsafe { data.as_mut_ptr().add(dst) }, state: u32::MAX },
                    width, expected_count: count, calls: 0,
                };
                let result = unsafe { virtual_array_assign(&mut destination.array, &source) };
                assert_eq!(result, &mut destination.array as *mut _);
                assert_eq!(data, expected);
                assert_eq!(destination.array.count, count);
                assert_eq!(destination.array.state, 0);
                assert_eq!(source.state, 99);
                assert_eq!(destination.calls, 2);
            }
        }
    }

    #[test]
    fn wrapping_product_and_self_assignment() {
        for &(count, element_width) in &[(0x8000_0000, 2), (7, 0)] {
            let mut fixture = Fixture {
                array: VirtualArray { vtable: &INITIAL, count,
                    data: core::ptr::null_mut(), state: 123 },
                width: element_width, expected_count: count, calls: 0,
            };
            let object = &mut fixture.array as *mut VirtualArray;
            let source = VirtualArray { vtable: core::ptr::null(), count,
                data: core::ptr::null_mut(), state: 99 };
            assert_eq!(unsafe { virtual_array_assign(object, &source) }, object);
            assert_eq!(fixture.array.count, count);
            assert_eq!(fixture.array.state, 0);
        }
        let mut data = [1u8; 16];
        let mut fixture = Fixture {
            array: VirtualArray { vtable: &INITIAL, count: 3,
                data: data.as_mut_ptr(), state: 123 },
            width: 0, expected_count: 3, calls: 0,
        };
        // Aliasing requires the count reload to observe prepare's mutation.
        unsafe extern "C" fn self_width(array: *mut VirtualArray) -> u32 {
            assert_eq!((*array).count, 0xdead_beef);
            0
        }
        unsafe extern "C" fn self_prepare(array: *mut VirtualArray, count: u32) {
            assert_eq!(count, 3);
            (*array).count = 0xdead_beef;
        }
        let table = VirtualArrayVtable { unresolved_00_14: [0; 6],
            element_width: self_width, unresolved_1c_b8: [0; 40],
            prepare_count: self_prepare };
        fixture.array.vtable = &table;
        let object = &mut fixture.array as *mut VirtualArray;
        assert_eq!(unsafe { virtual_array_assign(object, object) }, object);
        assert_eq!(fixture.array.count, 0xdead_beef);
        assert_eq!(fixture.array.state, 0);
        assert_eq!(data, [1; 16]);
    }
}
