//! SCSI MODE SENSE page 6 (rigid disk geometry).
//!
//! Original FUN_080fb2e4 @ 0x080fb2e4, true extent
//! [0x080fb2e4, 0x080fb390): 172 instruction bytes, no literals, followed
//! by a new function push. Raw A32 decoding finds two plain incoming BLs
//! (0x080fb11c, 0x080fb1f0), zero predicated incoming BLs, zero outgoing
//! plain/predicated BLs and three register BLX calls (+0x28, +0x24, +0x5c).
//! Caller 0x080faec0 selects page 6 or all pages (0x3f).
//!
//! Query slots +0x28 then +0x24; write 86 0b 01, the low 16 bits of
//! the second result big-endian, zero, and the first result big-endian.
//! Query +0x5c after those writes, store its low byte, then 02 00.
//! Reload the receiver's object and its vtable before every query. Always
//! write thirteen bytes; unsigned lengths <=13 return length+1, else 13.
//! Concrete virtual method identities remain unresolved: no address seams.
//! Deliberate deviations: repr(C) pointer fields and vtable entries widen
//! on hosts while preserving target word indices. Volatile accesses retain
//! receiver reloads and the original byte store order; no behavioral changes.

use core::ptr;

#[repr(C)]
pub struct GeometryPageVtable {
    pub reserved_00_20: [usize; 9],
    pub query_slot_24: unsafe extern "C" fn(*mut GeometryPageObject) -> u32,
    pub query_slot_28: unsafe extern "C" fn(*mut GeometryPageObject) -> u32,
    pub reserved_2c_58: [usize; 12],
    pub query_slot_5c: unsafe extern "C" fn(*mut GeometryPageObject) -> u32,
}

#[repr(C)]
pub struct GeometryPageObject {
    pub vtable: *const GeometryPageVtable,
}

#[repr(C)]
pub struct GeometryPageReceiver {
    pub object: *mut GeometryPageObject,
}

/// # Safety
/// Receiver, each dynamically selected object/vtable and its three query
/// methods must be valid. Output must be writable for thirteen bytes even
/// when requested_length is smaller. Queries may replace the receiver object.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn scsi_geometry_page_write(
    receiver: *const GeometryPageReceiver,
    output: *mut u8,
    requested_length: u32,
) -> u32 {
    let object = ptr::read_volatile(ptr::addr_of!((*receiver).object));
    let vtable = ptr::read_volatile(ptr::addr_of!((*object).vtable));
    let first = ((*vtable).query_slot_28)(object);
    let object = ptr::read_volatile(ptr::addr_of!((*receiver).object));
    let vtable = ptr::read_volatile(ptr::addr_of!((*object).vtable));
    let second = ((*vtable).query_slot_24)(object);
    ptr::write_volatile(output, 0x86);
    ptr::write_volatile(output.add(1), 11);
    ptr::write_volatile(output.add(2), 1);
    ptr::write_volatile(output.add(3), (second >> 8) as u8);
    ptr::write_volatile(output.add(4), second as u8);
    ptr::write_volatile(output.add(5), 0);
    ptr::write_volatile(output.add(6), (first >> 24) as u8);
    ptr::write_volatile(output.add(7), (first >> 16) as u8);
    ptr::write_volatile(output.add(8), (first >> 8) as u8);
    ptr::write_volatile(output.add(9), first as u8);
    let object = ptr::read_volatile(ptr::addr_of!((*receiver).object));
    let vtable = ptr::read_volatile(ptr::addr_of!((*object).vtable));
    let third = ((*vtable).query_slot_5c)(object);
    ptr::write_volatile(output.add(10), third as u8);
    ptr::write_volatile(output.add(11), 2);
    ptr::write_volatile(output.add(12), 0);
    if requested_length <= 13 { requested_length + 1 } else { 13 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        object: GeometryPageObject,
        receiver: *mut GeometryPageReceiver,
        next: *mut GeometryPageObject,
        output: *mut u8,
        value: u32,
        stage: u32,
    }

    unsafe extern "C" fn first(object: *mut GeometryPageObject) -> u32 {
        let fixture = &mut *object.cast::<Fixture>();
        assert_eq!(fixture.stage, 0);
        assert_eq!(*fixture.output, 0xa5);
        fixture.stage = 1;
        (*fixture.receiver).object = fixture.next;
        fixture.value
    }

    unsafe extern "C" fn second(object: *mut GeometryPageObject) -> u32 {
        let fixture = &mut *object.cast::<Fixture>();
        assert_eq!(fixture.stage, 0);
        assert_eq!(*fixture.output, 0xa5);
        fixture.stage = 2;
        (*fixture.receiver).object = fixture.next;
        fixture.value
    }

    unsafe extern "C" fn third(object: *mut GeometryPageObject) -> u32 {
        let fixture = &mut *object.cast::<Fixture>();
        assert_eq!(fixture.stage, 0);
        assert_eq!(core::slice::from_raw_parts(fixture.output, 3), &[0x86, 11, 1]);
        assert_eq!(*fixture.output.add(10), 0xa5);
        assert_eq!(*fixture.output.add(11), 0xa5);
        assert_eq!(*fixture.output.add(12), 0xa5);
        fixture.stage = 3;
        fixture.value
    }

    #[test]
    fn reloads_objects_and_writes_full_big_endian_page_for_all_lengths() {
        let vtable = GeometryPageVtable {
            reserved_00_20: [0; 9], query_slot_24: second, query_slot_28: first,
            reserved_2c_58: [0; 12], query_slot_5c: third,
        };
        for alignment in 0..4 {
            for length in (0..=15).chain([0x7fff_ffff, 0x8000_0000, u32::MAX]) {
                for values in [[0x12345678, 0xabcd9876, 0x76543210], [0, 0, 0], [u32::MAX; 3]] {
                    let mut storage = [0xa5; 24];
                    let start = 4 + alignment;
                    let output = unsafe { storage.as_mut_ptr().add(start) };
                    let mut receiver = GeometryPageReceiver { object: ptr::null_mut() };
                    let mut fixtures = values.map(|value| Fixture {
                        object: GeometryPageObject { vtable: &vtable }, receiver: &mut receiver,
                        next: ptr::null_mut(), output, value, stage: 0,
                    });
                    fixtures[0].next = &mut fixtures[1].object;
                    fixtures[1].next = &mut fixtures[2].object;
                    receiver.object = &mut fixtures[0].object;
                    let result = unsafe { scsi_geometry_page_write(&receiver, output, length) };
                    let first_bytes = values[0].to_be_bytes();
                    let second_bytes = (values[1] as u16).to_be_bytes();
                    assert_eq!(&storage[start..start + 13], &[
                        0x86, 11, 1, second_bytes[0], second_bytes[1], 0,
                        first_bytes[0], first_bytes[1], first_bytes[2], first_bytes[3],
                        values[2] as u8, 2, 0,
                    ]);
                    assert_eq!(result, if length < 14 { length + 1 } else { 13 });
                    assert_eq!(fixtures.map(|fixture| fixture.stage), [1, 2, 3]);
                    assert!(storage[..start].iter().all(|&byte| byte == 0xa5));
                    assert!(storage[start + 13..].iter().all(|&byte| byte == 0xa5));
                }
            }
        }
    }
}
