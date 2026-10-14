//! Read an opaque observable-array cell's value.
//!
//! Original: `FUN_083d6998` @ `0x083d6998`, true size 24 bytes, ending
//! at the return at `0x083d69ac`; the next getter starts at `0x083d69b0`.
//! Raw A32 words verify zero plain/predicated direct BLs and one BLX through
//! vtable slot +0x40. One inbound plain BL at 0x083d08ac, none predicated.
//! Dispatch the indexed cell accessor with (this, index), then read its first
//! aligned 32-bit word without null checks or value normalization.
//! Deliberate deviation: reuse the pre-destructor's widened host object and
//! vtable representation; ARM retains four-byte pointer words and slot +0x40.

#[cfg(target_os = "none")]
use super::opaque_observable_array_pre_destruct::OpaqueObservableArrayCellAt;
#[cfg(not(target_os = "none"))]
use super::opaque_observable_array_pre_destruct::HostOpaqueObservableArrayPreDestruct;

/// # Safety
/// `this` must have a valid vtable whose +0x40 accessor accepts the index and
/// returns a non-null, aligned, readable u32 cell. No bounds checks are added.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn opaque_observable_array_cell_value(this: *mut u32, index: i32) -> u32 {
    #[cfg(target_os = "none")]
    let cell = unsafe {
        let vtable = this.read() as *const u32;
        let cell_at: OpaqueObservableArrayCellAt =
            core::mem::transmute(vtable.add(0x40 / 4).read() as usize);
        cell_at(this, index)
    };
    #[cfg(not(target_os = "none"))]
    let cell = unsafe {
        let host = this.cast::<HostOpaqueObservableArrayPreDestruct>();
        ((*(*host).vtable).cell_at)(host, index)
    };
    unsafe { cell.read() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::opaque_observable_array_pre_destruct::OpaqueObservableArrayPreDestructVtable;

    #[repr(C)]
    struct Fixture {
        array: HostOpaqueObservableArrayPreDestruct,
        cells: [u32; 5],
        seen_index: i32,
        calls: u32,
    }

    unsafe extern "C" fn cell_at(this: *mut HostOpaqueObservableArrayPreDestruct, index: i32) -> *mut u32 {
        let fixture = unsafe { &mut *this.cast::<Fixture>() };
        fixture.seen_index = index;
        fixture.calls += 1;
        let slot = match index {
            i32::MIN => 0,
            -1 => 1,
            0 => 2,
            1 => 3,
            i32::MAX => 4,
            _ => panic!("unexpected index"),
        };
        // Mutate the selected cell during dispatch: the wrapper must load after it.
        fixture.cells[slot] = fixture.cells[slot].wrapping_add(1);
        &mut fixture.cells[slot]
    }

    #[test]
    fn returns_full_word_after_dispatch_for_signed_index_boundaries() {
        let table = OpaqueObservableArrayPreDestructVtable {
            unresolved_00_3c: [0; 16], cell_at,
        };
        let mut fixture = Fixture {
            array: HostOpaqueObservableArrayPreDestruct {
                vtable: &table, count: 0, unresolved_08_0f: [0; 8], enabled: 0,
            },
            cells: [u32::MAX, 0, 0x7fff_ffff, 0xffff_fffe, 0x1234_5677],
            seen_index: 7, calls: 0,
        };
        for (index, expected) in [
            (i32::MIN, 0), (-1, 1), (0, 0x8000_0000),
            (1, u32::MAX), (i32::MAX, 0x1234_5678),
        ] {
            let result = unsafe {
                opaque_observable_array_cell_value((&mut fixture.array as *mut HostOpaqueObservableArrayPreDestruct).cast(), index)
            };
            assert_eq!(result, expected);
            assert_eq!(fixture.seen_index, index);
        }
        assert_eq!(fixture.calls, 5);
    }
}
