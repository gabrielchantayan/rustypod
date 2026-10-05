//! Refresh collection value statistics.
//!
//! Original FUN_081d111c at 0x081d111c, 156 bytes through 0x081d11b8.
//! Raw A32 decoding verifies two inbound plain BLs (0x0815e660, 0x081d0dc0),
//! zero predicated BLs; outgoing one plain BL to __rt_udiv and one BLX r2.
//! Initialize maximum (+0x14), minimum (+0x18), and average (+0x1c); snapshot
//! signed count (+0x34). Query embedded collection (+0x30) via vtable +0x40
//! for each nonnegative index below count. Returned slots hold nullable u32
//! value pointers. Non-null values update unsigned extrema and wrapping sum.
//! Divide sum by the full count, including null entries; only count zero
//! resets minimum to zero. Negative counts skip iteration but still divide
//! by their unsigned bit pattern. No target behavioral deviations.
//! Host deviation: vtable function addresses use native usize width at the
//! same byte offset; object and value pointers remain target-width u32.

use crate::runtime::rt_div::__rt_udiv;

/// # Safety
/// `owner` must provide 14 aligned readable/writable u32 words. For positive
/// counts its collection vtable +0x40 must contain a callable native function
/// address with signature `unsafe extern "C" fn(*mut u32, i32) -> *const u32`.
/// Each returned slot must be readable and its nonzero u32 address must point
/// to a readable aligned value. The callback must leave the owner valid.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_value_statistics_refresh(owner: *mut u32) {
    owner.add(5).write(0);
    owner.add(6).write(u32::MAX);
    owner.add(7).write(0);
    let count = owner.add(13).read() as i32;
    let mut index = 0i32;
    while index < count {
        let vtable = owner.add(12).read() as usize as *const u8;
        let entry = vtable.add(0x40).cast::<usize>().read();
        let get_slot: unsafe extern "C" fn(*mut u32, i32) -> *const u32 =
            core::mem::transmute(entry);
        let value = get_slot(owner.add(12), index).read() as usize as *const u32;
        if !value.is_null() {
            let value = value.read();
            owner.add(7).write(owner.add(7).read().wrapping_add(value));
            if value < owner.add(6).read() {
                owner.add(6).write(value);
            }
            if owner.add(5).read() < value {
                owner.add(5).write(value);
            }
        }
        index += 1;
    }
    if count == 0 {
        owner.add(6).write(0);
    } else {
        owner.add(7).write(__rt_udiv(owner.add(7).read(), count as u32));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    unsafe extern "C" fn get_slot(collection: *mut u32, index: i32) -> *const u32 {
        // The test collection uses its third word as an extra backing pointer.
        let slots = collection.add(2).read() as usize as *const u32;
        assert!(index >= 0 && index < collection.add(1).read() as i32);
        slots.add(index as usize)
    }
    extern crate std;

    #[test]
    fn extrema_null_slots_wrapping_sum_and_signed_count() {
        let Some(slab) = try_map_u32_slab(hints::COLLECTION_VALUE_STATISTICS_REFRESH, 0x1000) else {
            assert!(note_missing_u32_fixture("app/collection_value_statistics_refresh"));
            return;
        };
        unsafe {
            let table = slab;
            table.add(0x40).cast::<usize>().write(get_slot as *const () as usize);
            let slots = slab.add(0x100).cast::<u32>();
            let values = slab.add(0x200).cast::<u32>();
            let cases: &[&[Option<u32>]] = &[
                &[], &[None], &[None, None], &[Some(0)], &[Some(u32::MAX)],
                &[Some(12), None, Some(3)], &[Some(u32::MAX), Some(2)],
                &[Some(0x8000_0000), Some(0x7fff_ffff), Some(0)],
                &[Some(9), Some(9), Some(9)],
            ];
            for case in cases {
                let mut owner = [0x1357_2468u32; 15];
                owner[12] = table as usize as u32;
                owner[13] = case.len() as u32;
                owner[14] = slots as usize as u32;
                for (i, value) in case.iter().enumerate() {
                    values.add(i).write(value.unwrap_or(0));
                    slots.add(i).write(if value.is_some() { values.add(i) as usize as u32 } else { 0 });
                }
                let before = owner;
                collection_value_statistics_refresh(owner.as_mut_ptr());
                let present: std::vec::Vec<u32> = case.iter().filter_map(|v| *v).collect();
                let max = present.iter().copied().max().unwrap_or(0);
                let min = if case.is_empty() { 0 } else { present.iter().copied().min().unwrap_or(u32::MAX) };
                let sum = present.iter().map(|&v| v as u64).sum::<u64>() as u32;
                let average = if case.is_empty() { 0 } else { sum / case.len() as u32 };
                assert_eq!(&owner[5..8], &[max, min, average], "{case:?}");
                for i in (0..5).chain(8..15) { assert_eq!(owner[i], before[i]); }
            }
            for count in [i32::MIN, -1] {
                let mut owner = [0u32; 14]; // Invalid vtable proves no iteration.
                owner[13] = count as u32;
                collection_value_statistics_refresh(owner.as_mut_ptr());
                assert_eq!(&owner[5..8], &[0, u32::MAX, 0]);
            }
        }
    }
}
