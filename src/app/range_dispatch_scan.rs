//! `range_dispatch_scan` — `FUN_081b4e2c` @ 0x081b4e2c.
//! True extent: 176 bytes, ending at 0x081b4edc (next function's push).
//! Raw A32: two outgoing plain BLs, zero predicated BLs, one indirect BLX;
//! two incoming plain BLs at 0x08155fac/0x08155fec, zero predicated BLs.
//!
//! Walk from *start to the live exclusive *end by a wrapping signed step.
//! Construct a range state with resolution 1 and dispatch vtable slot 5.
//! Only successful dispatches advance the accumulated displacement. At the
//! context's marker, return 1 if that displacement belongs to its collection;
//! otherwise continue and return 0 on reaching the exclusive endpoint.
//!
//! Deviations: reuse the ported range constructor; retain the verified stock
//! membership routine at 0x08155ef0. Host execution of that unported boundary
//! panics. Tests inject operations into the same traversal core. Target object
//! fields remain u32 words, not host-sized pointer fields. No extra guards.

use crate::util::range_state::{range_state_construct, RangeState};

#[inline(always)]
unsafe fn scan(
    start: *const u32,
    end: *const u32,
    step: u32,
    mut dispatch: impl FnMut(*mut u32) -> i32,
    mut marker: impl FnMut() -> u32,
    mut contains: impl FnMut(u32) -> i32,
) -> i32 {
    let mut position = start.read();
    let mut displacement = 0u32;
    while position != end.read_volatile() {
        if dispatch(&mut position) != 0 {
            displacement = displacement.wrapping_add(step);
            if marker() == position && contains(displacement) != 0 {
                return 1;
            }
        }
        position = position.wrapping_add(step);
    }
    0
}

#[inline(always)]
unsafe fn displacement_present(collection: *mut u8, displacement: u32) -> i32 {
    #[cfg(target_os = "none")]
    {
        let contains: unsafe extern "C" fn(*mut u8, u32) -> i32 =
            core::mem::transmute(0x0815_5ef0usize);
        contains(collection, displacement)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (collection, displacement);
        panic!("range_dispatch_scan requires retail membership routine 0x08155ef0")
    }
}

/// # Safety
/// `context` must be a writable aligned 140-byte retail context with valid
/// u32 pointer words at +0x40/+0x44 and a callable vtable slot 5 on its
/// dispatch receiver. Start/end must be readable aligned words. All callbacks
/// must obey the retail ABI; traversal must eventually reach end or succeed.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn range_dispatch_scan(
    context: *mut u32, start: *const u32, end: *const u32, step: u32,
) -> i32 {
    let mut state = core::mem::MaybeUninit::<RangeState>::uninit();
    scan(start, end, step, |position| {
        range_state_construct(state.as_mut_ptr(), position, 1);
        let argument = context.add(0x88 / 4).read_volatile();
        let receiver = context.add(0x44 / 4).read_volatile() as usize as *mut u32;
        let table = receiver.read() as usize as *const u32;
        let dispatch: unsafe extern "C" fn(*mut u32, *mut u32, *mut RangeState, u32, u32) -> i32 =
            core::mem::transmute(table.add(5).read() as usize);
        dispatch(receiver, context, state.as_mut_ptr(), 1, argument)
    }, || context.add(0x48 / 4).read_volatile(), |displacement| {
        let collection = context.add(0x40 / 4).read_volatile() as usize as *mut u8;
        displacement_present(collection, displacement)
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::scan;
    use core::cell::Cell;

    #[test]
    fn empty_range_never_dispatches() {
        let value = 7;
        assert_eq!(unsafe { super::range_dispatch_scan(core::ptr::null_mut(),
            &value, &value, 1) }, 0);
        assert_eq!(unsafe { scan(&value, &value, 1, |_| panic!("dispatch"),
            || panic!("marker"), |_| panic!("contains")) }, 0);
    }

    #[test]
    fn failed_dispatch_does_not_count_and_membership_requires_marker() {
        let mut visited = std::vec::Vec::new();
        let mut queried = std::vec::Vec::new();
        let marker = Cell::new(0);
        let result = unsafe { scan(&1, &5, 1, |position| {
            let p = position.read();
            visited.push(p);
            marker.set(p);
            if p == 2 { 0 } else { -1 }
        }, || if marker.get() == 3 { 99 } else { marker.get() }, |d| {
            queried.push(d);
            if d == 3 { -7 } else { 0 }
        }) };
        assert_eq!(result, 1);
        assert_eq!(visited, [1, 2, 3, 4]);
        assert_eq!(queried, [1, 3]);
    }

    #[test]
    fn reverse_and_wrapping_steps_stop_at_exclusive_end() {
        for (start, end, step, expected) in [
            (2, u32::MAX, u32::MAX, std::vec![2, 1, 0]),
            (u32::MAX, 1, 1, std::vec![u32::MAX, 0]),
        ] {
            let mut visited = std::vec::Vec::new();
            let mut sums = std::vec::Vec::new();
            let position = Cell::new(0);
            let result = unsafe { scan(&start, &end, step, |p| {
                let value = p.read(); visited.push(value); position.set(value); 1
            }, || position.get(), |d| { sums.push(d); 0 }) };
            assert_eq!(result, 0);
            assert_eq!(visited, expected);
            let expected_sums: std::vec::Vec<_> = (1..=expected.len())
                .map(|n| (n as u32).wrapping_mul(step)).collect();
            assert_eq!(sums, expected_sums);
        }
    }

    #[test]
    fn callback_updates_position_and_live_endpoint() {
        let end = Cell::new(10u32);
        let mut visited = std::vec::Vec::new();
        let result = unsafe { scan(&1, end.as_ptr(), 1, |p| {
            visited.push(p.read()); p.write(8); end.set(9); 0
        }, || panic!("marker"), |_| panic!("contains")) };
        assert_eq!(result, 0);
        assert_eq!(visited, [1]);
    }
}
