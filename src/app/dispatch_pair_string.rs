//! Composite dispatch-selector string writer — FUN_08187d98 @ 0x08187d98.
//! True extent: 128 bytes through 0x08187e18 (124 code bytes and four
//! literal bytes containing " \0"); next function starts at 0x08187e18.
//! Raw words verify four plain BLs, zero predicated BLs, two virtual BLXs.
//! Whole-image incoming BL census: two plain calls, zero predicated calls.
//! Resolve owner+0x18, invoke vtable slot 33 with selector 9, append a space,
//! measure twice, then invoke freshly loaded slot 33 with selector 17 at
//! the terminator and wrapping remaining capacity. No bounds/NULL guard.
//! Deviation: native-width vtable pointers on hosts; owner+0x18 remains u32.
//! Selector meanings and concrete target class are not recovered.

//! ARM codegen inlines strcat's space copy and shares the two post-append
//! length measurements; without an intervening write their result is equal.
//! Both virtual calls, selector values and vtable reload are retained.
use super::object_dispatch_target::object_dispatch_target;
use crate::libc::strcat::strcat;
use crate::libc::strlen::strlen;

type WriteSelector = unsafe extern "C" fn(*mut DispatchStringTarget, *mut u8, u32, u32, *const u8);
#[repr(C)]
pub struct DispatchStringTarget {
    pub vtable: *const usize,
}

/// Write selectors 9 and 17 separated by a single space.
/// # Safety
/// Owner+0x18 must contain a live target with a callable vtable slot 33.
/// Source must satisfy that virtual method's contract. Destination must
/// accommodate both results, a space and NUL, even when capacity is zero
/// or wraps after subtraction: stock does not constrain strcat by capacity.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn dispatch_pair_string(
    owner: *mut u8, source: *const u8, destination: *mut u8, capacity: u32,
) {
    let target = object_dispatch_target(owner) as usize as *mut DispatchStringTarget;
    let first: WriteSelector = core::mem::transmute((*target).vtable.add(33).read());
    first(target, destination, capacity, 9, source);
    strcat(destination, b" \0".as_ptr());
    let remaining = capacity.wrapping_sub(strlen(destination) as u32);
    let end = destination.wrapping_add(strlen(destination));
    let second: WriteSelector = core::mem::transmute((*target).vtable.add(33).read());
    second(target, end, remaining, 17, source);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[repr(C)]
    struct Fixture {
        target: DispatchStringTarget,
        second_table: *const usize,
        remaining: u32,
        first_capacity: u32,
    }
    unsafe extern "C" fn first(p: *mut DispatchStringTarget, dst: *mut u8, cap: u32, selector: u32, src: *const u8) {
        assert_eq!(selector, 9);
        let f = &mut *p.cast::<Fixture>();
        f.first_capacity = cap;
        let mut i = 0;
        while src.add(i).read() != 0 {
            dst.add(i).write(src.add(i).read()); i += 1;
        }
        dst.add(i).write(0);
        f.target.vtable = f.second_table;
    }
    unsafe extern "C" fn second(p: *mut DispatchStringTarget, dst: *mut u8, cap: u32, selector: u32, _: *const u8) {
        assert_eq!(selector, 17);
        (*p.cast::<Fixture>()).remaining = cap;
        dst.write(b'!'); dst.add(1).write(0);
    }
    #[test]
    fn joins_empty_and_nonempty_results_reloads_vtable_and_wraps_capacity() {
        let Some(slab) = crate::testing::try_map_u32_slab(
            crate::testing::hints::DISPATCH_PAIR_STRING, 4096,
        ) else { return; };
        let mut first_table = [0usize; 34]; first_table[33] = first as *const () as usize;
        let mut second_table = [0usize; 34]; second_table[33] = second as *const () as usize;
        unsafe {
            let f = slab.add(64).cast::<Fixture>();
            slab.cast::<u32>().add(6).write(f as usize as u32);
            for source in [b"\0".as_slice(), b"abc\0".as_slice()] {
                for capacity in [0, 1, 4, 40, u32::MAX] {
                    f.write(Fixture { target: DispatchStringTarget { vtable: first_table.as_ptr() },
                        second_table: second_table.as_ptr(), remaining: 0, first_capacity: 0 });
                    let mut out = [0xa5; 16];
                    dispatch_pair_string(slab, source.as_ptr(), out.as_mut_ptr(), capacity);
                    let n = source.len() - 1;
                    assert_eq!(&out[..n], &source[..n]);
                    assert_eq!(&out[n..n+3], b" !\0");
                    assert_eq!(out[n+3], 0xa5);
                    assert_eq!((*f).first_capacity, capacity);
                    assert_eq!((*f).remaining, capacity.wrapping_sub((n+1) as u32));
                }
            }
            ptr::drop_in_place(f);
        }
    }
}
