//! Port of the ARM ADS 1.0.1 qsort from osos.
//!
//! Originals:
//! - `qsort` @ 0x08030cd4 (256 bytes, 7 callers): public entry. Returns
//!   immediately when `size == 0`; runs `qsort_inner` only when
//!   `count > 10`; ALWAYS finishes with a straight insertion sort over the
//!   whole array — this pass is an integral part of the algorithm, it
//!   repairs the partitions of <= 10 elements that `qsort_inner`
//!   deliberately leaves unsorted.
//! - `qsort_inner` @ 0x08030998 (828 bytes): median-of-three quicksort
//!   with an explicit 32-entry recursion stack (base/count pairs in the
//!   260-byte frame) instead of recursion. The median is stashed just
//!   below the last element and used as pivot; lo/last act as sentinels
//!   so the partition scans cannot run off the ends. The larger half is
//!   pushed on the stack, the smaller half is processed by looping;
//!   partitions of <= 10 elements are abandoned to the final insertion
//!   sort.
//!
//! The port mirrors the original algorithm, including two of its quirks:
//! - after partitioning, the "left" count is `pivot_index - 1` and the
//!   "right" range starts AT the pivot position, so the element just left
//!   of the pivot is skipped by the quicksort phase (the final insertion
//!   sort fixes it);
//! - element swaps use a word-at-a-time path only when both `size` and the
//!   element pointer are word-aligned (the original's `(size|ptr)&3`
//!   test), byte-at-a-time otherwise — elements may be unaligned, and no
//!   memcpy helper is ever called.
//!
//! Deliberate deviations:
//! - the original computes the pivot index as `(i - lo) / size` via a call
//!   to `__rt_udiv` @ 0x08036f14; the port tracks the index incrementally
//!   during the partition scan to avoid a `__aeabi_uidiv` dependency.
//!   Semantics are identical.
//! - `qsort` returns early on `count == 0` (the original relies on
//!   `last = base - size` comparing above `base`, which a degenerate
//!   null-ish base would violate). No effect for any real array.
//!
//! What must (and does) match exactly: the comparison-callback convention
//! (`extern "C" fn(*const u8, *const u8) -> i32`, negative/zero/positive,
//! called with pointers to whole elements) and the final sorted order.

/// Swap `size` bytes at `a` and `b`. Word-at-a-time when both `size` and
/// the pointer are word-aligned (all elements share the same alignment
/// when `size % 4 == 0`, so testing one pointer suffices, as in the
/// original); byte-at-a-time otherwise.
unsafe fn swap_elements(a: *mut u8, b: *mut u8, size: usize) {
    if (size | a as usize) & 3 == 0 {
        let mut wa = a as *mut u32;
        let mut wb = b as *mut u32;
        let mut words = size / 4;
        while words > 0 {
            let tmp = wa.read();
            wa.write(wb.read());
            wb.write(tmp);
            wa = wa.add(1);
            wb = wb.add(1);
            words -= 1;
        }
    } else {
        let mut k = 0;
        while k < size {
            let tmp = *a.add(k);
            *a.add(k) = *b.add(k);
            *b.add(k) = tmp;
            k += 1;
        }
    }
}

/// qsort_inner — original: `FUN_08030998` @ 0x08030998 (828 bytes).
///
/// Median-of-three quicksort with explicit stack, leaving partitions of
/// <= 10 elements unsorted. Only called from `qsort` (with `count > 10`),
/// which runs the finishing insertion sort; the contract is the same as
/// `qsort`'s.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn qsort_inner(
    base: *mut u8,
    count: usize,
    size: usize,
    cmp: extern "C" fn(*const u8, *const u8) -> i32,
) {
    // Explicit recursion stack, like the original's 260-byte frame:
    // 32 base/count pairs. Only the larger half is ever pushed, so the
    // depth is bounded by log2(count) and 32 entries cannot overflow.
    // MaybeUninit + unchecked access: only entries below `depth` are ever
    // read, and this keeps LLVM from emitting __aeabi_memclr4 calls and
    // bounds-check panics that the firmware link cannot satisfy.
    let mut base_stack: [core::mem::MaybeUninit<*mut u8>; 32] =
        [core::mem::MaybeUninit::uninit(); 32];
    let mut count_stack: [core::mem::MaybeUninit<usize>; 32] =
        [core::mem::MaybeUninit::uninit(); 32];
    base_stack[0].write(base);
    count_stack[0].write(count);
    let mut depth = 1usize;

    loop {
        depth -= 1;
        let mut lo = base_stack.get_unchecked(depth).assume_init();
        let mut n = count_stack.get_unchecked(depth).assume_init();

        loop {
            // Median-of-three: order lo <= mid <= last, then stash the
            // pivot (the median, at mid) just below `last`.
            let mid = lo.add(size * (n / 2));
            let last = lo.add(size * (n - 1));
            if cmp(lo, mid) > 0 {
                swap_elements(lo, mid, size);
            }
            if cmp(mid, last) > 0 {
                if cmp(lo, last) > 0 {
                    swap_elements(lo, last, size);
                }
                swap_elements(mid, last, size);
            }
            let pivot = last.sub(size);
            swap_elements(mid, pivot, size);

            // Hoare-style partition around the pivot. lo and last are
            // sentinels (median-of-three guarantees lo <= pivot <= last),
            // so neither scan can leave the array.
            let mut i = lo;
            let mut i_index = 0usize;
            let mut j = pivot;
            loop {
                loop {
                    i = i.add(size);
                    i_index += 1;
                    if cmp(i, pivot) >= 0 {
                        break;
                    }
                }
                loop {
                    j = j.sub(size);
                    if cmp(j, pivot) <= 0 {
                        break;
                    }
                }
                if j <= i {
                    break;
                }
                swap_elements(i, j, size);
            }
            swap_elements(i, pivot, size);

            // Original quirk: the left range is [lo, i-1) and the right
            // range starts AT the pivot position i, so element i-1 is
            // skipped by the quicksort phase. The finishing insertion
            // sort in qsort() repairs this.
            let left_count = i_index - 1;
            let right_count = n - i_index;

            // Push the larger half, loop on the smaller one; halves of
            // <= 10 elements are left for the insertion sort.
            if left_count > right_count {
                if right_count > 10 {
                    base_stack.get_unchecked_mut(depth).write(lo);
                    count_stack.get_unchecked_mut(depth).write(left_count);
                    depth += 1;
                    lo = i;
                    n = right_count;
                } else if left_count > 10 {
                    n = left_count;
                } else {
                    break;
                }
            } else if left_count > 10 {
                base_stack.get_unchecked_mut(depth).write(i);
                count_stack.get_unchecked_mut(depth).write(right_count);
                depth += 1;
                n = left_count;
            } else if right_count > 10 {
                lo = i;
                n = right_count;
            } else {
                break;
            }
        }

        if depth == 0 {
            return;
        }
    }
}

/// qsort — original: `FUN_08030cd4` @ 0x08030cd4 (256 bytes).
///
/// Sorts `count` elements of `size` bytes at `base` using `cmp`, which
/// returns negative/zero/positive like the ARM ADS convention. Does
/// nothing when `size == 0`.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn qsort(
    base: *mut u8,
    count: usize,
    size: usize,
    cmp: extern "C" fn(*const u8, *const u8) -> i32,
) {
    if size == 0 {
        return;
    }
    if count > 10 {
        qsort_inner(base, count, size, cmp);
    }
    // Straight insertion sort over the whole array. Besides sorting small
    // arrays on its own, this pass is what finishes the quicksort: it
    // repairs the <= 10 element partitions qsort_inner abandons.
    //
    // `wrapping_*`: for count == 0 the original computes last = base-size
    // and the loop simply never runs (base is always a real array there);
    // guard explicitly so a degenerate base of 0/1 cannot wrap the
    // pointer comparison. Behavior for any real array is unchanged.
    if count == 0 {
        return;
    }
    let last = base.wrapping_add(size.wrapping_mul(count.wrapping_sub(1)));
    let mut cur = base;
    while cur < last {
        let elem = cur.add(size);
        // Insertion point: walk down while the predecessor is strictly
        // greater (equal elements keep their relative order here).
        let mut scan = cur;
        while scan >= base && cmp(scan, elem) > 0 {
            scan = scan.sub(size);
        }
        let target = scan.add(size);
        // Shift [target, elem) up by one element and drop the saved
        // element into target, word- or byte-wise as in swap_elements.
        if (size | elem as usize) & 3 == 0 {
            let stride = size / 4; // in u32 words, not bytes
            let mut k = 0;
            while k < size {
                let pos = elem.add(k) as *mut u32;
                let tmp = pos.read();
                let mut p = pos;
                while p.sub(stride) as *mut u8 >= target {
                    p.write(p.sub(stride).read());
                    p = p.sub(stride);
                }
                p.write(tmp);
                k += 4;
            }
        } else {
            let mut k = 0;
            while k < size {
                let pos = elem.add(k);
                let tmp = *pos;
                let mut p = pos;
                while p.sub(size) >= target {
                    *p = *p.sub(size);
                    p = p.sub(size);
                }
                *p = tmp;
                k += 1;
            }
        }
        cur = elem;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
    use std::vec;
    use std::vec::Vec;

    fn xorshift(state: &mut u32) -> u32 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *state = x;
        x
    }

    fn ordering_to_i32(ord: core::cmp::Ordering) -> i32 {
        match ord {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        }
    }

    extern "C" fn cmp_i32_asc(a: *const u8, b: *const u8) -> i32 {
        unsafe {
            let x = (a as *const i32).read_unaligned();
            let y = (b as *const i32).read_unaligned();
            ordering_to_i32(x.cmp(&y))
        }
    }

    extern "C" fn cmp_i32_desc(a: *const u8, b: *const u8) -> i32 {
        unsafe {
            let x = (a as *const i32).read_unaligned();
            let y = (b as *const i32).read_unaligned();
            ordering_to_i32(y.cmp(&x))
        }
    }

    fn sort_i32s(values: &mut [i32], cmp: extern "C" fn(*const u8, *const u8) -> i32) {
        unsafe {
            qsort(
                values.as_mut_ptr() as *mut u8,
                values.len(),
                core::mem::size_of::<i32>(),
                cmp,
            );
        }
    }

    /// Every required array length across random/sorted/reverse/equal
    /// patterns, verified against std's sort.
    #[test]
    fn sorts_ints_many_sizes_and_patterns() {
        for &count in &[0usize, 1, 2, 3, 10, 11, 100, 1000] {
            let mut rng = 0x1234_5678u32 ^ count as u32;
            let random: Vec<i32> = (0..count).map(|_| xorshift(&mut rng) as i32).collect();
            let mut sorted = random.clone();
            sorted.sort_unstable();
            let mut reverse = sorted.clone();
            reverse.reverse();
            let equal = vec![42i32; count];
            let duplicates: Vec<i32> = random.iter().map(|v| v % 7).collect();

            for (name, case) in [
                ("random", random),
                ("sorted", sorted),
                ("reverse", reverse),
                ("equal", equal),
                ("duplicates", duplicates),
            ] {
                let mut values = case;
                let mut reference = values.clone();
                reference.sort_unstable();
                sort_i32s(&mut values, cmp_i32_asc);
                assert_eq!(values, reference, "count={count} pattern={name}");
            }
        }
    }

    #[test]
    fn sorts_descending() {
        let mut rng = 0xdead_beefu32;
        for &count in &[2usize, 3, 10, 11, 100, 1000] {
            let mut values: Vec<i32> = (0..count).map(|_| xorshift(&mut rng) as i32).collect();
            let mut reference = values.clone();
            reference.sort_unstable_by(|a, b| b.cmp(a));
            sort_i32s(&mut values, cmp_i32_desc);
            assert_eq!(values, reference, "count={count}");
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Rec8 {
        key: i32,
        tag: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Rec12 {
        key: i32,
        a: u32,
        b: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Rec16 {
        key: i32,
        a: u32,
        b: u32,
        c: u32,
    }

    macro_rules! struct_sort_test {
        ($name:ident, $rec:ty, $make:expr) => {
            #[test]
            fn $name() {
                extern "C" fn cmp_by_key(a: *const u8, b: *const u8) -> i32 {
                    unsafe {
                        let x = (*(a as *const $rec)).key;
                        let y = (*(b as *const $rec)).key;
                        ordering_to_i32(x.cmp(&y))
                    }
                }
                let make: fn(i32, u32) -> $rec = $make;
                let mut rng = 0x0bad_f00du32;
                for &count in &[0usize, 1, 2, 3, 10, 11, 100, 1000] {
                    let mut recs: Vec<$rec> = (0..count as u32)
                        .map(|i| make(xorshift(&mut rng) as i32 % 1000, i))
                        .collect();
                    let mut reference = recs.clone();
                    // Multiset check without relying on stability.
                    reference.sort_unstable();
                    unsafe {
                        qsort(
                            recs.as_mut_ptr() as *mut u8,
                            recs.len(),
                            core::mem::size_of::<$rec>(),
                            cmp_by_key,
                        );
                    }
                    let mut got = recs.clone();
                    got.sort_unstable();
                    assert_eq!(got, reference, "count={count} permutation");
                    assert!(
                        recs.windows(2).all(|w| w[0].key <= w[1].key),
                        "count={count} sortedness"
                    );
                }
            }
        };
    }

    struct_sort_test!(sorts_struct_size8, Rec8, |key, tag| Rec8 { key, tag });
    struct_sort_test!(sorts_struct_size12, Rec12, |key, tag| Rec12 {
        key,
        a: tag,
        b: tag * 3,
    });
    struct_sort_test!(sorts_struct_size16, Rec16, |key, tag| Rec16 {
        key,
        a: tag,
        b: tag * 3,
        c: tag * 7,
    });

    /// Odd element sizes (3/5/7/9 bytes) force the byte-swap paths.
    #[test]
    fn sorts_odd_element_sizes() {
        extern "C" fn cmp_key_u16(a: *const u8, b: *const u8) -> i32 {
            unsafe {
                let x = u16::from_le_bytes([*a, *a.add(1)]);
                let y = u16::from_le_bytes([*b, *b.add(1)]);
                ordering_to_i32(x.cmp(&y))
            }
        }
        let mut rng = 0x5eed_5eedu32;
        for &size in &[3usize, 5, 7, 9] {
            for &count in &[0usize, 1, 2, 3, 10, 11, 100, 1000] {
                let mut buf = vec![0u8; count * size];
                for chunk in buf.chunks_mut(size) {
                    let key = xorshift(&mut rng) % 100;
                    chunk[0..2].copy_from_slice(&(key as u16).to_le_bytes());
                    for b in &mut chunk[2..] {
                        *b = xorshift(&mut rng) as u8;
                    }
                }
                let mut reference = buf.clone();
                reference.sort_unstable();
                unsafe {
                    qsort(buf.as_mut_ptr(), count, size, cmp_key_u16);
                }
                // Sorted by key, and a permutation of the input bytes.
                let keys: Vec<u16> = buf
                    .chunks(size)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                assert!(
                    keys.windows(2).all(|w| w[0] <= w[1]),
                    "size={size} count={count} sortedness"
                );
                let mut got = buf.clone();
                got.sort_unstable();
                assert_eq!(got, reference, "size={size} count={count} permutation");
            }
        }
    }

    /// A deliberately misaligned base with word-sized elements: the
    /// original's (size|ptr)&3 test must select the byte path here.
    #[test]
    fn sorts_unaligned_elements() {
        let mut rng = 0xc001_d00du32;
        for &count in &[2usize, 3, 10, 11, 100, 1000] {
            let mut backing = vec![0u8; count * 4 + 1];
            let base = unsafe { backing.as_mut_ptr().add(1) };
            let mut reference = Vec::with_capacity(count);
            for i in 0..count {
                let v = xorshift(&mut rng) as i32;
                reference.push(v);
                unsafe {
                    (base.add(i * 4) as *mut i32).write_unaligned(v);
                }
            }
            unsafe {
                qsort(base, count, 4, cmp_i32_asc);
            }
            reference.sort_unstable();
            let got: Vec<i32> = (0..count)
                .map(|i| unsafe { (base.add(i * 4) as *const i32).read_unaligned() })
                .collect();
            assert_eq!(got, reference, "count={count}");
        }
    }

    static CMP_CALLS: AtomicUsize = AtomicUsize::new(0);
    static CMP_BASE: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
    static CMP_SPAN: AtomicUsize = AtomicUsize::new(0);
    static CMP_SIZE: AtomicUsize = AtomicUsize::new(0);
    static CMP_VIOLATIONS: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn cmp_i32_checked(a: *const u8, b: *const u8) -> i32 {
        CMP_CALLS.fetch_add(1, Ordering::Relaxed);
        let base = CMP_BASE.load(Ordering::Relaxed) as usize;
        let span = CMP_SPAN.load(Ordering::Relaxed);
        let size = CMP_SIZE.load(Ordering::Relaxed);
        for p in [a as usize, b as usize] {
            // Every callback argument must point at the start of an
            // element inside the array.
            if p < base || p >= base + span || (p - base) % size != 0 {
                CMP_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
            }
        }
        cmp_i32_asc(a, b)
    }

    #[test]
    fn callback_semantics() {
        let mut rng = 0xabcd_1234u32;
        let mut values: Vec<i32> = (0..1000).map(|_| xorshift(&mut rng) as i32).collect();
        CMP_BASE.store(values.as_mut_ptr() as *mut u8, Ordering::Relaxed);
        CMP_SPAN.store(values.len() * 4, Ordering::Relaxed);
        CMP_SIZE.store(4, Ordering::Relaxed);
        CMP_CALLS.store(0, Ordering::Relaxed);
        CMP_VIOLATIONS.store(0, Ordering::Relaxed);
        sort_i32s(&mut values, cmp_i32_checked);
        assert!(values.windows(2).all(|w| w[0] <= w[1]));
        assert!(CMP_CALLS.load(Ordering::Relaxed) > 0);
        assert_eq!(CMP_VIOLATIONS.load(Ordering::Relaxed), 0);

        // Degenerate arrays must not invoke the callback at all.
        CMP_CALLS.store(0, Ordering::Relaxed);
        let mut none: Vec<i32> = vec![];
        sort_i32s(&mut none, cmp_i32_checked);
        let mut one = vec![7i32];
        sort_i32s(&mut one, cmp_i32_checked);
        assert_eq!(CMP_CALLS.load(Ordering::Relaxed), 0);
        assert_eq!(one, vec![7]);
    }

    /// size == 0 is a documented no-op in the original.
    #[test]
    fn zero_size_is_noop() {
        let mut values = vec![3i32, 1, 2];
        unsafe {
            qsort(values.as_mut_ptr() as *mut u8, 3, 0, cmp_i32_asc);
        }
        assert_eq!(values, vec![3, 1, 2]);
    }
}
