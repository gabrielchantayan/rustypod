//! OpenSSL's generic `OBJ_bsearch`, the shared binary search behind the
//! object-identifier database lookups.
//!
//! Port: `obj_bsearch` — `FUN_0805eb04` @ **0x0805eb04** (112 bytes,
//! `0x0805eb04..0x0805eb74`; the next separately linked function starts at
//! `0x0805eb74`, a word-pair comparator tail-calling the ADS string block at
//! `0x08030f64`). Raw decoding of every immediate ARM B/BL word in
//! `osos.dec` finds **five inbound `bl` call sites**: `0x0805ee20`,
//! `0x0805f0dc`, `0x0805f320` (the `OBJ_ln2nid`/`OBJ_obj2nid`/`OBJ_sn2nid`
//! family) plus `0x0806ea04` and `0x08070df0`. The function body itself
//! contains no `bl`; the comparator rides the fifth (stack) argument
//! through `blx r9`.
//!
//! # Algorithm
//!
//! Classic lo/hi binary search over `nmemb` elements of `size` bytes at
//! `base`, ordered by `compar(key, elem)`: `mid = (lo + hi) / 2` (the
//! original adds the sign bit back before `asr #1`, a no-op for
//! non-negative counts), `elem = base + size * mid` (a 32-bit `mla`
//! wrap); `order < 0` keeps the left half (`hi = mid`), `order > 0` the
//! right (`lo = mid + 1`), `0` returns `elem`. `nmemb == 0` and an
//! exhausted range both return NULL.
//!
//! # Deliberate deviations
//!
//! None beyond the usual: the stack-passed fifth argument is a normal
//! Rust parameter, and the unsigned lo/hi arithmetic makes the original's
//! signed-divide fixup unnecessary. `#[inline(never)]` keeps it a real
//! `bl` target for the hooks.

/// Comparator ABI: returns <0 / 0 / >0 as `key` orders against `elem`.
pub type ObjCmpFn = unsafe extern "C" fn(key: *const u8, elem: *const u8) -> i32;

/// obj_bsearch — original: `FUN_0805eb04` @ 0x0805eb04 (112 bytes).
///
/// Binary search over `nmemb` elements of `size` bytes at `base`,
/// returning the element `compar` ranks equal to `key`, or NULL.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn obj_bsearch(
    key: *const u8,
    base: *const u8,
    nmemb: usize,
    size: usize,
    compar: ObjCmpFn,
) -> *mut u8 {
    let mut lo: usize = 0;
    let mut hi: usize = nmemb;
    while lo < hi {
        let mid = (lo + hi) / 2;
        // The original's mla is a 32-bit wrap; mirroring it with wrapping ops.
        let elem = base.wrapping_add(size.wrapping_mul(mid));
        let order = compar(key, elem);
        if order < 0 {
            hi = mid;
        } else if order > 0 {
            lo = mid + 1;
        } else {
            return elem as *mut u8;
        }
    }
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    unsafe extern "C" fn cmp_u32(key: *const u8, elem: *const u8) -> i32 {
        let k = (key as *const u32).read();
        let e = (elem as *const u32).read();
        if k < e {
            -1
        } else if k > e {
            1
        } else {
            0
        }
    }

    fn table(n: u32) -> Vec<u32> {
        // Even values 2, 4, ..., 2n: odd queries must miss.
        (1..=n).map(|i| i * 2).collect()
    }

    unsafe fn search(tab: &[u32], v: u32) -> *mut u8 {
        obj_bsearch(
            &v as *const u32 as *const u8,
            tab.as_ptr() as *const u8,
            tab.len(),
            4,
            cmp_u32,
        )
    }

    #[test]
    fn finds_every_element_and_misses_gaps() {
        let tab = table(64);
        for (i, &v) in tab.iter().enumerate() {
            unsafe {
                let hit = search(&tab, v);
                assert_eq!(hit, tab.as_ptr().add(i) as *mut u8, "hit {v}");
                assert!(search(&tab, v - 1).is_null(), "miss {}", v - 1);
            }
        }
    }

    #[test]
    fn empty_and_single_element_tables() {
        let v: u32 = 2;
        unsafe {
            assert!(obj_bsearch(
                &v as *const u32 as *const u8,
                core::ptr::null(),
                0,
                4,
                cmp_u32
            )
            .is_null());
        }
        let one = [4u32];
        unsafe {
            assert_eq!(search(&one, 4), one.as_ptr() as *mut u8);
            assert!(search(&one, 2).is_null(), "below the only element");
            assert!(search(&one, 6).is_null(), "above the only element");
        }
    }

    #[test]
    fn out_of_range_keys_miss() {
        let tab = table(7);
        unsafe {
            assert!(search(&tab, 0).is_null(), "below all");
            assert!(search(&tab, 100).is_null(), "above all");
        }
    }

    #[test]
    fn element_size_strides() {
        // Byte table with size 1, and a wide-record table with size 8.
        let bytes: Vec<u8> = (0u8..40).step_by(3).collect();
        let key: u8 = 21;
        unsafe extern "C" fn cmp_u8(key: *const u8, elem: *const u8) -> i32 {
            (*key as i32) - (*elem as i32)
        }
        unsafe {
            let hit = obj_bsearch(&key, bytes.as_ptr(), bytes.len(), 1, cmp_u8);
            assert_eq!(hit, bytes.as_ptr().add(7) as *mut u8);
        }
        // Records: u32 key at offset 0 of an 8-byte stride.
        let recs: Vec<u32> = (0..10).flat_map(|i| [i * 10, 0xdead]).collect();
        unsafe {
            let k: u32 = 60;
            let hit = obj_bsearch(
                &k as *const u32 as *const u8,
                recs.as_ptr() as *const u8,
                10,
                8,
                cmp_u32,
            );
            assert_eq!(hit, recs.as_ptr().add(12) as *mut u8);
        }
    }
}
