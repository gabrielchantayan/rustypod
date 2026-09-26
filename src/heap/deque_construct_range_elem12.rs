//! Range construction for the 12-byte-element deque instantiation.

use super::block_deque::{deque_construct, BlockDeque, DequeHead, DequeIter};

/// Firmware load address of the unported range-population helper.
pub const DEQUE_RANGE_POPULATE_ELEM12_ADDRESS: usize = 0x083e_a02c;

#[cfg(target_os = "none")]
type DequeRangePopulateElem12 = unsafe extern "C" fn(
    first_cur: u32,
    first_base: u32,
    first_end: u32,
    first_slot: u32,
    last_cur: u32,
    last_base: u32,
    last_end: u32,
    last_slot: u32,
    deque: u32,
);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn deque_range_populate_elem12(deque: *mut BlockDeque, first: *const DequeIter, last: *const DequeIter) {
    let populate: DequeRangePopulateElem12 = core::mem::transmute(DEQUE_RANGE_POPULATE_ELEM12_ADDRESS);
    let first_words = first.cast::<u32>();
    let last_words = last.cast::<u32>();
    populate(
        first_words.read(),
        first_words.add(1).read(),
        first_words.add(2).read(),
        first_words.add(3).read(),
        last_words.read(),
        last_words.add(1).read(),
        last_words.add(2).read(),
        last_words.add(3).read(),
        deque as usize as u32,
    );
}

#[cfg(not(target_os = "none"))]
pub type DequeRangePopulateElem12 = unsafe extern "C" fn(*mut BlockDeque, *const DequeIter, *const DequeIter);

#[cfg(not(target_os = "none"))]
pub unsafe extern "C" fn missing_deque_range_populate_elem12(
    _deque: *mut BlockDeque,
    _first: *const DequeIter,
    _last: *const DequeIter,
) {
    panic!("install deque range-populate host seam before calling this port")
}

/// Active host boundary for retailOS's unported range-population helper.
#[cfg(not(target_os = "none"))]
pub static mut DEQUE_RANGE_POPULATE_ELEM12: DequeRangePopulateElem12 = missing_deque_range_populate_elem12;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn deque_range_populate_elem12(deque: *mut BlockDeque, first: *const DequeIter, last: *const DequeIter) {
    let populate = core::ptr::read_volatile(core::ptr::addr_of!(DEQUE_RANGE_POPULATE_ELEM12));
    populate(deque, first, last)
}

/// `deque_construct_range_elem12` — original: `FUN_083dffc4` @ **0x083dffc4**
/// (128 bytes exactly, `0x083dffc4..0x083e0044`; the next separately linked
/// function begins at `0x083e0044`). Raw A32 decoding finds **2 inbound plain
/// `bl` call sites**, both unconditional, and zero predicated inbound `bl`
/// forms.
///
/// Sets the trailing `map_cap` word to zero, default-constructs the 0x28-byte
/// deque head, copies the two 16-byte source iterators into stack temporaries,
/// then passes their eight words and the deque to the 12-byte-element
/// range-population helper at `0x083ea02c`. The port calls the established
/// default deque constructor directly and preserves the raw helper ABI on
/// target; host builds expose the helper as a three-pointer seam.
///
/// Deliberate deviation: `FUN_083ea02c` is not ported, so its range population
/// remains a fixed-address target call (and an installable host seam).
///
/// # Safety
///
/// `deque` must point to a writable `BlockDeque`; `range` must point to two
/// adjacent, readable `DequeIter` values. The unported helper imposes its own
/// source-range and allocation requirements.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.deque_construct_range_elem12")]
#[inline(never)]
pub unsafe extern "C" fn deque_construct_range_elem12(
    deque: *mut BlockDeque,
    range: *const DequeIter,
) -> *mut BlockDeque {
    (*deque).map_cap = 0;
    deque_construct(deque.cast::<DequeHead>());
    let first = range.read();
    let last = range.add(1).read();
    deque_range_populate_elem12(deque, &first, &last);
    deque
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::ptr::addr_of_mut;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut RECORDED: Option<(*mut BlockDeque, DequeIter, DequeIter)> = None;

    unsafe extern "C" fn record_population(deque: *mut BlockDeque, first: *const DequeIter, last: *const DequeIter) {
        RECORDED = Some((deque, first.read(), last.read()));
    }

    #[test]
    fn initializes_the_full_deque_and_forwards_distinct_range_iterators() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let first = DequeIter { cur: 0x1111usize as *mut u8, seg_base: 0x2222usize as *mut u8, seg_end: 0x3333usize as *mut u8, seg_slot: 0x4444usize as *mut *mut u8 };
        let last = DequeIter { cur: 0x5555usize as *mut u8, seg_base: 0x6666usize as *mut u8, seg_end: 0x7777usize as *mut u8, seg_slot: 0x8888usize as *mut *mut u8 };
        let range = [first, last];
        let mut deque: BlockDeque = unsafe { core::mem::zeroed() };
        deque.map_cap = u32::MAX;
        unsafe {
            addr_of_mut!(RECORDED).write(None);
            addr_of_mut!(DEQUE_RANGE_POPULATE_ELEM12).write(record_population);
            let returned = deque_construct_range_elem12(&mut deque, range.as_ptr());
            assert_eq!(returned, addr_of_mut!(deque));
            let recorded = RECORDED.unwrap();
            assert_eq!(recorded.0, addr_of_mut!(deque));
            assert_eq!(recorded.1.cur, first.cur);
            assert_eq!(recorded.1.seg_base, first.seg_base);
            assert_eq!(recorded.1.seg_end, first.seg_end);
            assert_eq!(recorded.1.seg_slot, first.seg_slot);
            assert_eq!(recorded.2.cur, last.cur);
            assert_eq!(recorded.2.seg_base, last.seg_base);
            assert_eq!(recorded.2.seg_end, last.seg_end);
            assert_eq!(recorded.2.seg_slot, last.seg_slot);
        }
        assert!(deque.begin.cur.is_null());
        assert!(deque.end.cur.is_null());
        assert_eq!(deque.count, 0);
        assert!(deque.map.is_null());
        assert_eq!(deque.map_cap, 0);
        unsafe { addr_of_mut!(DEQUE_RANGE_POPULATE_ELEM12).write(missing_deque_range_populate_elem12) };
    }

    #[test]
    fn copies_range_before_the_population_seam_can_mutate_its_source() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe extern "C" fn mutate_source(_deque: *mut BlockDeque, first: *const DequeIter, _last: *const DequeIter) {
            first.cast_mut().write(DequeIter::NULL);
        }
        let range = [
            DequeIter { cur: 0x1000usize as *mut u8, seg_base: core::ptr::null_mut(), seg_end: core::ptr::null_mut(), seg_slot: core::ptr::null_mut() },
            DequeIter::NULL,
        ];
        let mut deque: BlockDeque = unsafe { core::mem::zeroed() };
        unsafe {
            addr_of_mut!(DEQUE_RANGE_POPULATE_ELEM12).write(mutate_source);
            deque_construct_range_elem12(&mut deque, range.as_ptr());
            assert_eq!(range[0].cur as usize, 0x1000);
            addr_of_mut!(DEQUE_RANGE_POPULATE_ELEM12).write(missing_deque_range_populate_elem12);
        }
    }
}
