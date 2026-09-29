//! Adapts a five-argument caller ABI to the global-record matcher.
//!
//! `global_record_match_search` — retailOS `FUN_082cad7c` at `0x082cad7c`
//! (**20 bytes, `0x082cad7c..0x082cad8f`**). Raw `osos.dec` A32 words show
//! `mov r0,r1; mov r1,r2; mov r2,r3; ldr r3,[sp]; b 0x0824c860`; the next
//! independently reachable function starts at `0x082cad90`. The body has no
//! plain or predicated outbound `bl` instructions. Full-image A32 decoding
//! finds two inbound plain `bl` instructions (`0x0825bdfc`, `0x08295b44`) and
//! no predicated inbound calls.
//!
//! # Algorithm
//!
//! Discards its first argument, shifts the remaining four arguments into
//! `global_record_match_search_target`'s normal register ABI, and tail-branches
//! to that routine. The target scans its eight global 104-byte records and
//! conditionally stores matching record addresses.
//!
//! # Deliberate deviations
//!
//! The unported target at `0x0824c860` is an ABI-only resident seam. Target
//! builds use a typed indirect call; host builds use a narrow test seam. Rust
//! returns normally after that call rather than using the original tail branch.

pub type GlobalRecordMatchSearchTarget = unsafe extern "C" fn(*const u8, *mut u32, u32, *mut u32) -> u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_global_record_match_search(_: *const u8, _: *mut u32, _: u32, _: *mut u32) -> u32 { 0 }

#[cfg(not(target_os = "none"))]
pub static mut GLOBAL_RECORD_MATCH_SEARCH_TARGET: GlobalRecordMatchSearchTarget = missing_global_record_match_search;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn global_record_match_search_target() -> GlobalRecordMatchSearchTarget {
    core::mem::transmute(0x0824_c860usize)
}

/// Forwards a record-match query after discarding the caller's source handle.
///
/// # Safety
/// `query`, `matches`, and `match_count` must satisfy the target routine's
/// retailOS ABI. In particular, `matches` has room for `capacity` 32-bit
/// record addresses and `match_count` is writable.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn global_record_match_search(
    _source_handle: u32,
    query: *const u8,
    matches: *mut u32,
    capacity: u32,
    match_count: *mut u32,
) -> u32 {
    #[cfg(target_os = "none")]
    return global_record_match_search_target()(query, matches, capacity, match_count);
    #[cfg(not(target_os = "none"))]
    return GLOBAL_RECORD_MATCH_SEARCH_TARGET(query, matches, capacity, match_count);
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut QUERY: *const u8 = core::ptr::null();
    static mut MATCHES: *mut u32 = core::ptr::null_mut();
    static mut CAPACITY: u32 = 0;
    static mut MATCH_COUNT: *mut u32 = core::ptr::null_mut();

    unsafe extern "C" fn record_call(query: *const u8, matches: *mut u32, capacity: u32, match_count: *mut u32) -> u32 {
        QUERY = query;
        MATCHES = matches;
        CAPACITY = capacity;
        MATCH_COUNT = match_count;
        1
    }

    struct Restore(GlobalRecordMatchSearchTarget);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe { GLOBAL_RECORD_MATCH_SEARCH_TARGET = self.0 } }
    }

    #[test]
    fn discards_source_handle_and_forwards_all_search_arguments() {
        let _lock = LOCK.lock();
        let restore = unsafe { Restore(GLOBAL_RECORD_MATCH_SEARCH_TARGET) };
        unsafe { GLOBAL_RECORD_MATCH_SEARCH_TARGET = record_call };
        let query = [0x14_u8; 44];
        let mut matches = [0_u32; 1];
        let mut count = 0_u32;

        assert_eq!(unsafe { global_record_match_search(0xdead_beef, query.as_ptr(), matches.as_mut_ptr(), 1, &mut count) }, 1);
        unsafe {
            assert_eq!(QUERY, query.as_ptr());
            assert_eq!(MATCHES, matches.as_mut_ptr());
            assert_eq!(CAPACITY, 1);
            assert_eq!(MATCH_COUNT, core::ptr::addr_of_mut!(count));
        }
        drop(restore);
    }
}
