//! FAT long-file-name reconstruction.
//!
//! `fat_lfn_reconstruct` is retailOS `FUN_082e44b4` at `0x082e44b4` (196
//! bytes; the next independently entered function starts at `0x082e4578`).
//! Raw decoding finds six plain `bl` sites (`0x082e44e0`, `0x082e4514`,
//! `0x082e4520`, `0x082e4534`, `0x082e4560`, and `0x082e456c`) and no
//! predicated `bl` sites. The first cache acquisition consumes inbound `r3`
//! as its cache key; the raw second call explicitly loads its block index
//! from state word 4 but leaves its scratch arguments unspecified.
//!
//! The function clears the output, acquires the directory block containing
//! the accumulated LFN records, and converts up to `min(total, current + 1)`
//! records in reverse order. A nonzero state word 4 is the preceding block
//! index; it acquires that block too and appends the remainder. Each acquired
//! descriptor is released after conversion. Deliberate deviation: target
//! builds call the already ported cache acquire/release functions; the
//! unported LFN record formatter remains a retailOS call. The second acquire
//! supplies zero for its raw unspecified scratch arguments.

use super::cache_block::cache_block_acquire;
use super::cache_entry::cache_entry_release;

const STATE_TOTAL_WORD: usize = 0;
const STATE_CURRENT_WORD: usize = 1;
const STATE_BLOCK_WORD: usize = 3;
const STATE_CONTINUES_WORD: usize = 4;
const CACHE_PAYLOAD_OFFSET: usize = 0x18;
const PREVIOUS_BLOCK_LFN_OFFSET: usize = 0x1f8;
const LFN_RECORD_SIZE: usize = 0x20;
const LFN_OUTPUT_CHARS: u32 = 13;
const OUTPUT_CAPACITY: u32 = 0x100;

type LfnRecordAppend = unsafe extern "C" fn(*mut u8, u32, *const u8, u32);
type CacheAcquire = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> *mut u8;
type CacheRelease = unsafe extern "C" fn(*mut u8, u32);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn append_lfn_records(output: *mut u8, capacity: u32, records: *const u8, count: u32) {
    let function: LfnRecordAppend = core::mem::transmute(0x082d7a50usize);
    function(output, capacity, records, count)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn acquire_cache_block(context: *mut u8, block: u32, ignored: u32, cache_key: u32) -> *mut u8 {
    cache_block_acquire(context, block, ignored, cache_key)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn release_cache_entry(entry: *mut u8) {
    cache_entry_release(entry, 0)
}

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
struct HostOps {
    append: LfnRecordAppend,
    acquire: CacheAcquire,
    release: CacheRelease,
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_append(_: *mut u8, _: u32, _: *const u8, _: u32) {
    panic!("fat_lfn_reconstruct formatter called without a host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_acquire(_: *mut u8, _: u32, _: u32, _: u32) -> *mut u8 {
    panic!("fat_lfn_reconstruct cache acquisition called without a host seam")
}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_release(_: *mut u8, _: u32) {
    panic!("fat_lfn_reconstruct cache release called without a host seam")
}
#[cfg(not(target_os = "none"))]
static mut HOST_OPS: HostOps = HostOps { append: unavailable_append, acquire: unavailable_acquire, release: unavailable_release };
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn host_ops() -> HostOps { core::ptr::read_volatile(core::ptr::addr_of!(HOST_OPS)) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn append_lfn_records(output: *mut u8, capacity: u32, records: *const u8, count: u32) { (host_ops().append)(output, capacity, records, count) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn acquire_cache_block(context: *mut u8, block: u32, ignored: u32, cache_key: u32) -> *mut u8 { (host_ops().acquire)(context, block, ignored, cache_key) }
#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn release_cache_entry(entry: *mut u8) { (host_ops().release)(entry, 0) }

/// Reconstructs accumulated FAT LFN entries into `output`.
///
/// Original: `FUN_082e44b4` @ `0x082e44b4`, 196 bytes, six plain `bl` sites
/// and zero predicated `bl` sites (binary-verified).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn fat_lfn_reconstruct(
    context: *mut u8,
    state: *const u32,
    output: *mut u8,
    cache_key: u32,
) -> *mut u8 {
    output.write(0);
    let total = state.add(STATE_TOTAL_WORD).read();
    if total == 0 { return output; }

    let current = state.add(STATE_CURRENT_WORD).read();
    let count = if current.wrapping_add(1) < total { current.wrapping_add(1) } else { total };
    let entry = acquire_cache_block(context, state.add(STATE_BLOCK_WORD).read(), output as usize as u32, cache_key);
    if entry.is_null() { return output; }

    append_lfn_records(output, OUTPUT_CAPACITY, entry.add(CACHE_PAYLOAD_OFFSET).wrapping_add(current as usize * LFN_RECORD_SIZE), count);
    release_cache_entry(entry);

    if state.add(STATE_CONTINUES_WORD).read() != 0 {
        let previous = acquire_cache_block(context, state.add(STATE_CONTINUES_WORD).read(), 0, 0);
        if !previous.is_null() {
            let used = count.wrapping_mul(LFN_OUTPUT_CHARS);
            append_lfn_records(output.wrapping_add(used as usize), OUTPUT_CAPACITY.wrapping_sub(used), previous.add(PREVIOUS_BLOCK_LFN_OFFSET), total.wrapping_sub(count));
            release_cache_entry(previous);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ENTRIES: [*mut u8; 2] = [core::ptr::null_mut(); 2];
    static mut ACQUIRE_COUNT: usize = 0;
    static mut APPENDS: [(*mut u8, u32, *const u8, u32); 2] = [(core::ptr::null_mut(), 0, core::ptr::null(), 0); 2];
    static mut APPEND_COUNT: usize = 0;
    static mut RELEASES: [*mut u8; 2] = [core::ptr::null_mut(); 2];
    static mut RELEASE_COUNT: usize = 0;

    unsafe extern "C" fn acquire(_: *mut u8, _: u32, _: u32, _: u32) -> *mut u8 { let entry = ENTRIES[ACQUIRE_COUNT]; ACQUIRE_COUNT += 1; entry }
    unsafe extern "C" fn append(output: *mut u8, capacity: u32, records: *const u8, count: u32) { APPENDS[APPEND_COUNT] = (output, capacity, records, count); APPEND_COUNT += 1; output.write((0x40 + APPEND_COUNT) as u8); }
    unsafe extern "C" fn release(entry: *mut u8, _: u32) { RELEASES[RELEASE_COUNT] = entry; RELEASE_COUNT += 1; }

    struct Reset(HostOps);
    impl Drop for Reset { fn drop(&mut self) { unsafe { HOST_OPS = self.0; } } }
    unsafe fn install(first: *mut u8, second: *mut u8) -> Reset {
        let prior = host_ops(); HOST_OPS = HostOps { append, acquire, release };
        ENTRIES = [first, second]; ACQUIRE_COUNT = 0; APPENDS = [(core::ptr::null_mut(), 0, core::ptr::null(), 0); 2]; APPEND_COUNT = 0; RELEASES = [core::ptr::null_mut(); 2]; RELEASE_COUNT = 0; Reset(prior)
    }

    #[test]
    fn zero_total_clears_output_without_acquiring() {
        let _lock = LOCK.lock();
        let _reset = unsafe { install(core::ptr::null_mut(), core::ptr::null_mut()) };
        let state = [0, 7, 0, 3, 1]; let mut output = [0xa5; 0x100];
        assert_eq!(unsafe { fat_lfn_reconstruct(core::ptr::null_mut(), state.as_ptr(), output.as_mut_ptr(), 9) }, output.as_mut_ptr());
        assert_eq!(output[0], 0); assert_eq!(unsafe { ACQUIRE_COUNT }, 0);
    }

    #[test]
    fn appends_current_and_previous_blocks_with_retail_capacities() {
        let _lock = LOCK.lock();
        let mut first = [0u8; 0x218]; let mut second = [0u8; 0x208];
        let _reset = unsafe { install(first.as_mut_ptr(), second.as_mut_ptr()) };
        let state = [5, 2, 0, 0x34, 1]; let mut output = [0xa5; 0x100];
        unsafe { fat_lfn_reconstruct(0x1234usize as *mut u8, state.as_ptr(), output.as_mut_ptr(), 0x77); }
        unsafe {
            assert_eq!(APPEND_COUNT, 2);
            assert_eq!(APPENDS[0], (output.as_mut_ptr(), 0x100, first.as_ptr().add(0x18 + 2 * 0x20), 3));
            assert_eq!(APPENDS[1], (output.as_mut_ptr().add(39), 217, second.as_ptr().add(0x1f8), 2));
            assert_eq!(RELEASES, [first.as_mut_ptr(), second.as_mut_ptr()]);
        }
    }
}
