//! `stream_read_string_record_map` — original: `FUN_082aaf10` @ **0x082aaf10**.
//!
//! **180 bytes** of code (`0x082aaf10..0x082aafc4`); the literal pool occupies
//! `0x082aafc4..0x082aafcc`, and the separately linked successor starts at
//! `0x082aafcc`. Raw ARM decoding finds eleven unconditional `bl` instructions
//! in the body and no predicated calls. It first reads an unsigned entry count,
//! then, for every entry, deserializes a COW string, constructs the fixed-key
//! string record, decodes the record through the unported entry helper, assigns
//! the mapped string, and destroys both temporaries.
//!
//! Deliberate deviation: `FUN_082aae1c`, `FUN_083db32c`, and the three
//! string-record helpers remain unported. Device builds call their verified
//! retailOS addresses; host builds route them through a replaceable operation
//! table so tests can prove the complete per-entry protocol.

use core::ptr;

const STATIC_EMPTY_STRING: *mut u8 = 0x08b3_1810 as *mut u8;

type ReadCount = unsafe extern "C" fn(*mut u8, *mut u8, u32);
type ReadString = unsafe extern "C" fn(*mut u8, *mut *mut u8);
type ClearWords = unsafe extern "C" fn(*mut u32) -> *mut u32;
type RecordConstruct = unsafe extern "C" fn(*mut StringRecord, *const u8, *const u8, *mut u32, u32) -> *mut StringRecord;
type DecodeEntry = unsafe extern "C" fn(*mut u8, *mut StringRecord) -> *mut u8;
type MapValue = unsafe extern "C" fn(*mut u8, *mut *mut u8) -> *mut *mut u8;
type RecordAssign = unsafe extern "C" fn(*mut StringRecord, *mut StringRecord) -> *mut StringRecord;
type RecordDestruct = unsafe extern "C" fn(*mut StringRecord) -> *mut StringRecord;
type StringRelease = unsafe extern "C" fn(*mut *mut u8);

#[repr(C)]
struct StringRecord {
    words: [u32; 5],
}

#[derive(Clone, Copy)]
struct StreamReadStringRecordMapOps {
    read_count: ReadCount,
    read_string: ReadString,
    clear_words: ClearWords,
    record_construct: RecordConstruct,
    decode_entry: DecodeEntry,
    map_value: MapValue,
    record_assign: RecordAssign,
    record_destruct: RecordDestruct,
    release_string: StringRelease,
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn retail_ops() -> StreamReadStringRecordMapOps {
    unsafe {
        StreamReadStringRecordMapOps {
            read_count: core::mem::transmute(0x083d_8134usize),
            read_string: core::mem::transmute(0x0807_45b8usize),
            clear_words: core::mem::transmute(0x083e_5aecusize),
            record_construct: core::mem::transmute(0x0819_7ab8usize),
            decode_entry: core::mem::transmute(0x082a_ae1cusize),
            map_value: core::mem::transmute(0x083d_b32cusize),
            record_assign: core::mem::transmute(0x0819_7c68usize),
            record_destruct: core::mem::transmute(0x0819_7c28usize),
            release_string: core::mem::transmute(0x083d_8b04usize),
        }
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_read_count(_: *mut u8, _: *mut u8, _: u32) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_read_string(_: *mut u8, _: *mut *mut u8) {}
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_clear_words(words: *mut u32) -> *mut u32 { words }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_record_construct(record: *mut StringRecord, _: *const u8, _: *const u8, _: *mut u32, _: u32) -> *mut StringRecord { record }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_decode_entry(owner: *mut u8, _: *mut StringRecord) -> *mut u8 { owner }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_map_value(map: *mut u8, _: *mut *mut u8) -> *mut *mut u8 { map.cast() }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_record_assign(record: *mut StringRecord, _: *mut StringRecord) -> *mut StringRecord { record }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_record_destruct(record: *mut StringRecord) -> *mut StringRecord { record }
#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_release_string(_: *mut *mut u8) {}

#[cfg(not(target_os = "none"))]
static mut OPS: StreamReadStringRecordMapOps = StreamReadStringRecordMapOps {
    read_count: missing_read_count,
    read_string: missing_read_string,
    clear_words: missing_clear_words,
    record_construct: missing_record_construct,
    decode_entry: missing_decode_entry,
    map_value: missing_map_value,
    record_assign: missing_record_assign,
    record_destruct: missing_record_destruct,
    release_string: missing_release_string,
};

#[inline(always)]
unsafe fn ops() -> StreamReadStringRecordMapOps {
    #[cfg(target_os = "none")]
    { unsafe { retail_ops() } }
    #[cfg(not(target_os = "none"))]
    { unsafe { ptr::read_volatile(ptr::addr_of!(OPS)) } }
}

/// Deserializes and applies each string-record entry from `owner` to `map`.
///
/// # Safety
///
/// `owner` and `map` must satisfy the unguarded retailOS stream and map ABIs.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.stream_read_string_record_map")]
#[inline(never)]
pub unsafe extern "C" fn stream_read_string_record_map(owner: *mut u8, map: *mut u8) -> *mut u8 {
    let ops = unsafe { ops() };
    let mut count = 0u32;
    unsafe { (ops.read_count)(owner, ptr::addr_of_mut!(count).cast(), 4) };
    for _ in 0..count {
        let mut string = STATIC_EMPTY_STRING;
        let mut scratch = [0u32; 3];
        let mut record = StringRecord { words: [0; 5] };
        unsafe { (ops.read_string)(owner, ptr::addr_of_mut!(string)) };
        unsafe { (ops.clear_words)(scratch.as_mut_ptr()) };
        unsafe { (ops.record_construct)(ptr::addr_of_mut!(record), ptr::null(), ptr::null(), scratch.as_mut_ptr(), 1) };
        unsafe { (ops.release_string)(scratch.as_mut_ptr().cast()) };
        unsafe { (ops.decode_entry)(owner, ptr::addr_of_mut!(record)) };
        let value = unsafe { (ops.map_value)(map, ptr::addr_of_mut!(string)) };
        unsafe { (ops.record_assign)(value.cast(), ptr::addr_of_mut!(record)) };
        unsafe { (ops.record_destruct)(ptr::addr_of_mut!(record)) };
        unsafe { (ops.release_string)(ptr::addr_of_mut!(string)) };
    }
    owner
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use parking_lot::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());
    static COUNT: AtomicU32 = AtomicU32::new(0);
    static READ_STRINGS: AtomicU32 = AtomicU32::new(0);
    static CONSTRUCTS: AtomicU32 = AtomicU32::new(0);
    static DECODES: AtomicU32 = AtomicU32::new(0);
    static ASSIGNS: AtomicU32 = AtomicU32::new(0);
    static DESTRUCTS: AtomicU32 = AtomicU32::new(0);
    static RELEASES: AtomicU32 = AtomicU32::new(0);
    static mut VALUE: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn read_count(_: *mut u8, target: *mut u8, _: u32) { unsafe { target.cast::<u32>().write(COUNT.load(Ordering::Relaxed)) } }
    unsafe extern "C" fn read_string(_: *mut u8, _: *mut *mut u8) { READ_STRINGS.fetch_add(1, Ordering::Relaxed); }
    unsafe extern "C" fn clear(words: *mut u32) -> *mut u32 { unsafe { words.write(0); words.add(1).write(0); words.add(2).write(0); } words }
    unsafe extern "C" fn construct(record: *mut StringRecord, first: *const u8, second: *const u8, _: *mut u32, flag: u32) -> *mut StringRecord { assert!(first.is_null() && second.is_null()); assert_eq!(flag, 1); CONSTRUCTS.fetch_add(1, Ordering::Relaxed); record }
    unsafe extern "C" fn decode(_: *mut u8, _: *mut StringRecord) -> *mut u8 { DECODES.fetch_add(1, Ordering::Relaxed); ptr::null_mut() }
    unsafe extern "C" fn value(_: *mut u8, _: *mut *mut u8) -> *mut *mut u8 { unsafe { ptr::addr_of_mut!(VALUE) } }
    unsafe extern "C" fn assign(_: *mut StringRecord, _: *mut StringRecord) -> *mut StringRecord { ASSIGNS.fetch_add(1, Ordering::Relaxed); ptr::null_mut() }
    unsafe extern "C" fn destruct(record: *mut StringRecord) -> *mut StringRecord { DESTRUCTS.fetch_add(1, Ordering::Relaxed); record }
    unsafe extern "C" fn release(_: *mut *mut u8) { RELEASES.fetch_add(1, Ordering::Relaxed); }

    fn install(count: u32) -> MutexGuard<'static, ()> {
        let guard = LOCK.lock();
        COUNT.store(count, Ordering::Relaxed);
        READ_STRINGS.store(0, Ordering::Relaxed); CONSTRUCTS.store(0, Ordering::Relaxed); DECODES.store(0, Ordering::Relaxed); ASSIGNS.store(0, Ordering::Relaxed); DESTRUCTS.store(0, Ordering::Relaxed); RELEASES.store(0, Ordering::Relaxed);
        unsafe { OPS = StreamReadStringRecordMapOps { read_count, read_string, clear_words: clear, record_construct: construct, decode_entry: decode, map_value: value, record_assign: assign, record_destruct: destruct, release_string: release }; }
        guard
    }

    #[test]
    fn zero_entries_only_reads_the_count() {
        let _guard = install(0);
        let owner = 0x1234usize as *mut u8;
        assert_eq!(unsafe { stream_read_string_record_map(owner, ptr::null_mut()) }, owner);
        assert_eq!(READ_STRINGS.load(Ordering::Relaxed), 0);
        assert_eq!(RELEASES.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn processes_every_entry_and_releases_both_temporaries() {
        let _guard = install(2);
        unsafe { stream_read_string_record_map(ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(READ_STRINGS.load(Ordering::Relaxed), 2);
        assert_eq!(CONSTRUCTS.load(Ordering::Relaxed), 2);
        assert_eq!(DECODES.load(Ordering::Relaxed), 2);
        assert_eq!(ASSIGNS.load(Ordering::Relaxed), 2);
        assert_eq!(DESTRUCTS.load(Ordering::Relaxed), 2);
        assert_eq!(RELEASES.load(Ordering::Relaxed), 4);
    }
}
