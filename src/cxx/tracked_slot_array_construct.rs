//! Tracked slot-array constructor: `FUN_083d543c` @ **0x083d543c**.
//! True extent **196 bytes**, [0x083d543c, 0x083d5500): 160 instruction
//! bytes, one record literal and 32 bytes of diagnostic text. Next entry
//! begins with `cmp r1, #0`. Whole-image A32 decoding finds one incoming
//! plain BL (0x081ef170), no predicated incoming BLs; nine outgoing plain
//! BLs, no predicated outgoing BLs.
//!
//! Initialize six fields, allocate wrapping `slots * 4` bytes, zero them,
//! fetch the tracker name from record 0x0897cc7c, allocate its strlen bytes,
//! and strncpy that many bytes starting one byte into names of length <=10
//! or two bytes into longer names. Padding supplies the terminating NUL;
//! empty names allocate zero bytes. Return the original object without an
//! allocation-failure guard. The caller constructs a ten-slot array with
//! options zero and growth two, independently of its other slot array.
//!
//! Deliberate deviations: native pointer fields widen on hosts, while slot
//! storage remains u32. Hosts inject the runtime name and allocation boundary.
//! The IRAM zero veneer calls the existing port directly; the disabled
//! diagnostic receives only its observable first argument. LLVM folds the
//! two adjacent post-allocation strlen calls and removes the inert diagnostic.
//! Volatile function-pointer dispatch prevents LLVM builtin substitution.

use core::ptr;

#[repr(C)]
pub struct TrackedSlotArray {
    pub data: *mut u32,
    pub slots: u32,
    pub used: u32,
    pub options: u32,
    pub growth: u32,
    pub tracker_label: *mut u8,
}

#[cfg(target_os = "none")]
const _: [(); 24] = [(); core::mem::size_of::<TrackedSlotArray>()];

#[cfg(not(test))]
static ALLOCATE: unsafe extern "C" fn(usize) -> *mut u8 = crate::runtime::malloc_rt::malloc;
#[cfg(test)]
static mut ALLOCATE: unsafe extern "C" fn(usize) -> *mut u8 = crate::runtime::malloc_rt::malloc;
static ZERO: unsafe extern "C" fn(*mut u8, usize) -> *mut u8 = crate::libc::memzero::memzero_aligned;
static COPY: unsafe extern "C" fn(*mut u8, *const u8, usize) -> *mut u8 = crate::libc::strncpy::strncpy;

/// Host source for the firmware's runtime-initialized tracker record.
#[cfg(not(target_os = "none"))]
pub static mut HOST_TRACKER_NAME: *const u8 = ptr::null();

unsafe fn tracker_name() -> *const u8 {
    #[cfg(target_os = "none")]
    { crate::app::tracker_record::tracker_record_name(0x0897_cc7c as *const u32) as *const u8 }
    #[cfg(not(target_os = "none"))]
    { ptr::addr_of!(HOST_TRACKER_NAME).read_volatile() }
}

/// # Safety
/// `array` must be writable and aligned. The runtime tracker name must be a
/// readable NUL-terminated string (with a valid one-past pointer when empty).
/// Allocations must be writable for the requested sizes; old fields are not
/// freed. Nonzero allocations may not fail, as in the original constructor.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn tracked_slot_array_construct(
    array: *mut TrackedSlotArray, options: u32, slots: u32, growth: u32,
) -> *mut TrackedSlotArray {
    (*array).data = ptr::null_mut();
    (*array).slots = slots;
    (*array).used = 0;
    (*array).options = options;
    (*array).growth = growth;
    (*array).tracker_label = ptr::null_mut();
    let allocate = ptr::addr_of!(ALLOCATE).read_volatile();
    let data = allocate(slots.wrapping_shl(2) as usize);
    (*array).data = data.cast();
    ptr::addr_of!(ZERO).read_volatile()(data, (*array).slots.wrapping_shl(2) as usize);
    let name = tracker_name();
    let label = allocate(crate::libc::strlen::strlen(name));
    (*array).tracker_label = label;
    let copy_len = crate::libc::strlen::strlen(name);
    let skip = if crate::libc::strlen::strlen(name) <= 10 { 1 } else { 2 };
    ptr::addr_of!(COPY).read_volatile()(label, name.add(skip), copy_len);
    super::tracker_diagnostic_no_op::tracker_diagnostic_no_op(array.cast());
    array
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut STORAGE: [[u32; 32]; 2] = [[0; 32]; 2];
    static mut REQUESTS: [usize; 2] = [0; 2];
    static mut CALLS: usize = 0;

    unsafe extern "C" fn allocate(bytes: usize) -> *mut u8 {
        assert!(bytes <= 128);
        let index = CALLS;
        CALLS += 1;
        REQUESTS[index] = bytes;
        ptr::addr_of_mut!(STORAGE).cast::<u32>().add(index * 32).cast()
    }

    struct Restore(unsafe extern "C" fn(usize) -> *mut u8, *const u8);
    impl Drop for Restore {
        fn drop(&mut self) { unsafe {
            ptr::addr_of_mut!(ALLOCATE).write(self.0);
            ptr::addr_of_mut!(HOST_TRACKER_NAME).write(self.1);
        } }
    }

    #[test]
    fn initializes_fields_and_preserves_allocation_boundaries_and_name_padding() {
        let _lock = LOCK.lock();
        unsafe {
            let _restore = Restore(ptr::addr_of!(ALLOCATE).read(), ptr::addr_of!(HOST_TRACKER_NAME).read());
            ptr::addr_of_mut!(ALLOCATE).write(allocate);
            for name in [b"\0\0".as_slice(), b"X\0", b"Xabcdefghi\0", b"XXabcdefghi\0", b"XXabcdefghijkl\0"] {
                for slots in [0, 1, 10, 0x4000_0000, 0x8000_0001] {
                    ptr::addr_of_mut!(STORAGE).write([[0xa5a5_a5a5; 32]; 2]);
                    CALLS = 0;
                    HOST_TRACKER_NAME = name.as_ptr();
                    #[repr(C)]
                    struct Fixture { before: u32, array: TrackedSlotArray, after: u32 }
                    let mut fixture = Fixture { before: 0x12345678, after: 0xabcdef01,
                        array: TrackedSlotArray { data: 1usize as *mut u32, slots: 99, used: 77,
                            options: 88, growth: 66, tracker_label: 1usize as *mut u8 } };
                    let array = ptr::addr_of_mut!(fixture.array);
                    assert_eq!(tracked_slot_array_construct(array, 0xfedcba98, slots, 0x87654321), array);
                    assert_eq!(((*array).slots, (*array).used, (*array).options, (*array).growth),
                        (slots, 0, 0xfedcba98, 0x87654321));
                    assert_eq!((fixture.before, fixture.after), (0x12345678, 0xabcdef01));
                    let len = name.iter().position(|&byte| byte == 0).unwrap();
                    let bytes = slots.wrapping_shl(2) as usize;
                    assert_eq!(ptr::addr_of!(REQUESTS).read(), [bytes, len]);
                    let data = core::slice::from_raw_parts((*array).data.cast::<u8>(), 128);
                    assert!(data[..bytes].iter().all(|&b| b == 0));
                    assert!(data[bytes..].iter().all(|&b| b == 0xa5));
                    let label = core::slice::from_raw_parts((*array).tracker_label, 128);
                    let skip = if len <= 10 { 1 } else { 2 };
                    for index in 0..len {
                        assert_eq!(label[index], if index + skip < len { name[index + skip] } else { 0 });
                    }
                    assert!(label[len..].iter().all(|&b| b == 0xa5));
                }
            }
        }
    }
}
