//! Bounded file-prefix reader — `FUN_080962f0` @ `0x080962f0`.
//! True extent: 192 bytes, ending at the next push @ `0x080963b0`.
//! Raw words contain five plain outbound BLs, zero predicated BLs; two
//! inbound plain BLs and zero predicated BLs reach this entry.
//!
//! Constructs an 84-byte caller-owned file object with (path, 1, 0,
//! 0x400, 1, 0), checks its +0x1c status, queries length, then reads
//! min(length, capacity). A successful nonzero transfer is sufficient,
//! even when short. Empty files succeed and write one NUL only when
//! capacity is nonzero. Nonempty files are never NUL-terminated; even
//! zero capacity reaches the read operation. Destruction runs on every path.
//!
//! Deliberate deviations: Rust merges the two destructor call sites and
//! does not reproduce register saves. Uninitialized object storage avoids
//! clearing bytes the constructor owns. Private monomorphized operations
//! allow isolated host behavioral fixtures without changing target callees.

use core::ffi::c_void;
use core::mem::MaybeUninit;

trait FileOperations {
    unsafe fn construct(&mut self, file: *mut u8, path: *const u8) -> i32;
    unsafe fn length(&mut self, file: *mut u8, length: *mut u32) -> i32;
    unsafe fn read(&mut self, file: *mut u8, count: u32, buffer: *mut u8, transferred: *mut u32) -> i32;
    unsafe fn destroy(&mut self, file: *mut u8);
}

struct RetailFileOperations;
impl FileOperations for RetailFileOperations {
    #[inline(always)]
    unsafe fn construct(&mut self, file: *mut u8, path: *const u8) -> i32 {
        crate::cxx::transition_addon::silver_controller_transition_addon_construct_from_cstr(
            file, path, 1, 0, 0x400, 1, 0,
        );
        file.cast::<i32>().add(7).read()
    }
    #[inline(always)]
    unsafe fn length(&mut self, file: *mut u8, length: *mut u32) -> i32 {
        crate::ft::system::ft_platform_file_length(file.cast::<c_void>(), length)
    }
    #[inline(always)]
    unsafe fn read(&mut self, file: *mut u8, count: u32, buffer: *mut u8, transferred: *mut u32) -> i32 {
        crate::fs::file_read::retail_file_read(file.cast::<c_void>(), count, buffer, transferred)
    }
    #[inline(always)]
    unsafe fn destroy(&mut self, file: *mut u8) {
        crate::cxx::transition_addon::silver_controller_transition_addon_destroy(file);
    }
}

#[inline(always)]
unsafe fn read_prefix(ops: &mut impl FileOperations, path: *const u8, buffer: *mut u8, capacity: u32) -> u32 {
    let mut storage = [MaybeUninit::<u32>::uninit(); 21];
    let file = storage.as_mut_ptr().cast::<u8>();
    let mut length = MaybeUninit::<u32>::uninit();
    let result = if ops.construct(file, path) != 0 || ops.length(file, length.as_mut_ptr()) != 0 {
        0
    } else {
        let length = length.assume_init();
        if length == 0 {
            if capacity != 0 { buffer.write(0); }
            1
        } else {
            let mut transferred = MaybeUninit::<u32>::uninit();
            let status = ops.read(file, length.min(capacity), buffer, transferred.as_mut_ptr());
            u32::from(status == 0 && transferred.assume_init() != 0)
        }
    };
    ops.destroy(file);
    result
}

/// Reads a bounded prefix of a file, returning one on success and zero on error.
/// Original: `0x080962f0`, 192 bytes; five outbound plain BLs, none predicated.
///
/// # Safety
/// `path` must satisfy the retail constructor's C-string contract. `buffer`
/// must be writable for `capacity` bytes. The resident file subsystem must
/// be available; object storage uses the firmware's 32-bit layout, not the
/// native-pointer host model used by the length-query port.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn retail_file_read_prefix(path: *mut u8, buffer: *mut u8, capacity: u32) -> u32 {
    read_prefix(&mut RetailFileOperations, path, buffer, capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        open_status: i32,
        length_status: i32,
        read_status: i32,
        data: &'static [u8],
        transferred: u32,
        length_calls: u32,
        read_count: Option<u32>,
        destroyed: bool,
    }
    impl Fixture {
        fn new(data: &'static [u8]) -> Self {
            Self { open_status: 0, length_status: 0, read_status: 0, data,
                transferred: data.len() as u32, length_calls: 0,
                read_count: None, destroyed: false }
        }
    }
    impl FileOperations for Fixture {
        unsafe fn construct(&mut self, _: *mut u8, _: *const u8) -> i32 { self.open_status }
        unsafe fn length(&mut self, _: *mut u8, length: *mut u32) -> i32 {
            self.length_calls += 1;
            if self.length_status == 0 { length.write(self.data.len() as u32); }
            self.length_status
        }
        unsafe fn read(&mut self, _: *mut u8, count: u32, buffer: *mut u8, transferred: *mut u32) -> i32 {
            self.read_count = Some(count);
            if self.read_status == 0 {
                let actual = count.min(self.transferred);
                core::ptr::copy_nonoverlapping(self.data.as_ptr(), buffer, actual as usize);
                transferred.write(actual);
            }
            self.read_status
        }
        unsafe fn destroy(&mut self, _: *mut u8) { assert!(!self.destroyed); self.destroyed = true; }
    }

    #[test]
    fn bounded_and_short_reads_leave_the_tail_untouched() {
        for (capacity, transferred, expected) in [(2, 4, 2), (6, 4, 4), (4, 1, 1)] {
            let mut fixture = Fixture::new(b"abcd");
            fixture.transferred = transferred;
            let mut buffer = [0xa5; 8];
            assert_eq!(unsafe { read_prefix(&mut fixture, core::ptr::null(), buffer.as_mut_ptr(), capacity) }, 1);
            assert_eq!(&buffer[..expected], &b"abcd"[..expected]);
            assert!(buffer[expected..].iter().all(|&byte| byte == 0xa5));
            assert_eq!(fixture.read_count, Some(capacity.min(4)));
            assert!(fixture.destroyed);
        }
    }

    #[test]
    fn empty_file_nul_and_zero_capacity_are_distinct() {
        for capacity in [0, 1, u32::MAX] {
            let mut fixture = Fixture::new(b"");
            let mut buffer = [0xa5; 2];
            let pointer = if capacity == 0 { core::ptr::null_mut() } else { buffer.as_mut_ptr() };
            assert_eq!(unsafe { read_prefix(&mut fixture, core::ptr::null(), pointer, capacity) }, 1);
            assert_eq!(buffer, [if capacity == 0 { 0xa5 } else { 0 }, 0xa5]);
            assert_eq!(fixture.read_count, None);
            assert!(fixture.destroyed);
        }
        let mut fixture = Fixture::new(b"abcd");
        let mut buffer = [0xa5; 2];
        assert_eq!(unsafe { read_prefix(&mut fixture, core::ptr::null(), buffer.as_mut_ptr(), 0) }, 0);
        assert_eq!(fixture.read_count, Some(0));
        assert_eq!(buffer, [0xa5; 2]);
        assert!(fixture.destroyed);
    }

    #[test]
    fn failures_preserve_output_and_always_destroy() {
        for failure in 0..4 {
            let mut fixture = Fixture::new(b"abcd");
            match failure {
                0 => fixture.open_status = -7,
                1 => fixture.length_status = 2,
                2 => fixture.read_status = -3,
                _ => fixture.transferred = 0,
            }
            let mut buffer = [0xa5; 4];
            assert_eq!(unsafe { read_prefix(&mut fixture, core::ptr::null(), buffer.as_mut_ptr(), 4) }, 0);
            assert_eq!(buffer, [0xa5; 4]);
            assert_eq!(fixture.length_calls, u32::from(failure != 0));
            assert_eq!(fixture.read_count, if failure < 2 { None } else { Some(4) });
            assert!(fixture.destroyed);
        }
    }
}
