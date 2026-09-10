//! Playlist-pointer string-table marker.
//!
//! The table object at 0x08a79c10 lies beyond the decrypted osos body; only
//! its literal address is observable here. The original does not dereference
//! it itself: `string_table_set_decimal` receives it unchanged.

const PLAYLIST_POINTER_TABLE: *mut u8 = 0x08a7_9c10 as *mut u8;
const PLAYLIST_POINTER_KEY: &[u8] = b"PlaylistPtr\0";

/// set_playlist_pointer_marker_if — original: `FUN_08219eec` @ 0x08219eec
/// (72 bytes, 0x08219eec..0x08219f34 including the two literal-pool words;
/// the next separately linked function begins at 0x08219f3c). Decoding every
/// ARM B/BL immediate in osos.dec finds 11 direct `bl` callers, all
/// unconditional and none predicated; three further unconditional `b` tail
/// calls enter at 0x08130fc8, 0x08232998, and 0x08239c14.
///
/// When `enabled` is nonzero, makes a temporary COW string for the literal
/// `"PlaylistPtr"`, writes decimal 1 under that key through
/// `string_table_set_decimal` at the literal table address, then releases the
/// temporary. It returns 1 in either case. Raw ARM gives r2 its only
/// semantic role; r0 and r1 are saved only into stack slots later overwritten
/// by the decimal value. r3 is saved into the COW result slot, but direct
/// callers do not establish it and the constructor overwrites that slot. All
/// four ABI slots remain present so existing callers retain their exact
/// calling convention. The original performs no NULL guard because none of
/// the caller-provided slots are dereferenced.
///
/// Deliberate deviations: none. The target path calls the existing Rust ports
/// for the COW-string constructor/release and decimal string-table writer;
/// host tests install that writer's documented seams to observe the result.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn set_playlist_pointer_marker_if(
    _: *mut u8,
    _: *mut u8,
    enabled: u32,
    _: *mut u8,
) -> u32 {
    if enabled != 0 {
        let mut key = core::mem::MaybeUninit::<*mut u8>::uninit();
        let key = unsafe {
            crate::cxx::string::cxx_string_from_cstr(
                key.as_mut_ptr(),
                PLAYLIST_POINTER_KEY.as_ptr(),
            )
        };
        let value = 1i32;
        unsafe {
            crate::app::string_table::string_table_set_decimal(
                PLAYLIST_POINTER_TABLE,
                key,
                core::ptr::addr_of!(value),
            );
            crate::cxx::string::cxx_string_release(key);
        }
    }
    1
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::app::string_table::{StringTableAssignOps, STRING_TABLE_ASSIGN_OPS};
    use crate::printf::printf_api::{PrintfEngineFn, PRINTF_ENGINE};
    use crate::heap::types::{HeapDescriptor, HeapDescriptorDescriptor};
    use crate::heap::veneers::{HeapVeneerOps, HEAP_OPS};
    use core::ffi::c_void;
    use core::ptr;
    use std::ffi::CStr;
    use std::sync::{Mutex, MutexGuard};
    use std::vec::Vec;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut ASSIGNMENT: Option<(usize, Vec<u8>, Vec<u8>)> = None;

    const ARENA_SIZE: usize = 1024;

    #[repr(C, align(8))]
    struct Arena([u8; ARENA_SIZE]);

    static mut ARENA: Arena = Arena([0; ARENA_SIZE]);
    static mut ARENA_USED: usize = 0;

    struct OpsGuard {
        assign: StringTableAssignOps,
        engine: PrintfEngineFn,
    }

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(STRING_TABLE_ASSIGN_OPS), self.assign);
                ptr::write_volatile(ptr::addr_of_mut!(PRINTF_ENGINE), self.engine);
            }
        }
    }

    struct ArenaGuard {
        ops: HeapVeneerOps,
    }

    impl Drop for ArenaGuard {
        fn drop(&mut self) {
            unsafe {
                ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), self.ops);
            }
        }
    }

    unsafe extern "C" fn arena_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        _tag: usize,
    ) -> *mut u8 {
        let used = unsafe { ARENA_USED };
        let aligned = (size + 7) & !7;
        if used + aligned > ARENA_SIZE {
            return ptr::null_mut();
        }
        unsafe {
            ARENA_USED = used + aligned;
            ptr::addr_of_mut!(ARENA.0).cast::<u8>().add(used)
        }
    }

    unsafe extern "C" fn arena_free(
        _heap: *mut HeapDescriptorDescriptor,
        _ptr: *mut u8,
        _tag: usize,
    ) {
    }

    unsafe extern "C" fn arena_create(
        descriptor: *mut HeapDescriptor,
        _start: *mut u8,
        _size: usize,
    ) -> *mut HeapDescriptorDescriptor {
        descriptor.cast()
    }

    unsafe extern "C" fn decimal_engine(
        fmt: *const u8,
        putc: unsafe extern "C" fn(u8, *mut c_void),
        context: *mut c_void,
        arguments: *const u32,
    ) -> i32 {
        assert_eq!(unsafe { CStr::from_ptr(fmt.cast()).to_bytes() }, b"%d");
        assert_eq!(unsafe { arguments.cast::<i32>().read() }, 1);
        unsafe { putc(b'1', context) };
        1
    }

    unsafe extern "C" fn record_assign(
        table: *mut u8,
        key: *mut *mut u8,
        value: *mut *mut u8,
    ) {
        let key = unsafe { CStr::from_ptr((*key).cast()).to_bytes().to_vec() };
        let value = unsafe { CStr::from_ptr((*value).cast()).to_bytes().to_vec() };
        unsafe { ASSIGNMENT = Some((table as usize, key, value)) };
    }

    fn install() -> (MutexGuard<'static, ()>, OpsGuard) {
        let lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        unsafe {
            let guard = OpsGuard {
                assign: ptr::read_volatile(ptr::addr_of!(STRING_TABLE_ASSIGN_OPS)),
                engine: ptr::read_volatile(ptr::addr_of!(PRINTF_ENGINE)),
            };
            ptr::write_volatile(
                ptr::addr_of_mut!(STRING_TABLE_ASSIGN_OPS),
                StringTableAssignOps { assign: record_assign },
            );
            ptr::write_volatile(ptr::addr_of_mut!(PRINTF_ENGINE), decimal_engine);
            ASSIGNMENT = None;
            (lock, guard)
        }
    }

    #[test]
    fn marks_playlist_pointer_only_when_enabled() {
        let (_lock, _restore) = install();
        let _heap = crate::heap::veneers::tests::mock_heap();
        let _arena = unsafe {
            ARENA_USED = 0;
            let previous = ptr::read_volatile(ptr::addr_of!(HEAP_OPS));
            let mut active = previous;
            active.alloc = arena_alloc;
            active.free = arena_free;
            active.create = arena_create;
            ptr::write_volatile(ptr::addr_of_mut!(HEAP_OPS), active);
            ArenaGuard { ops: previous }
        };

        assert_eq!(
            unsafe {
                set_playlist_pointer_marker_if(
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                )
            },
            1,
        );
        assert_eq!(unsafe { ASSIGNMENT.clone() }, None);

        for enabled in [1, u32::MAX] {
            unsafe {
                ASSIGNMENT = None;
                assert_eq!(
                    set_playlist_pointer_marker_if(
                        ptr::null_mut(),
                        ptr::null_mut(),
                        enabled,
                        ptr::null_mut(),
                    ),
                    1,
                );
            }
            assert_eq!(
                unsafe { ASSIGNMENT.clone() },
                Some((0x08a7_9c10, b"PlaylistPtr".to_vec(), b"1".to_vec())),
            );
        }
    }
}
