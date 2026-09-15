//! Resource-fork path construction.
//!
//! `ft_resource_fork_path` — original: `FUN_080c9604` @ 0x080c9604 (172
//! bytes; 5 direct `bl` call sites, all unconditional).
//!
//! The raw ARM body is 0x080c9604..0x080c96b0; 0x080c96b0 starts a distinct
//! function. It allocates `strlen(path) + strlen(resource_name) + 1` through
//! `ft_mem_alloc`, then inserts `resource_name` immediately before the final
//! slash-delimited path component. With no slash, it yields `resource_name +
//! path`. Allocation failure returns null. The original's unchecked 32-bit
//! length arithmetic, unguarded pointers, and its redundant NUL after the
//! copied directory prefix are deliberate here. Behavioral semantics have no
//! deviations. Codegen deliberately inlines `ft_mem_alloc` (and its zero
//! fill) plus the string helpers, rather than retaining the five stock `bl`s.
use crate::ft::memory::{ft_mem_alloc, FtMemory};
use crate::libc::{strcat::strcat, strchr::strrchr, strncpy::strncpy};
use crate::libc::strlen::strlen;

/// Allocate a path with `resource_name` inserted before its last component.
///
/// # Safety
/// `memory` must be a valid FreeType allocator. `path` and `resource_name`
/// must point to NUL-terminated readable strings.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ft_resource_fork_path(
    memory: *mut FtMemory,
    mut path: *const u8,
    resource_name: *const u8,
) -> *mut u8 {
    let size = (strlen(path) as u32)
        .wrapping_add(strlen(resource_name) as u32)
        .wrapping_add(1) as i32;
    let mut error = 0;
    let output = ft_mem_alloc(memory, size, &mut error);
    if error != 0 {
        return core::ptr::null_mut();
    }

    let slash = strrchr(path, b'/' as i32);
    if slash.is_null() {
        *output = 0;
    } else {
        let prefix_len = slash.offset_from(path) as usize + 1;
        strncpy(output, path, prefix_len);
        *output.add(prefix_len) = 0;
        path = slash.add(1);
    }
    strcat(output, resource_name);
    strcat(output, path);
    output
}

mod tests {
    use super::*;

    struct HostAllocator {
        storage: [u8; 128],
        fail: bool,
        calls: usize,
    }

    unsafe extern "C" fn allocate(memory: *mut FtMemory, _size: i32) -> *mut u8 {
        let allocator = (*memory).user.cast::<HostAllocator>();
        (*allocator).calls += 1;
        if (*allocator).fail {
            core::ptr::null_mut()
        } else {
            (*allocator).storage.as_mut_ptr()
        }
    }

    unsafe extern "C" fn free(_memory: *mut FtMemory, _block: *mut u8) {}

    unsafe extern "C" fn reallocate(
        _memory: *mut FtMemory,
        _cur: i32,
        _new: i32,
        block: *mut u8,
    ) -> *mut u8 {
        block
    }

    fn fixture(fail: bool) -> (HostAllocator, FtMemory) {
        let mut allocator = HostAllocator { storage: [0xa5; 128], fail, calls: 0 };
        let memory = FtMemory {
            user: (&raw mut allocator).cast(),
            alloc: allocate,
            free,
            realloc: reallocate,
        };
        (allocator, memory)
    }

    #[test]
    fn inserts_resource_name_before_the_final_component() {
        unsafe {
            let (mut allocator, mut memory) = fixture(false);
            memory.user = (&raw mut allocator).cast();
            let path = b"fonts/ui/font.ttf\0";
            let resource = b"resource.frk/\0";
            let output = ft_resource_fork_path(&mut memory, path.as_ptr(), resource.as_ptr());
            assert_eq!(allocator.calls, 1);
            assert_eq!(
                core::slice::from_raw_parts(output, b"fonts/ui/resource.frk/font.ttf\0".len()),
                b"fonts/ui/resource.frk/font.ttf\0"
            );
        }
    }

    #[test]
    fn no_slash_prepends_resource_name() {
        unsafe {
            let (mut allocator, mut memory) = fixture(false);
            memory.user = (&raw mut allocator).cast();
            let output = ft_resource_fork_path(
                &mut memory,
                b"font.ttf\0".as_ptr(),
                b"resource.frk/\0".as_ptr(),
            );
            assert_eq!(
                core::slice::from_raw_parts(output, b"resource.frk/font.ttf\0".len()),
                b"resource.frk/font.ttf\0"
            );
        }
    }

    #[test]
    fn allocation_error_returns_null_before_accessing_the_output() {
        unsafe {
            let (mut allocator, mut memory) = fixture(true);
            memory.user = (&raw mut allocator).cast();
            assert!(ft_resource_fork_path(
                &mut memory,
                b"dir/file\0".as_ptr(),
                b"resource.frk/\0".as_ptr(),
            ).is_null());
            assert_eq!(allocator.calls, 1);
        }
    }
}
