//! `cff_sid_to_string` — original: `FUN_080d3f74` @ **0x080d3f74**
//! (**172 bytes**, `0x080d3f74..0x080d4020`; the next function starts at
//! `0x080d4020`).
//!
//! Raw ARM decoding finds five unconditional inbound plain `bl` instructions,
//! no predicated inbound `bl`, three unconditional outgoing plain `bl`
//! instructions, no predicated outgoing `bl`, one virtual `blx`, and one
//! conditional tail `b`.  The routine returns null for SID `0xffff`.  Custom
//! SIDs (`>= 391`) tail-call the unported helper at `0x080a8294` with
//! `sid - 391`; standard SIDs ask the PSNames service at vtable slot `+0x14`,
//! then allocate and copy a new
//! NUL-terminated string through the CFF library's `memory` field (`+0x1c`).
//!
//! Deliberate deviation: Rust cannot emit the conditional tail branch.  The
//! custom-SID path calls the exact fixed firmware address on target and a
//! replaceable host seam in tests; `custom_arg3` is preserved because raw ARM
//! forwards r3 unchanged but its semantic role is not recovered.

use core::ptr;

use crate::ft::memory::{ft_mem_alloc, FtMemory};
use crate::libc::rt_memcpy::__rt_memcpy;
use crate::libc::strlen::strlen;

const CUSTOM_SID_FIRST: u32 = 391;
const INVALID_SID: u32 = 0xffff;
const RETAIL_CUSTOM_SID_TO_STRING: usize = 0x080a_8294;

type StandardSidString = unsafe extern "C" fn(u32) -> *const u8;
type CustomSidString = unsafe extern "C" fn(*mut u8, u32, *const u8, *mut u8) -> *mut u8;

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn source_memory(source: *mut u8) -> *mut FtMemory {
    let library = ptr::read_volatile(source.cast::<*mut u8>());
    ptr::read_volatile(library.add(0x1c).cast::<*mut FtMemory>())
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostCffSidSource {
    pub library: *mut HostCffSidLibrary,
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostCffSidLibrary {
    pub memory: *mut FtMemory,
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn source_memory(source: *mut u8) -> *mut FtMemory {
    (*source.cast::<HostCffSidSource>()).library.as_ref().unwrap().memory
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn standard_sid_string(service: *const u8, sid: u32) -> *const u8 {
    let address = ptr::read_volatile(service.add(0x14).cast::<u32>());
    let string: StandardSidString = core::mem::transmute(address as usize);
    string(sid)
}

#[cfg(not(target_os = "none"))]
#[repr(C)]
pub struct HostPsNamesService {
    pub slots_before_standard_string: [usize; 5],
    pub standard_string: StandardSidString,
}

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn standard_sid_string(service: *const u8, sid: u32) -> *const u8 {
    ((*service.cast::<HostPsNamesService>()).standard_string)(sid)
}

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn custom_sid_string(source: *mut u8, sid: u32, service: *const u8, custom_arg3: *mut u8) -> *mut u8 {
    let custom: CustomSidString = core::mem::transmute(RETAIL_CUSTOM_SID_TO_STRING);
    custom(source, sid, service, custom_arg3)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_custom_sid_string(
    _source: *mut u8, _sid: u32, _service: *const u8, _custom_arg3: *mut u8,
) -> *mut u8 {
    ptr::null_mut()
}

#[cfg(not(target_os = "none"))]
pub static mut CFF_CUSTOM_SID_TO_STRING: CustomSidString = missing_custom_sid_string;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn custom_sid_string(source: *mut u8, sid: u32, service: *const u8, custom_arg3: *mut u8) -> *mut u8 {
    ptr::read_volatile(ptr::addr_of!(CFF_CUSTOM_SID_TO_STRING))(source, sid, service, custom_arg3)
}

/// Resolves a CFF SID to an owned string.
///
/// # Safety
/// `source` must have the retail CFF source layout; its library's `+0x1c`
/// memory pointer must be valid when a standard SID resolves.  `service` is
/// either null or has a callable standard-string slot.  `custom_arg3` has the
/// raw helper's unrecovered ABI role and is forwarded only on custom SIDs.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn cff_sid_to_string(
    source: *mut u8,
    sid: u32,
    service: *const u8,
    custom_arg3: *mut u8,
) -> *mut u8 {
    if sid == INVALID_SID {
        return ptr::null_mut();
    }
    if sid >= CUSTOM_SID_FIRST {
        return custom_sid_string(source, sid - CUSTOM_SID_FIRST, service, custom_arg3);
    }
    if service.is_null() {
        return ptr::null_mut();
    }

    let standard = standard_sid_string(service, sid);
    if standard.is_null() {
        return ptr::null_mut();
    }
    let length = strlen(standard);
    let mut error = 0;
    let copy = ft_mem_alloc(source_memory(source), length.wrapping_add(1) as i32, &mut error);
    if error == 0 {
        __rt_memcpy(copy, standard, length);
        copy.add(length).write(0);
    }
    copy
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::boxed::Box;
    use std::vec;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut CUSTOM_ARGS: (*mut u8, u32, *const u8, *mut u8) = (ptr::null_mut(), 0, ptr::null(), ptr::null_mut());

    unsafe extern "C" fn alloc(_memory: *mut FtMemory, size: i32) -> *mut u8 {
        Box::into_raw(vec![0; size as usize].into_boxed_slice()) as *mut u8
    }
    unsafe extern "C" fn free(_memory: *mut FtMemory, _block: *mut u8) {}
    unsafe extern "C" fn realloc(_memory: *mut FtMemory, _old: i32, _new: i32, block: *mut u8) -> *mut u8 { block }
    unsafe extern "C" fn standard(sid: u32) -> *const u8 {
        match sid { 0 => b".notdef\0".as_ptr(), 390 => b"Semibold\0".as_ptr(), _ => ptr::null() }
    }
    unsafe extern "C" fn custom(source: *mut u8, sid: u32, service: *const u8, arg3: *mut u8) -> *mut u8 {
        CUSTOM_ARGS = (source, sid, service, arg3);
        0x1234usize as *mut u8
    }

    fn fixture() -> (FtMemory, HostCffSidLibrary, HostCffSidSource, HostPsNamesService) {
        let memory = FtMemory { user: ptr::null_mut(), alloc, free, realloc };
        let library = HostCffSidLibrary { memory: (&memory as *const FtMemory).cast_mut() };
        let source = HostCffSidSource { library: (&library as *const HostCffSidLibrary).cast_mut() };
        let service = HostPsNamesService { slots_before_standard_string: [0; 5], standard_string: standard };
        (memory, library, source, service)
    }

    #[test]
    fn standard_sid_is_copied_and_nul_terminated() {
        let (mut memory, mut library, mut source, service) = fixture();
        library.memory = &mut memory;
        source.library = &mut library;
        let name = unsafe { cff_sid_to_string((&mut source as *mut HostCffSidSource).cast(), 390, (&service as *const HostPsNamesService).cast(), ptr::null_mut()) };
        assert_eq!(unsafe { core::slice::from_raw_parts(name, 9) }, b"Semibold\0");
    }

    #[test]
    fn invalid_and_unavailable_standard_sids_return_null() {
        let (_memory, _library, mut source, service) = fixture();
        assert!(unsafe { cff_sid_to_string((&mut source as *mut HostCffSidSource).cast(), INVALID_SID, (&service as *const HostPsNamesService).cast(), ptr::null_mut()) }.is_null());
        assert!(unsafe { cff_sid_to_string((&mut source as *mut HostCffSidSource).cast(), 1, (&service as *const HostPsNamesService).cast(), ptr::null_mut()) }.is_null());
    }

    #[test]
    fn custom_sid_forwards_the_raw_tail_abi() {
        let _guard = LOCK.lock();
        let (_memory, _library, mut source, service) = fixture();
        let old = unsafe { CFF_CUSTOM_SID_TO_STRING };
        unsafe { CFF_CUSTOM_SID_TO_STRING = custom; }
        let arg3 = 0x5678usize as *mut u8;
        let result = unsafe { cff_sid_to_string((&mut source as *mut HostCffSidSource).cast(), CUSTOM_SID_FIRST + 4, (&service as *const HostPsNamesService).cast(), arg3) };
        unsafe { CFF_CUSTOM_SID_TO_STRING = old; }
        assert_eq!(result as usize, 0x1234);
        assert_eq!(unsafe { CUSTOM_ARGS.1 }, 4);
        assert_eq!(unsafe { CUSTOM_ARGS.3 }, arg3);
    }
}
