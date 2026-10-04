//! Filename-selected stream factory, `FUN_08209f48` @ `0x08209f48`.
//! Raw extent: 188 bytes through `0x0820a003`: 180 bytes of code (including
//! jump-table branches), then size literals 0x638 and 0x444. The next real
//! function is `bx lr` at 0x0820a004. Independently decoded calls: 13 outbound
//! plain BL, zero predicated BL; two inbound plain BL, zero predicated BL.
//!
//! Classify the filename through 0x08091f84, then allocate and construct one
//! of six stream objects. Classification failure or an unsupported byte returns
//! 1 without changing the output slot; success stores the constructor result
//! and returns 0. The first argument is unused, not a classification output.
//!
//! Deviations: Rust uses a match instead of the ARM branch table, and a byte
//! local instead of the saved r3 stack word. Unported classification and stream
//! constructors remain address-verified retailOS calls; allocation uses the
//! existing operator_new port. Host callbacks must be explicitly installed.

pub type FilenameClassify = unsafe extern "C" fn(*const u8, *mut u8) -> u32;
pub type StreamConstruct = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(not(target_os = "none"))]
pub static mut FILENAME_CLASSIFY: Option<FilenameClassify> = None;
#[cfg(not(target_os = "none"))]
pub static mut STREAM_CONSTRUCTORS: [Option<StreamConstruct>; 6] = [None; 6];
#[cfg(not(target_os = "none"))]
pub static mut STREAM_ALLOCATE: Option<unsafe extern "C" fn(usize) -> *mut u8> = None;

/// Create the stream selected by the filename's retailOS classification.
///
/// # Safety
/// `filename` must satisfy the resident classifier's requirements, including
/// its five-byte suffix read. `out` must be writable on success. Allocations
/// must satisfy the selected constructor; NULL is passed through unchecked.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn stream_create_for_filename(
    _unused: *mut u8, filename: *const u8, out: *mut *mut u8,
) -> u32 {
    let mut kind = 0u8;
    #[cfg(target_os = "none")]
    let classify: FilenameClassify = unsafe { core::mem::transmute(0x0809_1f84usize) };
    #[cfg(not(target_os = "none"))]
    let classify = unsafe { FILENAME_CLASSIFY.expect("filename classifier not installed") };
    if unsafe { classify(filename, &mut kind) } != 0 { return 1; }
    let (size, address) = match kind {
        0 => (0x638, 0x0828_2978usize),
        1 => (0x444, 0x080f_6818usize),
        2 => (0x2e0, 0x081c_80a4usize),
        3 => (0x440, 0x0829_5930usize),
        4 => (0x40, 0x0828_2fa8usize),
        5 => (0x38, 0x0813_83c0usize),
        _ => return 1,
    };
    #[cfg(target_os = "none")]
    let object = unsafe { crate::heap::veneers::operator_new(size) };
    #[cfg(not(target_os = "none"))]
    let object = unsafe { STREAM_ALLOCATE.expect("stream allocator not installed")(size) };
    #[cfg(target_os = "none")]
    let construct: StreamConstruct = unsafe { core::mem::transmute(address) };
    #[cfg(not(target_os = "none"))]
    let construct = {
        let _ = address;
        unsafe { STREAM_CONSTRUCTORS[kind as usize].expect("stream constructor not installed") }
    };
    unsafe { out.write(construct(object)) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    // One test owns these module-private host seams; no shared allocator state.
    static mut SIZE: usize = 0;
    static mut STORAGE: [u32; 398] = [0; 398];
    unsafe extern "C" fn classify(input: *const u8, kind: *mut u8) -> u32 {
        unsafe { kind.write(input.read()); input.add(1).read() as u32 }
    }
    unsafe extern "C" fn allocate(size: usize) -> *mut u8 {
        unsafe { SIZE = size; core::ptr::addr_of_mut!(STORAGE).cast() }
    }
    unsafe extern "C" fn construct(object: *mut u8) -> *mut u8 {
        // Return a distinct pointer: the factory must store the result, not raw allocation.
        unsafe { object.cast::<u32>().write(0x12345678); object.add(4) }
    }
    #[test]
    fn selection_and_failure_preserve_output_contract() {
        unsafe {
            FILENAME_CLASSIFY = Some(classify);
            STREAM_ALLOCATE = Some(allocate);
            STREAM_CONSTRUCTORS = [Some(construct); 6];
            let allocation = core::ptr::addr_of_mut!(STORAGE).cast::<u8>();
            for (kind, size) in [0x638, 0x444, 0x2e0, 0x440, 0x40, 0x38].into_iter().enumerate() {
                let input = [kind as u8, 0];
                let mut out = core::ptr::null_mut();
                assert_eq!(stream_create_for_filename(core::ptr::null_mut(), input.as_ptr(), &mut out), 0);
                assert_eq!(out, allocation.add(4));
                assert_eq!(core::ptr::addr_of!(SIZE).read(), size);
                assert_eq!(allocation.cast::<u32>().read(), 0x12345678);
            }
            // Neither failure path may allocate, construct, or dereference the unused argument.
            STREAM_ALLOCATE = None;
            STREAM_CONSTRUCTORS = [None; 6];
            for input in [[0, 1], [5, 255], [6, 0], [255, 0]] {
                let mut out = allocation;
                assert_eq!(stream_create_for_filename(core::ptr::null_mut(), input.as_ptr(), &mut out), 1);
                assert_eq!(out, allocation);
                assert_eq!(stream_create_for_filename(core::ptr::null_mut(), input.as_ptr(), core::ptr::null_mut()), 1);
            }
            FILENAME_CLASSIFY = None;
        }
    }
}
