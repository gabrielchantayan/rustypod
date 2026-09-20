//! Builds a callback result through retailOS's opaque collection worker.

/// callback_result_build — original: `FUN_083d22e4` @ 0x083d22e4 (68 bytes;
/// 0x083d22e4..0x083d2328).
///
/// Raw ARM establishes three inbound plain `bl` call sites and no predicated
/// inbound `bl` call sites. It calls the unported worker at 0x083d2e80 once,
/// forwarding `context` and `input`, then copies the worker's two words and
/// trailing status byte into `output`. The worker's concrete identity is not
/// established, so the target build deliberately retains that direct retailOS
/// call rather than inventing a Rust seam. Host tests substitute it with a
/// recording worker. There are no other deliberate deviations.
#[repr(C)]
pub struct CallbackResult {
    pub first: u32,
    pub second: u32,
    pub status: u8,
}

type RetailResultBuilder = unsafe extern "C" fn(*mut CallbackResult, *mut u8, *const u32);

#[cfg(not(test))]
unsafe fn invoke_retail_result_builder(
    output: *mut CallbackResult,
    context: *mut u8,
    input: *const u32,
) {
    let retail_result_builder: RetailResultBuilder = core::mem::transmute(0x083d2e80usize);
    retail_result_builder(output, context, input);
}

#[cfg(test)]
unsafe fn invoke_retail_result_builder(
    output: *mut CallbackResult,
    context: *mut u8,
    input: *const u32,
) {
    test_retail_result_builder(output, context, input);
}

/// # Safety
///
/// `output` must be aligned and writable for two `u32` words followed by one
/// byte. `context` and `input` are forwarded unchanged to the retail worker;
/// their validity requirements are defined by that unported worker.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn callback_result_build(
    output: *mut CallbackResult,
    context: *mut u8,
    input: *const u32,
) {
    let mut local_result = core::mem::MaybeUninit::<CallbackResult>::uninit();

    invoke_retail_result_builder(local_result.as_mut_ptr(), context, input);
    let local_result = local_result.assume_init();
    (*output).first = local_result.first;
    (*output).second = local_result.second;
    (*output).status = local_result.status;
}

#[cfg(test)]
static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
#[cfg(test)]
static mut LAST_CONTEXT: *mut u8 = core::ptr::null_mut();
#[cfg(test)]
static mut LAST_INPUT: *const u32 = core::ptr::null();

#[cfg(test)]
unsafe fn test_retail_result_builder(
    output: *mut CallbackResult,
    context: *mut u8,
    input: *const u32,
) {
    LAST_CONTEXT = context;
    LAST_INPUT = input;
    output.write(CallbackResult {
        first: input.read(),
        second: input.add(1).read(),
        status: ((*context).wrapping_add(1)) & 1,
    });
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{callback_result_build, CallbackResult, LAST_CONTEXT, LAST_INPUT, TEST_LOCK};
    #[repr(C, align(4))]
    struct ResultBytes([u8; 12]);


    #[test]
    fn forwards_worker_arguments_and_copies_all_result_fields() {
        let _guard = TEST_LOCK.lock();
        let input = [0x1122_3344, 0xaabb_ccdd];
        let mut context = 0x34;
        let mut output = CallbackResult {
            first: 0,
            second: 0,
            status: 0xff,
        };

        unsafe {
            callback_result_build(&mut output, &mut context, input.as_ptr());

            assert_eq!(LAST_CONTEXT as usize, (&mut context as *mut u8) as usize);
            assert_eq!(LAST_INPUT as usize, input.as_ptr() as usize);
        }
        assert_eq!(output.first, input[0]);
        assert_eq!(output.second, input[1]);
        assert_eq!(output.status, 1);
    }

    #[test]
    fn preserves_zero_status_from_the_worker() {
        let _guard = TEST_LOCK.lock();
        let input = [0, u32::MAX];
        let mut context = 0x35;
        let mut output = ResultBytes([0xa5; 12]);

        unsafe {
            callback_result_build(output.0.as_mut_ptr().cast(), &mut context, input.as_ptr());
        }
        assert_eq!(&output.0[..9], &[0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0]);
        assert_eq!(&output.0[9..], &[0xa5; 3]);
    }
}
