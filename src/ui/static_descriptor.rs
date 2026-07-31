//! `ui_descriptor_init_static_span` — original: `FUN_0811f720` @
//! `0x0811f720` (28 bytes, including the literal at `0x0811f73c`).
//!
//! Initializes only the three observed fields of a caller-owned UI descriptor:
//! it stores the fixed retailOS pointer `0x0898_2f40` at +0x00, that pointer
//! plus 0x20 at +0x04, and the u16 value `0x0400` at +0x0c. Callers then fill
//! other fields, so their layout and the intervening bytes remain deliberately
//! unnamed and untouched.
//!
//! Deviations: none. The original requires the supplied object to be aligned
//! for its word and halfword stores; this port preserves that requirement.

/// RetailOS static base pointer loaded from the literal at `0x0811f73c`.
pub const UI_DESCRIPTOR_STATIC_BASE: u32 = 0x0898_2f40;
/// The second pointer the original derives from [`UI_DESCRIPTOR_STATIC_BASE`].
pub const UI_DESCRIPTOR_STATIC_SPAN_END: u32 = UI_DESCRIPTOR_STATIC_BASE + 0x20;
/// The u16 field value the original writes at offset +0x0c.
pub const UI_DESCRIPTOR_STATIC_EXTENT: u16 = 0x0400;

/// Offset of the fixed base pointer within the caller-owned descriptor.
pub const UI_DESCRIPTOR_STATIC_BASE_OFFSET: usize = 0x00;
/// Offset of the fixed base-plus-0x20 pointer within the descriptor.
pub const UI_DESCRIPTOR_STATIC_SPAN_END_OFFSET: usize = 0x04;
/// Offset of the u16 `0x0400` field within the descriptor.
pub const UI_DESCRIPTOR_STATIC_EXTENT_OFFSET: usize = 0x0c;
/// Offset of the caller-supplied word stored by
/// [`ui_descriptor_init_static_span_with_parameter`].
pub const UI_DESCRIPTOR_PARAMETER_OFFSET: usize = 0x08;
/// The second pointer the parameterized initializer derives from
/// [`UI_DESCRIPTOR_STATIC_BASE`].
pub const UI_DESCRIPTOR_PARAMETERIZED_SPAN_END: u32 = UI_DESCRIPTOR_STATIC_BASE + 0x24;

/// Calls [`ui_descriptor_init_static_span`], replaces its static span with
/// the adjacent 0x24-byte span, and records `parameter` at +0x08.
///
/// Original: `FUN_0811f748` @ `0x0811f748` (32 bytes).
///
/// The retailOS wrapper calls `FUN_0811f720`, whose unchanged r0 supplies
/// the descriptor pointer for the subsequent stores. This Rust ABI returns
/// that same pointer explicitly after routing through
/// [`ui_descriptor_init_static_span`]. It then writes the static base at
/// +0x00, the base-plus-0x24 endpoint at +0x04, and its second argument at
/// +0x08; the callee's u16 `0x0400` at +0x0c remains in place.
///
/// Deviations: the reference C inferred a `void` return for this wrapper
/// despite the preserved ARM r0 value. The explicit pointer result models
/// the observed returned descriptor pointer without altering the stores.
/// Target builds route through a volatile function-pointer seam to keep LLVM
/// from inlining the ported callee, which changes the original direct `bl`
/// into an indirect `blx` without changing its target.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn ui_descriptor_init_static_span_with_parameter(
    descriptor: *mut u8,
    parameter: u32,
) -> *mut u8 {
    initialize_static_span(descriptor);
    descriptor
        .add(UI_DESCRIPTOR_STATIC_BASE_OFFSET)
        .cast::<u32>()
        .write(UI_DESCRIPTOR_STATIC_BASE);
    descriptor
        .add(UI_DESCRIPTOR_STATIC_SPAN_END_OFFSET)
        .cast::<u32>()
        .write(UI_DESCRIPTOR_PARAMETERIZED_SPAN_END);
    descriptor
        .add(UI_DESCRIPTOR_PARAMETER_OFFSET)
        .cast::<u32>()
        .write(parameter);
    descriptor
}

#[cfg(any(test, target_os = "none"))]
type StaticSpanInitializer = unsafe extern "C" fn(*mut u8);

#[cfg(test)]
static mut STATIC_SPAN_INITIALIZER_FOR_TEST: StaticSpanInitializer = ui_descriptor_init_static_span;

#[cfg(all(target_os = "none", not(test)))]
static UI_DESCRIPTOR_STATIC_SPAN_INITIALIZER: StaticSpanInitializer = ui_descriptor_init_static_span;

#[cfg(test)]
#[inline(always)]
unsafe fn initialize_static_span(descriptor: *mut u8) {
    unsafe { STATIC_SPAN_INITIALIZER_FOR_TEST(descriptor) };
}

#[cfg(all(target_os = "none", not(test)))]
#[inline(always)]
unsafe fn initialize_static_span(descriptor: *mut u8) {
    let initializer =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(UI_DESCRIPTOR_STATIC_SPAN_INITIALIZER)) };
    unsafe { initializer(descriptor) };
}

#[cfg(all(not(target_os = "none"), not(test)))]
#[inline(always)]
unsafe fn initialize_static_span(descriptor: *mut u8) {
    unsafe { ui_descriptor_init_static_span(descriptor) };
}


/// Writes the observed static UI descriptor fields into `descriptor`.
///
/// The pointer must be valid and aligned for the 32-bit stores at +0x00/+0x04
/// and the 16-bit store at +0x0c. No other part of the descriptor layout is
/// known or accessed.
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn ui_descriptor_init_static_span(descriptor: *mut u8) {
    descriptor
        .add(UI_DESCRIPTOR_STATIC_BASE_OFFSET)
        .cast::<u32>()
        .write(UI_DESCRIPTOR_STATIC_BASE);
    descriptor
        .add(UI_DESCRIPTOR_STATIC_SPAN_END_OFFSET)
        .cast::<u32>()
        .write(UI_DESCRIPTOR_STATIC_SPAN_END);
    descriptor
        .add(UI_DESCRIPTOR_STATIC_EXTENT_OFFSET)
        .cast::<u16>()
        .write(UI_DESCRIPTOR_STATIC_EXTENT);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct DescriptorBytes([u8; 0x10]);

    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    static INITIALIZER_ROUTE_LOCK: AtomicBool = AtomicBool::new(false);
    static ROUTED_DESCRIPTOR: AtomicUsize = AtomicUsize::new(0);

    struct InitializerRouteLock;

    impl InitializerRouteLock {
        fn acquire() -> Self {
            while INITIALIZER_ROUTE_LOCK
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {}
            Self
        }
    }

    impl Drop for InitializerRouteLock {
        fn drop(&mut self) {
            INITIALIZER_ROUTE_LOCK.store(false, Ordering::Release);
        }
    }

    unsafe extern "C" fn recording_static_span_initializer(descriptor: *mut u8) {
        ROUTED_DESCRIPTOR.store(descriptor as usize, Ordering::SeqCst);
        unsafe { ui_descriptor_init_static_span(descriptor) };
    }

    unsafe fn read_u32(descriptor: &DescriptorBytes, offset: usize) -> u32 {
        unsafe { descriptor.0.as_ptr().add(offset).cast::<u32>().read() }
    }

    #[test]
    fn parameterized_initializer_returns_descriptor_and_sets_fields() {
        let _route_lock = InitializerRouteLock::acquire();
        let mut descriptor = DescriptorBytes([0xa5; 0x10]);
        let returned = unsafe {
            ui_descriptor_init_static_span_with_parameter(
                descriptor.0.as_mut_ptr(),
                0x1234_5678,
            )
        };

        assert_eq!(returned, descriptor.0.as_mut_ptr());
        assert_eq!(
            unsafe { read_u32(&descriptor, UI_DESCRIPTOR_STATIC_BASE_OFFSET) },
            UI_DESCRIPTOR_STATIC_BASE
        );
        assert_eq!(
            unsafe { read_u32(&descriptor, UI_DESCRIPTOR_STATIC_SPAN_END_OFFSET) },
            UI_DESCRIPTOR_PARAMETERIZED_SPAN_END
        );
        assert_eq!(
            unsafe { read_u32(&descriptor, UI_DESCRIPTOR_PARAMETER_OFFSET) },
            0x1234_5678
        );
        assert_eq!(
            unsafe {
                descriptor
                    .0
                    .as_ptr()
                    .add(UI_DESCRIPTOR_STATIC_EXTENT_OFFSET)
                    .cast::<u16>()
                    .read()
            },
            UI_DESCRIPTOR_STATIC_EXTENT
        );
        assert_eq!(descriptor.0[0x0e..0x10], [0xa5; 2]);
    }

    #[test]
    fn parameterized_initializer_routes_through_static_span_initializer() {
        let _route_lock = InitializerRouteLock::acquire();
        let mut descriptor = DescriptorBytes([0; 0x10]);
        ROUTED_DESCRIPTOR.store(0, Ordering::SeqCst);

        unsafe {
            let previous = STATIC_SPAN_INITIALIZER_FOR_TEST;
            STATIC_SPAN_INITIALIZER_FOR_TEST = recording_static_span_initializer;
            let returned =
                ui_descriptor_init_static_span_with_parameter(descriptor.0.as_mut_ptr(), 0);
            STATIC_SPAN_INITIALIZER_FOR_TEST = previous;
            assert_eq!(returned, descriptor.0.as_mut_ptr());
        }

        assert_eq!(
            ROUTED_DESCRIPTOR.load(Ordering::SeqCst),
            descriptor.0.as_mut_ptr() as usize,
            "the wrapper must call the ported 0x0811f720 initializer"
        );
    }

    #[test]
    fn field_offsets_match_the_original_stores() {
        assert_eq!(UI_DESCRIPTOR_STATIC_BASE_OFFSET, 0x00);
        assert_eq!(UI_DESCRIPTOR_STATIC_SPAN_END_OFFSET, 0x04);
        assert_eq!(UI_DESCRIPTOR_STATIC_EXTENT_OFFSET, 0x0c);
        assert_eq!(core::mem::size_of_val(&UI_DESCRIPTOR_STATIC_BASE), 4);
        assert_eq!(core::mem::size_of_val(&UI_DESCRIPTOR_STATIC_EXTENT), 2);
    }

    #[test]
    fn writes_all_and_only_the_observed_fields() {
        let mut descriptor = DescriptorBytes([0xa5; 0x10]);

        unsafe { ui_descriptor_init_static_span(descriptor.0.as_mut_ptr()) };

        let base = unsafe {
            descriptor
                .0
                .as_ptr()
                .add(UI_DESCRIPTOR_STATIC_BASE_OFFSET)
                .cast::<u32>()
                .read()
        };
        let span_end = unsafe {
            descriptor
                .0
                .as_ptr()
                .add(UI_DESCRIPTOR_STATIC_SPAN_END_OFFSET)
                .cast::<u32>()
                .read()
        };
        let extent = unsafe {
            descriptor
                .0
                .as_ptr()
                .add(UI_DESCRIPTOR_STATIC_EXTENT_OFFSET)
                .cast::<u16>()
                .read()
        };

        assert_eq!(base, 0x0898_2f40);
        assert_eq!(span_end, 0x0898_2f60);
        assert_eq!(extent, 0x0400);
        assert_eq!(descriptor.0[0x08..0x0c], [0xa5; 4]);
        assert_eq!(descriptor.0[0x0e..0x10], [0xa5; 2]);
    }
}
