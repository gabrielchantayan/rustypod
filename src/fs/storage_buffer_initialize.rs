//! Extent-backed storage buffer initialization at retailOS 0x081c0180.
//!
//! True extent: 100 bytes, [0x081c0180, 0x081c01e4): 76 instruction
//! bytes followed by seven literal words. Whole-image raw A32 decoding finds
//! two inbound plain BLs (0x08161f5c, 0x08161f6c), no predicated inbound
//! BLs, and one outbound plain BL to 0x080418ac, no predicated outbound BLs.
//! Read the kind byte at +0xec. Kinds 3 and 4 select opaque descriptor words
//! 0x0803a1fc and 0x0803a19c respectively, then initialize the embedded
//! storage state at +0x10 using the workspace at +0x10c and four resident
//! callback words. Other kinds return 24 without modifying the object.
//! Return the initializer status unchanged, including failures.
//!
//! Deviations: Ghidra's void return is corrected from raw r0 dataflow and
//! callers' status checks. The unported initializer and its opaque arguments
//! retain exact firmware addresses, without attributing unreliable Ghidra
//! callback identities. Private callback injection permits host execution;
//! supported host calls without a resident implementation explicitly panic.

// Callback arguments are target-width opaque words, not native host pointers.
type Initialize = unsafe extern "C" fn(*mut u8, *mut u8, u32, u32, u32, u32, u32) -> i32;

#[inline(always)]
unsafe fn initialize_with(object: *mut u8, initialize: Initialize) -> i32 {
    let descriptor = match object.add(0xec).read() {
        3 => 0x0803_a1fc,
        4 => 0x0803_a19c,
        _ => return 24,
    };
    initialize(
        object.add(0x10), object.add(0x10c), descriptor,
        0x081b_4f20, 0x081b_508c, 0x081b_519c, 0x081b_517c,
    )
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_initialize(
    _: *mut u8, _: *mut u8, _: u32, _: u32, _: u32, _: u32, _: u32,
) -> i32 {
    panic!("storage_buffer_initialize requires retailOS initializer 0x080418ac")
}

/// Initializes an extent-backed storage object's embedded state.
///
/// # Safety
/// `object` must be a valid retailOS storage object (at least 0x178 bytes),
/// with its base fields constructed. On device the resident initializer and
/// callback code must be available; this function does not validate pointers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn storage_buffer_initialize(object: *mut u8) -> i32 {
    #[cfg(target_os = "none")]
    let initialize: Initialize = core::mem::transmute(0x0804_18acusize);
    #[cfg(not(target_os = "none"))]
    let initialize: Initialize = unavailable_initialize;
    initialize_with(object, initialize)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn complete(
        state: *mut u8, workspace: *mut u8, descriptor: u32,
        _: u32, _: u32, _: u32, _: u32,
    ) -> i32 {
        // Model the resident initializer's observable state publication and
        // error return, without global callback state or target-pointer casts.
        let object = state.sub(0x10);
        let status = object.cast::<i32>().read();
        if status == 0 {
            state.cast::<u32>().write(descriptor);
            workspace.write(1);
        }
        status
    }

    #[test]
    fn unsupported_kinds_return_24_without_mutation() {
        for kind in 0..=255u8 {
            if kind == 3 || kind == 4 { continue; }
            let mut object = [0xa5a5_a5a5u32; 0x178 / 4];
            unsafe { object.as_mut_ptr().cast::<u8>().add(0xec).write(kind) };
            let before = object;
            assert_eq!(unsafe { storage_buffer_initialize(object.as_mut_ptr().cast()) }, 24);
            assert_eq!(object, before);
        }
    }

    #[test]
    fn supported_kinds_publish_state_and_propagate_errors() {
        for (kind, descriptor) in [(3, 0x0803_a1fc), (4, 0x0803_a19c)] {
            for status in [0, 24, -50, -108, i32::MIN, i32::MAX] {
                let mut object = [0xa5a5_a5a5u32; 0x178 / 4];
                object[0] = status as u32;
                let ptr = object.as_mut_ptr().cast::<u8>();
                unsafe { ptr.add(0xec).write(kind) };
                let mut expected = object;
                if status == 0 {
                    expected[4] = descriptor;
                    expected[0x10c / 4] = (expected[0x10c / 4] & !0xff) | 1;
                }
                assert_eq!(unsafe { initialize_with(ptr, complete) }, status);
                assert_eq!(object, expected);
            }
        }
    }
}
