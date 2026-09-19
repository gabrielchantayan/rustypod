//! Accessor for a kind-resolved UI backend's resource count.
use super::object_state::object_backend_for_kind;

/// object_resource_count — original: `FUN_0805417c` @ `0x0805417c` (16
/// bytes).
///
/// Raw ARM words from `osos.dec`: `e52de004 ebfff70f e5900f68 e49df004`;
/// this is `str lr,[sp,#-4]!; bl 0x08051dc4; ldr r0,[r0,#0xf68];
/// ldr pc,[sp],#4`. The next real function starts at `0x0805418c`.
/// Four plain `bl 0x0805417c` callers (0x081118d8, 0x08113a24,
/// 0x0811458c, and 0x0813c300) and no predicated-BL callers were verified
/// from `osos.asm`.
///
/// Resolves a kind-1 backend or kind-2 proxy through
/// [`object_backend_for_kind`], then returns the backend's little-endian
/// resource-table count word at `+0xf68`. The Rust call uses the existing
/// resolver seam rather than reproducing its tag dispatch; no null or bounds
/// guard is added, matching the stock `ldr`.
///
/// # Safety
///
/// `object` must satisfy [`object_backend_for_kind`], and its resolved
/// backend must be readable as an aligned `u32` at `+0xf68`.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn object_resource_count(object: *const u8) -> u32 {
    const RESOURCE_COUNT_OFFSET: usize = 0xf68;

    let backend = object_backend_for_kind(object);
    (backend.add(RESOURCE_COUNT_OFFSET) as *const u32).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(8))]
    struct Backend([u8; 0xf6c]);

    #[repr(align(8))]
    struct Proxy([u8; 0xf04]);

    fn backend_with_count(count: u32) -> Backend {
        let mut backend = Backend([0; 0xf6c]);
        backend.0[0] = 1;
        unsafe {
            (backend.0.as_mut_ptr().add(0xf68) as *mut u32).write(count);
        }
        backend
    }

    #[test]
    fn returns_zero_count_from_a_backend_object() {
        let backend = backend_with_count(0);
        assert_eq!(unsafe { object_resource_count(backend.0.as_ptr()) }, 0);
    }

    #[test]
    fn resolves_a_proxy_before_loading_the_count() {
        let backend = backend_with_count(u32::MAX);
        let mut proxy = Proxy([0; 0xf04]);
        proxy.0[0] = 2;
        unsafe {
            (proxy.0.as_mut_ptr().add(0xefc) as *mut *const u8).write_unaligned(backend.0.as_ptr());
        }
        assert_eq!(
            unsafe { object_resource_count(proxy.0.as_ptr()) },
            u32::MAX
        );
    }
}
