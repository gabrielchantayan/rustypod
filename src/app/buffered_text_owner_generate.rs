//! Buffered capability text generation — `FUN_081522a8` at 0x081522a8.
//! True extent [0x081522a8, 0x0815236c): 196 bytes (192 code, four literal).
//! Raw aligned A32 decoding: two incoming plain BLs at 0x080fdbac and
//! 0x08293588; ten outgoing plain BLs, no predicated BLs in either direction.
//! If storage is active, format two identity strings, set device and filesystem
//! metadata, populate capabilities, and generate text. If capacity plus overflow
//! grows without wrapping and remains below 0x3c10, allocate sum + 1 bytes,
//! copy the descriptor, release the temporary, reset text and generate again.
//! Return the text length at +24; Ghidra's 64-bit return is incidental restored r1.
//! No target behavioral deviations. Preserve the surprising release of the new
//! temporary descriptor after copying, including its stale upper flag bytes.
//! Unported callees use verified retail addresses. The existing Rust snprintf
//! takes an explicit VaList, not the retail variadic ABI, so retain retail here.
//! Host production calls are unsupported; tests inject only unported callees.

use super::buffered_text_owner_construct::StorageInitialize;

#[cfg(target_os = "none")]
type Format = unsafe extern "C" fn(*mut u8, u32, *const u8, ...) -> i32;
type Configure = unsafe extern "C" fn(*mut u8, u32);
#[cfg(not(target_os = "none"))]
type Format = unsafe extern "C" fn(*mut u8, u32, *const u8) -> i32;
type Update = unsafe extern "C" fn(*mut u8);
type Feature = unsafe extern "C" fn() -> u32;
type Release = unsafe extern "C" fn(*mut u8) -> *mut u8;
type Reset = unsafe extern "C" fn(*mut u8, u32, u32);

struct Calls {
    format: Format,
    configure: Configure,
    feature: Feature,
    populate: Update,
    generate: Update,
    initialize: StorageInitialize,
    release: Release,
    reset: Reset,
}

#[inline(always)]
unsafe fn generate_with(owner: *mut u8, model: *const u8, serial: *const u8,
                        device: u32, filesystem: u32, calls: &Calls) -> u32 {
    if owner.read() != 0 {
        owner.add(0x2d8).cast::<u32>().write(device);
        (calls.format)(owner.add(0x2c4), 20, model);
        (calls.format)(owner.add(0x2e8), 20, serial);
        (calls.configure)(owner, filesystem);
        owner.add(0x317).write((calls.feature)() as u8);
        (calls.populate)(owner);
        (calls.generate)(owner);
        let words = owner.cast::<u32>();
        let capacity = words.add(5).read();
        let required = capacity.wrapping_add(words.add(7).read());
        if required > capacity && required < 0x3c10 {
            // The original starts with saved r1/r2/r3, then only overwrites
            // the low flag byte. Retain those upper bytes on allocation failure.
            let mut storage = [model as usize as u32, serial as usize as u32, device];
            (calls.initialize)(storage.as_mut_ptr().cast(), required + 1,
                               0x089c_c96cusize as *mut u8);
            for (index, value) in storage.iter().enumerate() { words.add(index).write(*value); }
            (calls.release)(storage.as_mut_ptr().cast());
            (calls.reset)(owner.add(12), words.add(1).read(), words.add(2).read());
            (calls.generate)(owner);
        }
    }
    owner.add(24).cast::<u32>().read()
}

/// Requires an aligned, writable 1000-byte retail owner and valid format strings.
/// Active owners additionally require the live firmware allocator and text runtime.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn buffered_text_owner_generate(
    owner: *mut u8, model: *const u8, serial: *const u8, device: u32, filesystem: u32,
) -> u32 {
    #[cfg(target_os = "none")]
    {
        generate_with(owner, model, serial, device, filesystem, &Calls {
            format: core::mem::transmute(0x0802_f768usize),
            configure: core::mem::transmute(0x0815_21ccusize),
            feature: core::mem::transmute(0x080f_ab94usize),
            populate: core::mem::transmute(0x0814_fb4cusize),
            generate: core::mem::transmute(0x0815_02b0usize),
            initialize: core::mem::transmute(0x0815_0238usize),
            release: core::mem::transmute(0x0815_0280usize),
            reset: core::mem::transmute(0x0812_367cusize),
        })
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (owner, model, serial, device, filesystem);
        panic!("retail capability text generation is unavailable on host")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use libc's actual variadic ABI for formatting; fixtures contain no conversions.
    extern "C" { fn snprintf(dst: *mut u8, size: usize, format: *const u8, ...) -> i32; }
    unsafe extern "C" fn format(dst: *mut u8, size: u32, text: *const u8) -> i32 {
        snprintf(dst, size as usize, text)
    }
    unsafe extern "C" fn configure(owner: *mut u8, filesystem: u32) {
        owner.add(0x31c).cast::<u32>().write(filesystem);
    }
    unsafe extern "C" fn feature() -> u32 { 0x101 }
    unsafe extern "C" fn populate(_: *mut u8) {}
    unsafe extern "C" fn generate(owner: *mut u8) {
        let words = owner.cast::<u32>();
        words.add(6).write(words.add(6).read() + 1);
    }
    unsafe extern "C" fn initialize(storage: *mut u8, size: u32, _: *mut u8) -> *mut u8 {
        storage.write(1);
        storage.cast::<u32>().add(1).write(0x12345678);
        storage.cast::<u32>().add(2).write(size);
        storage
    }
    unsafe extern "C" fn release(storage: *mut u8) -> *mut u8 {
        storage.cast::<u32>().add(1).write(0);
        storage
    }
    unsafe extern "C" fn reset(text: *mut u8, buffer: u32, capacity: u32) {
        text.cast::<u32>().add(1).write(buffer);
        text.cast::<u32>().add(2).write(capacity);
        text.cast::<u32>().add(3).write(0);
        text.cast::<u32>().add(4).write(0);
    }
    fn calls() -> Calls {
        Calls { format,
                configure, feature, populate, generate, initialize, release, reset }
    }

    #[test]
    fn inactive_owner_preserves_every_byte_and_returns_length() {
        let mut owner = [0xa5a5a5a5u32; 250];
        owner[0] &= !255;
        owner[6] = 0xfedcba98;
        let before = owner;
        unsafe {
            assert_eq!(generate_with(owner.as_mut_ptr().cast(), core::ptr::null(),
                                    core::ptr::null(), 99, 2, &calls()), 0xfedcba98);
        }
        assert_eq!(owner, before);
    }

    #[test]
    fn resize_boundaries_wrap_and_descriptor_release() {
        for (capacity, overflow, resize) in [
            (0u32, 0u32, false), (0, 1, true), (100, 0, false),
            (0x2fff, 1, true), (0x3000, 0xc0f, true),
            (0x3000, 0xc10, false), (0xffffffff, 1, false),
            (100, 0xffffffff, false),
        ] {
            let mut owner = [0u32; 250];
            owner[0] = 1;
            owner[5] = capacity;
            owner[7] = overflow;
            unsafe {
                let base = owner.as_mut_ptr().cast::<u8>();
                let length = generate_with(base, b"Model\0".as_ptr(), b"Serial\0".as_ptr(),
                                           0xf000, 2, &calls());
                assert_eq!(length, 1);
                assert_eq!(core::slice::from_raw_parts(base.add(0x2c4), 6), b"Model\0");
                assert_eq!(core::slice::from_raw_parts(base.add(0x2e8), 7), b"Serial\0");
                assert_eq!(base.add(0x317).read(), 1);
            }
            assert_eq!(owner[0x2d8 / 4], 0xf000);
            assert_eq!(owner[0x31c / 4], 2);
            if resize {
                assert_eq!(owner[1], 0x12345678); // Release changes only temporary.
                assert_eq!(owner[2], capacity + overflow + 1);
                assert_eq!(owner[4], 0x12345678);
                assert_eq!(owner[5], capacity + overflow + 1);
                assert_eq!(owner[7], 0);
            } else {
                assert_eq!(owner[0], 1);
                assert_eq!(owner[5], capacity);
                assert_eq!(owner[7], overflow);
            }
        }
    }
}
