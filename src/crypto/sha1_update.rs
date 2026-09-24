//! RetailOS SHA-1 streaming update.
//!
//! `sha1_update` — original: `FUN_080f4fd8` @ **0x080f4fd8**. Raw
//! `osos.dec` words establish the 176-byte extent `0x080f4fd8..0x080f5087`;
//! `push {r4,lr}` at `0x080f5088` starts the next function. It has one plain
//! internal `bl` to the SHA-1 block transform at `0x0807d558` and no
//! predicated direct BLs. Full-image decoding finds three inbound plain BLs
//! and no predicated forms.
//!
//! # Algorithm
//!
//! Appends each byte to the context's 64-byte big-endian word buffer. Every
//! completed block invokes the stock SHA-1 transform, resets the buffered-byte
//! count, and advances the 64-bit bit count stored as high and low u32 words.
//!
//! # Deliberate deviation
//!
//! The block transform is not ported. ARM builds call its verified stock entry;
//! host tests install a recorder seam. Context word indices model the 32-bit
//! firmware layout rather than host pointer-sized field offsets.

/// The 352-byte SHA-1 context layout used by retailOS.
#[repr(C, align(4))]
pub struct Sha1Context {
    pub(crate) words: [u32; 88],
}

/// Stock `SHA1_Transform(context)` entry point.
pub type Sha1BlockFn = unsafe extern "C" fn(*mut Sha1Context);

#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_sha1_block(context: *mut Sha1Context) {
    let block: Sha1BlockFn = unsafe { core::mem::transmute(0x0807_d558usize) };
    unsafe { block(context) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_sha1_block(_context: *mut Sha1Context) {
    panic!("sha1_update requires SHA1 block worker 0x0807d558")
}

#[cfg(target_os = "none")]
pub static mut SHA1_BLOCK: Sha1BlockFn = firmware_sha1_block;
#[cfg(not(target_os = "none"))]
pub static mut SHA1_BLOCK: Sha1BlockFn = missing_sha1_block;

#[inline(always)]
unsafe fn sha1_block() -> Sha1BlockFn {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SHA1_BLOCK)) }
}

/// `SHA1_Update(context, input, input_len)` — original: `FUN_080f4fd8` @
/// 0x080f4fd8 (176 bytes; three inbound plain BLs, one internal plain BL,
/// and no predicated direct BLs).
///
/// # Safety
///
/// For positive signed `input_len`, `input` must be readable for that many
/// bytes and `context` must point to a retailOS SHA-1 context.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn sha1_update(context: *mut Sha1Context, input: *const u8, input_len: u32) {
    let mut index = 0u32;
    while (index as i32) < (input_len as i32) {
        unsafe {
            let buffered = (*context).words[85];
            let word = 5 + buffered / 4;
            let word_ptr = context.cast::<u32>().add(word as usize);
            *word_ptr = (*word_ptr << 8) | *input.add(index as usize) as u32;

            let next_buffered = buffered.wrapping_add(1);
            (*context).words[85] = next_buffered;
            if (next_buffered & 0x3f) == 0 {
                sha1_block()(context);
                (*context).words[85] = 0;
            }

            let low_ptr = context.cast::<u32>().add(87);
            let low = core::ptr::read_volatile(low_ptr).wrapping_add(8);
            core::ptr::write_volatile(low_ptr, low);
            let high_ptr = context.cast::<u32>().add(86);
            core::ptr::write_volatile(high_ptr, core::ptr::read_volatile(high_ptr).wrapping_add((low < 8) as u32));
        }
        index = index.wrapping_add(1);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    pub(crate) static SHA1_UPDATE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut BLOCK_CALLS: u32 = 0;

    unsafe extern "C" fn record_block(_context: *mut Sha1Context) {
        unsafe { BLOCK_CALLS += 1 };
    }

    struct BlockReset(Sha1BlockFn);

    impl Drop for BlockReset {
        fn drop(&mut self) {
            unsafe { SHA1_BLOCK = self.0 };
        }
    }

    #[test]
    fn buffers_bytes_in_big_endian_words_and_counts_bits() {
        let _guard = SHA1_UPDATE_TEST_LOCK.lock();
        let saved = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SHA1_BLOCK)) };
        let _reset = BlockReset(saved);
        unsafe { SHA1_BLOCK = record_block; BLOCK_CALLS = 0 };

        let mut context = Sha1Context { words: [0; 88] };
        let input = [0x12, 0x34, 0x56, 0x78, 0x9a];
        unsafe { sha1_update(&mut context, input.as_ptr(), input.len() as u32) };

        assert_eq!(context.words[5], 0x1234_5678);
        assert_eq!(context.words[6], 0x0000_009a);
        assert_eq!(context.words[85], 5);
        assert_eq!(context.words[86], 0);
        assert_eq!(context.words[87], 40);
        assert_eq!(unsafe { BLOCK_CALLS }, 0);
    }

    #[test]
    fn transforms_completed_block_and_carries_bit_count() {
        let _guard = SHA1_UPDATE_TEST_LOCK.lock();
        let saved = unsafe { core::ptr::read_volatile(core::ptr::addr_of!(SHA1_BLOCK)) };
        let _reset = BlockReset(saved);
        unsafe { SHA1_BLOCK = record_block; BLOCK_CALLS = 0 };

        let mut context = Sha1Context { words: [0; 88] };
        context.words[86] = 7;
        context.words[87] = u32::MAX - 7;
        let input = [0xa5; 64];
        unsafe { sha1_update(&mut context, input.as_ptr(), input.len() as u32) };

        assert_eq!(context.words[85], 0);
        assert_eq!(context.words[86], 8);
        assert_eq!(context.words[87], 504);
        assert_eq!(unsafe { BLOCK_CALLS }, 1);
    }

    #[test]
    fn ignores_negative_signed_lengths_without_reading_input() {
        let mut context = Sha1Context { words: [0; 88] };
        unsafe { sha1_update(&mut context, core::ptr::null(), 0x8000_0000) };
        assert_eq!(context.words[85], 0);
        assert_eq!(context.words[86], 0);
        assert_eq!(context.words[87], 0);
    }
}
