//! CBC encryption for the proprietary `"STANDARD"` cipher.
//!
//! `proprietary_cipher_cbc_encrypt` — original: `FUN_0802e758` @
//! `0x0802e758` (188 bytes, `0x0802e758..0x0802e814`; the distinct next
//! function begins at `0x0802e814`). Raw ARM decoding finds three inbound,
//! unconditional plain `bl` calls (`0x0802a408`, `0x0802a4a4`, and
//! `0x0802ac00`), no predicated inbound calls, and two unconditional body
//! calls to the unported block encryptor at `0x0802e58c`.
//!
//! XOR the first 16-byte plaintext block with the IV, encrypt it, then XOR
//! every following plaintext block with the preceding ciphertext block before
//! encrypting it. The stock body unconditionally processes one block, even
//! when `byte_len < 16`; callers provide validated block-aligned lengths.
//!
//! # Deliberate deviation
//!
//! The 388-byte block encryptor at `0x0802e58c` is not ported. On ARM this
//! wrapper calls that verified retail target through an absolute veneer; host
//! tests replace it with a callback. This preserves the observed ABI without
//! inventing an identity or a second cipher implementation.

/// ABI of the unported retail block encryptor at `0x0802e58c`.
pub type RetailProprietaryCipherEncryptBlock = unsafe extern "C" fn(
    u32,
    u32,
    *const u8,
    *mut u8,
    *const u8,
    u32,
);

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_retail_proprietary_cipher_encrypt_block(
    _mode_word_0: u32,
    _mode_word_1: u32,
    _input: *const u8,
    _output: *mut u8,
    _round_keys: *const u8,
    _rounds: u32,
) {
}

/// Host-only callback replacing retailOS `0x0802e58c`.
#[cfg(not(target_os = "none"))]
pub static mut RETAIL_PROPRIETARY_CIPHER_ENCRYPT_BLOCK: RetailProprietaryCipherEncryptBlock =
    missing_retail_proprietary_cipher_encrypt_block;

#[cfg(not(target_os = "none"))]
#[inline(never)]
unsafe fn retail_proprietary_cipher_encrypt_block(
    mode_word_0: u32,
    mode_word_1: u32,
    input: *const u8,
    output: *mut u8,
    round_keys: *const u8,
    rounds: u32,
) {
    unsafe {
        core::ptr::read_volatile(core::ptr::addr_of!(RETAIL_PROPRIETARY_CIPHER_ENCRYPT_BLOCK))(
            mode_word_0,
            mode_word_1,
            input,

            output,
            round_keys,
            rounds,
        )
    }
}
#[cfg(target_os = "none")]
unsafe extern "C" {
    fn retail_proprietary_cipher_encrypt_block(
        mode_word_0: u32,
        mode_word_1: u32,
        input: *const u8,
        output: *mut u8,
        round_keys: *const u8,
        rounds: u32,
    );
}


#[cfg(target_os = "none")]
core::arch::global_asm!(
    r#"
    .syntax unified
    .text
    .p2align 2
    .globl retail_proprietary_cipher_encrypt_block
retail_proprietary_cipher_encrypt_block:
    ldr     pc, 1f
1:  .word   0x0802e58c
"#
);

/// Encrypts `byte_len` bytes in 16-byte CBC blocks.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn proprietary_cipher_cbc_encrypt(
    mode_word_0: u32,
    mode_word_1: u32,
    plaintext: *const u8,
    ciphertext: *mut u8,
    iv: *const u8,
    round_keys: *const u8,
    rounds: u32,
    byte_len: u32,
) {
    let mut chained_input = [0u8; 16];
    unsafe {
        for index in 0..16 {
            chained_input[index] = *plaintext.add(index) ^ *iv.add(index);
        }

        let mut offset = 0u32;
        let final_offset = byte_len.wrapping_sub(16) as i32;
        while (offset as i32) < final_offset {
            retail_proprietary_cipher_encrypt_block(
                mode_word_0,
                mode_word_1,
                chained_input.as_ptr(),
                ciphertext.add(offset as usize),
                round_keys,
                rounds,
            );
            for index in 0..16 {
                chained_input[index] = *ciphertext.add(offset as usize + index)
                    ^ *plaintext.add(offset as usize + 16 + index);
            }
            offset = offset.wrapping_add(16);
        }
        retail_proprietary_cipher_encrypt_block(
            mode_word_0,
            mode_word_1,
            chained_input.as_ptr(),
            ciphertext.add(offset as usize),
            round_keys,
            rounds,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{RetailProprietaryCipherEncryptBlock, RETAIL_PROPRIETARY_CIPHER_ENCRYPT_BLOCK,
        proprietary_cipher_cbc_encrypt};
    extern crate std;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut MODE_WORDS: (u32, u32) = (0, 0);
    static mut ROUNDS: u32 = 0;
    static mut ROUND_KEYS: *const u8 = core::ptr::null();

    unsafe extern "C" fn recording_encryptor(
        mode_word_0: u32,
        mode_word_1: u32,
        input: *const u8,
        output: *mut u8,
        round_keys: *const u8,
        rounds: u32,
    ) {
        unsafe {
            CALLS += 1;
            MODE_WORDS = (mode_word_0, mode_word_1);
            ROUNDS = rounds;
            ROUND_KEYS = round_keys;
            for index in 0..16 {
                *output.add(index) = *input.add(index) ^ 0xa5;
            }
        }
    }

    struct TargetRestore(RetailProprietaryCipherEncryptBlock);
    impl Drop for TargetRestore {
        fn drop(&mut self) {
            unsafe { RETAIL_PROPRIETARY_CIPHER_ENCRYPT_BLOCK = self.0; }
        }
    }

    #[test]
    fn chains_ciphertext_and_forwards_block_encryptor_arguments() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RETAIL_PROPRIETARY_CIPHER_ENCRYPT_BLOCK;
            RETAIL_PROPRIETARY_CIPHER_ENCRYPT_BLOCK = recording_encryptor;
            CALLS = 0;
            TargetRestore(previous)
        };
        let plaintext: [u8; 32] = core::array::from_fn(|index| index as u8 * 3 + 1);
        let iv: [u8; 16] = core::array::from_fn(|index| 0xf0 - index as u8);
        let round_keys = [0x5au8; 32];
        let mut ciphertext = [0u8; 32];

        unsafe {
            proprietary_cipher_cbc_encrypt(0x1122_3344, 0x5566_7788, plaintext.as_ptr(),
                ciphertext.as_mut_ptr(), iv.as_ptr(), round_keys.as_ptr(), 9, 32);
        }

        let first: [u8; 16] = core::array::from_fn(|index| plaintext[index] ^ iv[index] ^ 0xa5);
        let second: [u8; 16] = core::array::from_fn(|index| plaintext[16 + index] ^ first[index] ^ 0xa5);
        assert_eq!(&ciphertext[..16], &first);
        assert_eq!(&ciphertext[16..], &second);
        assert_eq!(unsafe { CALLS }, 2);
        assert_eq!(unsafe { MODE_WORDS }, (0x1122_3344, 0x5566_7788));
        assert_eq!(unsafe { ROUNDS }, 9);
        assert_eq!(unsafe { ROUND_KEYS }, round_keys.as_ptr());
    }

    #[test]
    fn encrypts_one_block_without_reading_a_following_block() {
        let _lock = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _restore = unsafe {
            let previous = RETAIL_PROPRIETARY_CIPHER_ENCRYPT_BLOCK;
            RETAIL_PROPRIETARY_CIPHER_ENCRYPT_BLOCK = recording_encryptor;
            CALLS = 0;
            TargetRestore(previous)
        };
        let plaintext = [0x3cu8; 16];
        let iv = [0xc3u8; 16];
        let mut ciphertext = [0u8; 16];

        unsafe {
            proprietary_cipher_cbc_encrypt(0, 0, plaintext.as_ptr(), ciphertext.as_mut_ptr(),
                iv.as_ptr(), core::ptr::null(), 0, 16);
        }

        assert_eq!(ciphertext, [0x5au8; 16]);
        assert_eq!(unsafe { CALLS }, 1);
    }
}
