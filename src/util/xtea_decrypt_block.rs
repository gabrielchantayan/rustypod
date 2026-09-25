//! Eight-round XTEA block decryptor @ 0x08056c8c.
//!
//! Raw osos.dec words establish the complete 152-byte body from `stmdb
//! sp!,{r4-r10,lr}` at 0x08056c8c through the tail `b 0x080b4454` at
//! 0x08056d20; the next function begins at 0x08056d2c. The body has two
//! plain unconditional `bl` instructions, no predicated `bl` instructions,
//! and one tail branch. Three inbound plain `bl` call sites reach it.
//!
//! It loads an eight-byte ciphertext block big-endian, applies eight XTEA
//! decrypt rounds using the four-word key and the fixed delta-derived initial
//! sum, then writes the two plaintext words big-endian. The original delegates
//! byte conversion to two unported helpers; the port folds their verified byte
//! accesses because neither helper has a names.yaml identity. Deliberate
//! deviation: LLVM unrolls the fixed eight-round loop.

/// xtea_decrypt_block — original: `FUN_08056c8c` @ 0x08056c8c (152 bytes;
/// two direct unconditional `bl` instructions, no predicated calls, and a
/// tail branch to the big-endian store helper).
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.xtea_decrypt_block")]
#[inline(never)]
pub unsafe extern "C" fn xtea_decrypt_block(key: *const u32, input: *const u8, output: *mut u8) {
    let mut left = ((input.read_volatile() as u32) << 24)
        | ((input.add(1).read_volatile() as u32) << 16)
        | ((input.add(2).read_volatile() as u32) << 8)
        | input.add(3).read_volatile() as u32;
    let mut right = ((input.add(4).read_volatile() as u32) << 24)
        | ((input.add(5).read_volatile() as u32) << 16)
        | ((input.add(6).read_volatile() as u32) << 8)
        | input.add(7).read_volatile() as u32;
    let key0 = key.read();
    let key1 = key.add(1).read();
    let key2 = key.add(2).read();
    let key3 = key.add(3).read();
    let mut sum = 0xf1bb_cdc8u32;

    for _ in 0..8 {
        right = right.wrapping_sub(
            ((left << 4).wrapping_add(key2) ^ left.wrapping_add(sum))
                ^ ((left >> 5).wrapping_add(key3)),
        );
        left = left.wrapping_sub(
            ((right << 4).wrapping_add(key0) ^ right.wrapping_add(sum))
                ^ ((right >> 5).wrapping_add(key1)),
        );
        sum = sum.wrapping_sub(0x9e37_79b9);
    }

    output.write_volatile((left >> 24) as u8);
    output.add(1).write_volatile((left >> 16) as u8);
    output.add(2).write_volatile((left >> 8) as u8);
    output.add(3).write_volatile(left as u8);
    output.add(4).write_volatile((right >> 24) as u8);
    output.add(5).write_volatile((right >> 16) as u8);
    output.add(6).write_volatile((right >> 8) as u8);
    output.add(7).write_volatile(right as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_decrypt(key: [u32; 4], input: [u8; 8]) -> [u8; 8] {
        let mut left = u32::from_be_bytes(input[..4].try_into().unwrap());
        let mut right = u32::from_be_bytes(input[4..].try_into().unwrap());
        let mut sum = 0xf1bb_cdc8u32;

        for _ in 0..8 {
            right = right.wrapping_sub(
                ((left << 4).wrapping_add(key[2]) ^ left.wrapping_add(sum))
                    ^ ((left >> 5).wrapping_add(key[3])),
            );
            left = left.wrapping_sub(
                ((right << 4).wrapping_add(key[0]) ^ right.wrapping_add(sum))
                    ^ ((right >> 5).wrapping_add(key[1])),
            );
            sum = sum.wrapping_sub(0x9e37_79b9);
        }

        let mut output = [0u8; 8];
        output[..4].copy_from_slice(&left.to_be_bytes());
        output[4..].copy_from_slice(&right.to_be_bytes());
        output
    }

    #[test]
    fn decrypts_known_xtea_ciphertext() {
        let key = [0x0123_4567, 0x89ab_cdef, 0xfeed_face, 0xc001_d00d];
        let ciphertext = [0xa5, 0x1c, 0x36, 0xe7, 0x90, 0x4b, 0xd2, 0x08];
        let expected = reference_decrypt(key, ciphertext);
        let mut output = [0u8; 8];

        unsafe { xtea_decrypt_block(key.as_ptr(), ciphertext.as_ptr(), output.as_mut_ptr()) };

        assert_eq!(output, expected);
    }

    #[test]
    fn supports_unaligned_input_and_output_without_overwrite() {
        let key = [0, u32::MAX, 0x1357_9bdf, 0x2468_ace0];
        let ciphertext = [0xff, 0, 1, 2, 3, 4, 5, 0x80];
        let expected = reference_decrypt(key, ciphertext);

        for input_offset in 0..4 {
            for output_offset in 0..4 {
                let mut input = [0xa5u8; 12];
                let mut output = [0x5au8; 16];
                input[input_offset..input_offset + 8].copy_from_slice(&ciphertext);

                unsafe {
                    xtea_decrypt_block(
                        key.as_ptr(),
                        input.as_ptr().add(input_offset),
                        output.as_mut_ptr().add(output_offset + 4),
                    )
                };

                assert_eq!(&output[output_offset + 4..output_offset + 12], expected);
                assert!(output[..output_offset + 4].iter().all(|&byte| byte == 0x5a));
                assert!(output[output_offset + 12..].iter().all(|&byte| byte == 0x5a));
            }
        }
    }
}
