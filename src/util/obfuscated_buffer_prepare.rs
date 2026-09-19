/// obfuscated_buffer_prepare — original: `FUN_082d408c` @ `0x082d408c`
/// (72 bytes: 18 ARM words, `0x082d408c..0x082d40d0`).
///
/// The raw body has one outbound unconditional `bl` to `0x08093440` and no
/// predicated BLs. It has four inbound unconditional BLs (at `0x081637d4`,
/// `0x082729e0`, `0x08272a0c`, and `0x082d42b0`) and no inbound predicated
/// BLs. A null size slot returns 1. Otherwise it replaces the slot with 0x362;
/// when the caller supplied a non-null buffer of at least that size, it first
/// applies the stock byte transform `byte ^ (index + 0x11)` across all 0x362
/// bytes and returns 0. A smaller capacity returns 12 without touching the
/// buffer. No deliberate deviation: its transform is the separately linked
/// `xor_index_key` port of retailOS `0x08093440`.

use super::xor_index_key::xor_index_key;

const REQUIRED_BUFFER_SIZE: u32 = 0x362;

#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn obfuscated_buffer_prepare(buffer: *mut u8, size_slot: *mut u32) -> u32 {
    if size_slot.is_null() {
        return 1;
    }

    let supplied_size = size_slot.read();
    if !buffer.is_null() && supplied_size >= REQUIRED_BUFFER_SIZE {
        xor_index_key(buffer, buffer, REQUIRED_BUFFER_SIZE as i32);
        size_slot.write(REQUIRED_BUFFER_SIZE);
        return 0;
    }

    size_slot.write(REQUIRED_BUFFER_SIZE);
    12
}

#[cfg(test)]
mod tests {
    use super::{obfuscated_buffer_prepare, REQUIRED_BUFFER_SIZE};

    #[test]
    fn null_size_slot_returns_one() {
        assert_eq!(unsafe { obfuscated_buffer_prepare(core::ptr::null_mut(), core::ptr::null_mut()) }, 1);
    }

    #[test]
    fn absent_or_small_buffer_reports_capacity_requirement() {
        let mut size = 0;
        assert_eq!(unsafe { obfuscated_buffer_prepare(core::ptr::null_mut(), &mut size) }, 12);
        assert_eq!(size, REQUIRED_BUFFER_SIZE);

        let mut bytes = [0xa5; 8];
        size = REQUIRED_BUFFER_SIZE - 1;
        assert_eq!(unsafe { obfuscated_buffer_prepare(bytes.as_mut_ptr(), &mut size) }, 12);
        assert_eq!(size, REQUIRED_BUFFER_SIZE);
        assert_eq!(bytes, [0xa5; 8]);
    }

    #[test]
    fn sufficient_buffer_is_transformed_and_size_is_canonicalized() {
        let mut bytes = [0u8; REQUIRED_BUFFER_SIZE as usize];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut size = REQUIRED_BUFFER_SIZE + 1;

        assert_eq!(unsafe { obfuscated_buffer_prepare(bytes.as_mut_ptr(), &mut size) }, 0);
        assert_eq!(size, REQUIRED_BUFFER_SIZE);
        for (index, byte) in bytes.into_iter().enumerate() {
            assert_eq!(byte, (index as u8) ^ (index as u8).wrapping_add(0x11));
        }
    }
}
