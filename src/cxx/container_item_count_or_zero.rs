use crate::cxx::templates::container_is_empty;

/// container_item_count_or_zero — original: `FUN_081cb3e0` @ 0x081cb3e0
/// (40 bytes; three inbound plain `bl` call sites and no predicated `bl`
/// call sites).
///
/// The body calls the byte-identical `container_is_empty` alias at 0x083d75d0
/// on the embedded container at +0x4. An empty container returns zero;
/// otherwise it sign-extends the i16 count at +0x24. The raw words establish
/// the complete extent from `push {r4,lr}` through `pop {r4,pc}`; the next
/// function begins at 0x081cb408. The count's containing type is not known,
/// but all three callers use it as a signed loop bound. The port deliberately
/// uses the existing `container_is_empty` family seam rather than inventing a
/// separate identity for its byte-identical 0x083d75d0 callee.
///
/// # Safety
///
/// `object` must point to at least 38 readable bytes. The firmware makes no
/// NULL check.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.container_item_count_or_zero")]
#[inline(never)]
pub unsafe extern "C" fn container_item_count_or_zero(object: *const u8) -> i32 {
    if container_is_empty(object.add(4)) != 0 {
        0
    } else {
        (object.add(0x24).cast::<i16>().read()) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::container_item_count_or_zero;
    #[test]
    fn empty_container_returns_zero() {
        let object = [0u32; 10];
        assert_eq!(unsafe { container_item_count_or_zero(object.as_ptr().cast()) }, 0);
    }

    #[test]
    fn nonempty_container_sign_extends_the_i16_count() {
        let mut object = [0u32; 10];
        object[9] = 0x0000_fffe;
        assert_eq!(unsafe { container_item_count_or_zero(object.as_ptr().cast()) }, -2);
        object[9] = 0x0000_7fff;
        assert_eq!(unsafe { container_item_count_or_zero(object.as_ptr().cast()) }, 32_767);
    }
}
