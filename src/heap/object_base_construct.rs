//! Base constructor shared by several retailOS polymorphic objects.

use core::ptr;

/// The base-class vtable literal loaded by retailOS at `0x08274f10`.
pub const OBJECT_BASE_VTABLE_ADDRESS: u32 = 0x089a_5f98;

/// The retailOS global at `0x08a09f00`, incremented once per base construction.
///
/// Firmware startup owns its initial value; the replacement payload begins at
/// zero and retains the same wrapping increment semantics thereafter.
static mut OBJECT_BASE_INSTANCE_COUNTER: u32 = 0;

/// object_base_construct — retailOS `FUN_08274f10` @ **0x08274f10**
/// (**44 bytes** including the two trailing literal-pool words; 0 direct
/// calls, plain or predicated; 4 incoming plain `bl` call sites and no
/// predicated incoming calls).
///
/// Initializes the 16-byte common prefix of a polymorphic object: installs the
/// base vtable word, clears the words at target offsets +8 and +12, then assigns
/// the current global instance counter at +4 and increments that counter with
/// ARM's wrapping arithmetic. The next real function begins at `0x08274f44`;
/// `0x08274f3c` and `0x08274f40` are this function's literal-pool words.
///
/// Deliberate deviation: the firmware's loader-owned word at `0x08a09f00` is a
/// Rust static initialized to zero in the replacement payload. Target object
/// fields remain explicit `u32` words so host pointer width cannot alter their
/// retailOS offsets.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn object_base_construct(object: *mut u32) -> *mut u32 {
    ptr::write_volatile(object, OBJECT_BASE_VTABLE_ADDRESS);
    ptr::write_volatile(object.add(2), 0);
    ptr::write_volatile(object.add(3), 0);

    let counter = ptr::addr_of_mut!(OBJECT_BASE_INSTANCE_COUNTER);
    let instance_id = ptr::read_volatile(counter);
    ptr::write_volatile(object.add(1), instance_id);
    ptr::write_volatile(counter, instance_id.wrapping_add(1));
    object
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe fn set_instance_counter(value: u32) {
        core::ptr::addr_of_mut!(OBJECT_BASE_INSTANCE_COUNTER).write(value);
    }

    #[test]
    fn installs_the_target_width_prefix_and_returns_its_input() {
        let _guard = TEST_LOCK.lock();
        let mut object = [0xa5a5_a5a5; 4];
        unsafe {
            set_instance_counter(0x1020_3040);
            let returned = object_base_construct(object.as_mut_ptr());
            assert_eq!(returned, object.as_mut_ptr());
        }
        assert_eq!(object, [OBJECT_BASE_VTABLE_ADDRESS, 0x1020_3040, 0, 0]);
    }

    #[test]
    fn increments_the_shared_counter_with_u32_wraparound() {
        let _guard = TEST_LOCK.lock();
        let mut first = [0; 4];
        let mut second = [0; 4];
        unsafe {
            set_instance_counter(u32::MAX);
            object_base_construct(first.as_mut_ptr());
            object_base_construct(second.as_mut_ptr());
        }
        assert_eq!(first[1], u32::MAX);
        assert_eq!(second[1], 0);
    }
}
