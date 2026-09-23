//! Input-sequence item action clearing — `FUN_081293cc` @ **0x081293cc**.
//!
//! # Raw extent and call sites
//!
//! The 37 ARM words at `0x081293cc..0x08129460` form the complete **148-byte**
//! body; the independently entered next function begins at `0x08129464`. A
//! complete raw ARM branch scan finds three direct inbound calls: one plain
//! `bl` at `0x08129cb0`, and two predicated `blne` calls at `0x08129ccc` and
//! `0x0812ae20`.
//!
//! # Algorithm
//!
//! If the item has no pending-node head at `+0x04`, return. Otherwise, form the
//! MSB-first action bit `0x8000_0000 >> (action_index & 0xff)` (zero when that
//! shift count is at least 32). When that bit is set in `+0x08`, clear it and
//! unlink the first pending node whose byte `+0x13` equals `action_index`, then
//! release that node and return. Only when no node is removed does it sample
//! Timer E and store its truncated millisecond value at `+0x0c`.
//!
//! # Deliberate deviations
//!
//! The stock function holds its sampled counter in a stack word and calls the
//! already ported timer helpers directly; Rust preserves those operations but
//! uses host-only timer and deletion seams so tests neither touch Timer E MMIO
//! nor the retail heap. Item and node pointers remain target-width `u32` words
//! so host pointer width cannot alter the retail offsets.

#[cfg(test)]
static mut READ_USEC_TIMER: unsafe extern "C" fn(*mut u32) = crate::drivers::timer::read_usec_timer_into;
#[cfg(test)]
static mut DELETE_PENDING_NODE: unsafe extern "C" fn(*mut u8) = crate::heap::veneers::operator_delete;

#[inline(always)]
unsafe fn read_usec_timer(out: *mut u32) {
    #[cfg(test)]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(READ_USEC_TIMER))(out);
    }
    #[cfg(not(test))]
    {
        crate::drivers::timer::read_usec_timer_into(out);
    }
}

#[inline(always)]
unsafe fn delete_pending_node(node: *mut u8) {
    #[cfg(test)]
    {
        core::ptr::read_volatile(core::ptr::addr_of!(DELETE_PENDING_NODE))(node);
    }
    #[cfg(not(test))]
    {
        crate::heap::veneers::operator_delete(node);
    }
}

/// Clears one pending action from an input-sequence item.
///
/// # Safety
///
/// `item` must point to the retail four-word prefix and every nonzero pending
/// node word must be a valid target-width pointer to a node with link word
/// `+0x04` and action byte `+0x13`.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn input_sequence_item_clear_action(item: *mut u32, action_index: u32) {
    let head = unsafe { item.add(1).read() };
    if head == 0 {
        return;
    }

    let action_bit = 0x8000_0000u32.checked_shr(action_index & 0xff).unwrap_or(0);
    let pending_actions = unsafe { item.add(2).read() };
    if pending_actions & action_bit != 0 {
        unsafe { item.add(2).write(pending_actions & !action_bit) };

        let mut previous = head as *mut u32;
        if unsafe { (previous as *const u8).add(0x13).read() } == action_index as u8 {
            let next = unsafe { previous.add(1).read() };
            unsafe { item.add(1).write(next) };
            unsafe { delete_pending_node(previous.cast()) };
            return;
        } else {
            let mut node = unsafe { previous.add(1).read() } as *mut u32;
            while !node.is_null() {
                if unsafe { (node as *const u8).add(0x13).read() } == action_index as u8 {
                    let next = unsafe { node.add(1).read() };
                    unsafe { previous.add(1).write(next) };
                    unsafe { delete_pending_node(node.cast()) };
                    return;
                }
                previous = node;
                node = unsafe { node.add(1).read() } as *mut u32;
            }
        }
    }

    let mut counter_usec = 0;
    unsafe { read_usec_timer(&mut counter_usec) };
    unsafe { item.add(3).write(crate::drivers::timer::usec_to_millis(&counter_usec)) };
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    static mut DELETE_CALLS: u32 = 0;
    static mut DELETED_NODE: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn fixed_usec_timer(out: *mut u32) {
        out.write(1_234_999);
    }

    unsafe extern "C" fn record_delete(node: *mut u8) {
        DELETE_CALLS += 1;
        DELETED_NODE = node;
    }

    unsafe fn prepare_fixture() -> Option<(*mut u32, *mut u32, *mut u32)> {
        let slab = try_map_u32_slab(hints::INPUT_SEQUENCE_ITEM_CLEAR_ACTION, 0x1000)?;
        core::ptr::write_bytes(slab, 0, 0x1000);
        Some((slab.add(0x100).cast(), slab.add(0x200).cast(), slab.add(0x300).cast()))
    }

    unsafe fn install_seams() {
        DELETE_CALLS = 0;
        DELETED_NODE = core::ptr::null_mut();
        READ_USEC_TIMER = fixed_usec_timer;
        DELETE_PENDING_NODE = record_delete;
    }

    #[test]
    fn null_head_returns_without_changing_state_or_sampling_timer() {
        let _guard = TEST_LOCK.lock();
        let Some((item, _, _)) = (unsafe { prepare_fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            install_seams();
            item.add(2).write(0xffff_ffff);
            item.add(3).write(77);
            input_sequence_item_clear_action(item, 5);
            assert_eq!(item.add(2).read(), 0xffff_ffff);
            assert_eq!(item.add(3).read(), 77);
            assert_eq!(DELETE_CALLS, 0);
        }
    }

    #[test]
    fn clear_bit_unlinks_matching_head_without_sampling_timer() {
        let _guard = TEST_LOCK.lock();
        let Some((item, head, next)) = (unsafe { prepare_fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            install_seams();
            item.add(1).write(head as usize as u32);
            item.add(2).write(0x8000_0000);
            head.add(1).write(next as usize as u32);
            (head as *mut u8).add(0x13).write(0);
            input_sequence_item_clear_action(item, 0);
            assert_eq!(item.add(1).read(), next as usize as u32);
            assert_eq!(item.add(2).read(), 0);
            assert_eq!(item.add(3).read(), 0);
            assert_eq!(DELETE_CALLS, 1);
            assert_eq!(DELETED_NODE, head.cast());
        }
    }

    #[test]
    fn clear_bit_unlinks_first_matching_later_node_only() {
        let _guard = TEST_LOCK.lock();
        let Some((item, head, matching)) = (unsafe { prepare_fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            install_seams();
            let tail = matching.add(0x80);
            item.add(1).write(head as usize as u32);
            item.add(2).write(0x4000_0000);
            head.add(1).write(matching as usize as u32);
            (head as *mut u8).add(0x13).write(0);
            matching.add(1).write(tail as usize as u32);
            (matching as *mut u8).add(0x13).write(1);
            input_sequence_item_clear_action(item, 1);
            assert_eq!(item.add(1).read(), head as usize as u32);
            assert_eq!(head.add(1).read(), tail as usize as u32);
            assert_eq!(item.add(3).read(), 0);
            assert_eq!(DELETE_CALLS, 1);
            assert_eq!(DELETED_NODE, matching.cast());
        }
    }

    #[test]
    fn clear_bit_without_a_matching_node_samples_and_converts_timer() {
        let _guard = TEST_LOCK.lock();
        let Some((item, head, _)) = (unsafe { prepare_fixture() }) else {
            assert!(note_missing_u32_fixture(module_path!()));
            return;
        };
        unsafe {
            install_seams();
            item.add(1).write(head as usize as u32);
            item.add(2).write(0x4000_0000);
            (head as *mut u8).add(0x13).write(0);
            item.add(3).write(77);
            input_sequence_item_clear_action(item, 1);
            assert_eq!(item.add(2).read(), 0);
            assert_eq!(item.add(1).read(), head as usize as u32);
            assert_eq!(item.add(3).read(), 1_234);
            assert_eq!(DELETE_CALLS, 0);
        }
    }
}
