//! HFS B-tree record-request preparation.

use core::ptr::addr_of;

use super::hfs_btree_get_node::BTreeControlBlock;
use super::hfs_btree_key_length::hfs_btree_key_length;

/// RetailOS load address of the opaque request consumer.
pub const HFS_BTREE_RECORD_REQUEST_CONSUMER_ADDRESS: usize = 0x0805_8e64;

/// The target-sized request assembled by `hfs_btree_prepare_record_request`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct HfsBTreeRecordRequest {
    pub operation_context: u32,
    pub node_height: u32,
    pub record_index: u32,
    pub result: u32,
    pub key: u32,
    pub data: u32,
    pub key_length: u16,
    pub data_length: u16,
    pub operation_flags: u8,
    pub reserved: u8,
}

/// ABI of the unported request consumer at `0x08058e64`.
pub type HfsBTreeRecordRequestConsumer = unsafe extern "C" fn(
    btree: *mut BTreeControlBlock,
    node: *mut u8,
    request: *mut HfsBTreeRecordRequest,
    options: u32,
    operation_context: *mut u8,
    node_height: u16,
    record_index: u32,
    result: *mut u8,
) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn resident_consume_record_request(
    btree: *mut BTreeControlBlock,
    node: *mut u8,
    request: *mut HfsBTreeRecordRequest,
    options: u32,
    operation_context: *mut u8,
    node_height: u16,
    record_index: u32,
    result: *mut u8,
) -> i32 {
    let consumer: HfsBTreeRecordRequestConsumer =
        unsafe { core::mem::transmute(HFS_BTREE_RECORD_REQUEST_CONSUMER_ADDRESS) };
    unsafe { consumer(btree, node, request, options, operation_context, node_height, record_index, result) }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_consume_record_request(
    _btree: *mut BTreeControlBlock,
    _node: *mut u8,
    _request: *mut HfsBTreeRecordRequest,
    _options: u32,
    _operation_context: *mut u8,
    _node_height: u16,
    _record_index: u32,
    _result: *mut u8,
) -> i32 {
    panic!("hfs_btree_prepare_record_request needs a host request-consumer model")
}

#[cfg(target_os = "none")]
pub static mut HFS_BTREE_RECORD_REQUEST_CONSUMER: HfsBTreeRecordRequestConsumer =
    resident_consume_record_request;
#[cfg(not(target_os = "none"))]
pub static mut HFS_BTREE_RECORD_REQUEST_CONSUMER: HfsBTreeRecordRequestConsumer =
    missing_consume_record_request;

#[inline(always)]
unsafe fn request_consumer() -> HfsBTreeRecordRequestConsumer {
    unsafe { addr_of!(HFS_BTREE_RECORD_REQUEST_CONSUMER).read_volatile() }
}

/// `hfs_btree_prepare_record_request` — original: `FUN_080595c0` @
/// `0x080595c0` (132 bytes, `0x080595c0..0x08059644`; 3 verified inbound
/// direct call sites, all unconditional plain `bl` at `0x08041354`,
/// `0x08041ce0`, and `0x08048dec`; no predicated inbound `bl`). Its two
/// outgoing calls are unconditional plain `bl` at `0x08059600` and
/// `0x08059638`.
///
/// Builds the target's 34-byte B-tree record request: it obtains the HFS key
/// length, copies the seven remaining request words/halfwords/bytes into their
/// exact stack offsets, clears the final byte, and forwards it to the opaque
/// resident consumer at `0x08058e64` with options zero. The consumer has no
/// established identity, so this port deliberately names only its ABI and
/// address rather than assigning semantics not proven by the raw code.
/// Deliberate deviations: the unported direct call is a volatile dispatch seam
/// on the host; target builds call the resident address directly.
///
/// # Safety
///
/// `btree` and `key` must meet [`hfs_btree_key_length`]'s requirements. Every
/// pointer argument is forwarded unchanged to the resident consumer, whose
/// corresponding target ABI requirements apply.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.hfs_btree_prepare_record_request")]
#[inline(never)]
pub unsafe extern "C" fn hfs_btree_prepare_record_request(
    btree: *mut BTreeControlBlock,
    node: *mut u8,
    key: *const u8,
    data: *mut u8,
    data_length: u16,
    operation_context: *mut u8,
    node_height: u16,
    record_index: u32,
    operation_flags: u8,
    result: *mut u8,
) -> i32 {
    let request = HfsBTreeRecordRequest {
        operation_context: operation_context as usize as u32,
        node_height: node_height as u32,
        record_index,
        result: result as usize as u32,
        key: key as usize as u32,
        data: data as usize as u32,
        key_length: unsafe { hfs_btree_key_length(btree, key, (record_index == 1) as u32) },
        data_length,
        operation_flags,
        reserved: 0,
    };
    unsafe {
        request_consumer()(
            btree,
            node,
            core::ptr::addr_of!(request).cast_mut(),
            0,
            operation_context,
            node_height,
            record_index,
            result,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut OBSERVED: HfsBTreeRecordRequest = HfsBTreeRecordRequest {
        operation_context: 0, node_height: 0, record_index: 0, result: 0,
        key: 0, data: 0, key_length: 0, data_length: 0, operation_flags: 0, reserved: 0,
    };
    unsafe extern "C" fn record_consumer(
        _btree: *mut BTreeControlBlock, _node: *mut u8, request: *mut HfsBTreeRecordRequest,
        options: u32, _operation_context: *mut u8, _node_height: u16, _record_index: u32,
        _result: *mut u8,
    ) -> i32 {
        assert_eq!(options, 0);
        unsafe {
            CALLS += 1;
            OBSERVED = request.read();
        }
        -7
    }

    struct Reset(HfsBTreeRecordRequestConsumer);
    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe { core::ptr::addr_of_mut!(HFS_BTREE_RECORD_REQUEST_CONSUMER).write_volatile(self.0) };
        }
    }

    #[test]
    fn builds_exact_request_and_forwards_consumer_status() {
        let _lock = TEST_LOCK.lock();
        let prior = unsafe { request_consumer() };
        let _reset = Reset(prior);
        unsafe {
            core::ptr::addr_of_mut!(HFS_BTREE_RECORD_REQUEST_CONSUMER).write_volatile(record_consumer);
            CALLS = 0;
        }
        let mut btree: BTreeControlBlock = unsafe { core::mem::zeroed() };
        btree.attributes = 2;
        let key = 0x80f1_u16;
        let mut node = [0_u8; 4];
        let mut data = [0_u8; 4];
        let mut context = [0_u8; 4];
        let mut result = [0_u8; 4];
        assert_eq!(unsafe {
            hfs_btree_prepare_record_request(
                &mut btree, node.as_mut_ptr(), (&key as *const u16).cast(), data.as_mut_ptr(),
                0x1234, context.as_mut_ptr(), 0xabcd, 1, 0xfe, result.as_mut_ptr(),
            )
        }, -7);
        let observed = unsafe { OBSERVED };
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(observed.operation_context, context.as_mut_ptr() as usize as u32);
        assert_eq!(observed.node_height, 0xabcd);
        assert_eq!(observed.record_index, 1);
        assert_eq!(observed.result, result.as_mut_ptr() as usize as u32);
        assert_eq!(observed.key, (&key as *const u16) as usize as u32);
        assert_eq!(observed.data, data.as_mut_ptr() as usize as u32);
        assert_eq!(observed.key_length, 0x80f1);
        assert_eq!(observed.data_length, 0x1234);
        assert_eq!(observed.operation_flags, 0xfe);
        assert_eq!(observed.reserved, 0);
    }

    #[test]
    fn fixed_leaf_key_uses_control_length_before_dispatch() {
        let _lock = TEST_LOCK.lock();
        let prior = unsafe { request_consumer() };
        let _reset = Reset(prior);
        unsafe {
            core::ptr::addr_of_mut!(HFS_BTREE_RECORD_REQUEST_CONSUMER).write_volatile(record_consumer);
            CALLS = 0;
        }
        let mut btree: BTreeControlBlock = unsafe { core::mem::zeroed() };
        btree.max_key_length = 0xbeef;
        assert_eq!(unsafe {
            hfs_btree_prepare_record_request(
                &mut btree, core::ptr::null_mut(), core::ptr::dangling(), core::ptr::null_mut(),
                0, core::ptr::null_mut(), 0, 0, 0, core::ptr::null_mut(),
            )
        }, -7);
        assert_eq!(unsafe { CALLS }, 1);
        assert_eq!(unsafe { OBSERVED.key_length }, 0xbeef);
    }
}
