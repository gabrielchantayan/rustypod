//! Move a linked entry to the queue tail — retailOS 0x08058c3c.
//!
//! True extent [0x08058c3c,0x08058c80), 68 bytes; next function starts
//! with LDR r2,[r0,#4]. Verified inbound BLs: one plain at 0x0806b598,
//! one predicated at 0x0806c4f0. Zero outbound plain or predicated BLs.
//! Return unchanged for the current tail; otherwise publish the new tail,
//! unlink the entry from its successor and predecessor (or update head),
//! clear next, set previous to the old tail, and link the old tail forward.
//! Deviations: none for valid retail queues. Target-width pointer words
//! preserve firmware offsets on hosts; no allocation or callee seams.

/// # Safety
/// Queue words +1/+2 are head/tail; entry words +0/+1 are next/previous.
/// Entry must belong to a valid nonempty doubly linked queue. All accessed
/// objects must be writable, aligned, and addressed within the u32 range.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn move_entry_to_queue_end(queue: *mut u32, entry: *mut u32) {
    let tail = queue.add(2).read() as *mut u32;
    if tail == entry { return; }
    queue.add(2).write(entry as usize as u32);
    let previous = entry.add(1).read();
    let next = entry.read() as *mut u32;
    next.add(1).write(previous);
    let previous = entry.add(1).read() as *mut u32;
    if previous.is_null() {
        queue.add(1).write(entry.read());
    } else {
        previous.write(entry.read());
    }
    entry.write(0);
    entry.add(1).write(tail as usize as u32);
    tail.write(entry as usize as u32);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};

    #[test]
    fn every_position_preserves_bidirectional_order_and_payload() {
        let Some(base) = try_map_u32_slab(hints::MOVE_ENTRY_TO_QUEUE_END, 4096) else {
            assert!(note_missing_u32_fixture("util/move_entry_to_queue_end"));
            return;
        };
        unsafe {
            let queue = base.cast::<u32>();
            for count in 1..=4 {
                for selected in 0..count {
                    let nodes: [*mut u32; 4] = core::array::from_fn(|i| queue.add(16 + i*8));
                    queue.write(0xabcdef01);
                    queue.add(1).write(nodes[0] as usize as u32);
                    queue.add(2).write(nodes[count-1] as usize as u32);
                    for i in 0..count {
                        nodes[i].write(if i+1 == count { 0 } else { nodes[i+1] as usize as u32 });
                        nodes[i].add(1).write(if i == 0 { 0 } else { nodes[i-1] as usize as u32 });
                        nodes[i].add(2).write(0x12340000 + i as u32);
                    }
                    move_entry_to_queue_end(queue, nodes[selected]);
                    let mut order = [0; 4];
                    let mut n = 0;
                    for i in 0..count { if i != selected { order[n] = i; n += 1; } }
                    order[n] = selected;
                    assert_eq!(queue.read(), 0xabcdef01);
                    assert_eq!(queue.add(1).read(), nodes[order[0]] as usize as u32);
                    assert_eq!(queue.add(2).read(), nodes[selected] as usize as u32);
                    for position in 0..count {
                        let i = order[position];
                        assert_eq!(nodes[i].read(), if position+1 == count { 0 } else { nodes[order[position+1]] as usize as u32 });
                        assert_eq!(nodes[i].add(1).read(), if position == 0 { 0 } else { nodes[order[position-1]] as usize as u32 });
                        assert_eq!(nodes[i].add(2).read(), 0x12340000 + i as u32);
                    }
                }
            }
        }
    }
}
