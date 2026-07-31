//! `ui_noop_f7f4` — original: `FUN_0811f7f4` @ `0x0811f7f4` (4 bytes).
//!
//! The complete ARM body is `bx lr`, so this ABI-visible UI entry point returns
//! immediately without reading or modifying any state.
//!
//! Deviations: none. Although some decompiled callers pass an object-derived
//! value in r0, the recovered C signature is `void (void)` and the stock body
//! neither consumes that register nor guarantees a result through it.

/// Returns immediately without reading or modifying UI state.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn ui_noop_f7f4() {}

#[cfg(test)]
mod tests {
    use super::ui_noop_f7f4;

    #[test]
    fn returns_without_mutating_observable_state() {
        let observable = [0x12u8, 0x34, 0x56, 0x78];
        let before = observable;

        ui_noop_f7f4();

        assert_eq!(observable, before);
    }
}
