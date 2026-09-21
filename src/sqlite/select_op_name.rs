/// `select_op_name` — original: `FUN_08368c78` @ `0x08368c78` (40 bytes).
///
/// Verified inbound calls: three plain `bl`, zero predicated `bl`; the body
/// makes no calls. Select the compound-query operator text for SQLite parser
/// token codes: `TK_ALL` maps to `UNION ALL`, `TK_INTERSECT` to `INTERSECT`,
/// `TK_EXCEPT` to `EXCEPT`, and every other code to `UNION`. The returned
/// values are the original firmware string addresses. Deliberate deviations:
/// none.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub extern "C" fn select_op_name(operation: u32) -> u32 {
    const UNION_ALL: u32 = 0x088f_e11c;
    const INTERSECT: u32 = 0x088f_e124;
    const UNION: u32 = 0x088f_e128;
    const EXCEPT: u32 = 0x088f_e12c;

    match operation {
        0x6b => UNION_ALL,
        0x6c => INTERSECT,
        0x6d => EXCEPT,
        _ => UNION,
    }
}

#[cfg(test)]
mod tests {
    use super::select_op_name;

    #[test]
    fn maps_each_compound_operator_token() {
        assert_eq!(select_op_name(0x6b), 0x088f_e11c);
        assert_eq!(select_op_name(0x6c), 0x088f_e124);
        assert_eq!(select_op_name(0x6d), 0x088f_e12c);
    }

    #[test]
    fn defaults_to_union_outside_the_three_token_codes() {
        for operation in [0, 0x6a, 0x6e, u32::MAX] {
            assert_eq!(select_op_name(operation), 0x088f_e128);
        }
    }
}
