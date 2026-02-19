// ============================================================================
// CFA Test Decompilations (merged m2c + Ghidra)
// m2c: PowerPC decompiler (no VMX128 support)
// Ghidra: PowerPC:BE:64:Xenon with GhidraXenon extension (full VMX128)
// Variables renamed for readability
// ============================================================================


// ============================================================================
// Test 0: Stub function that returns zero (no-op / default handler)
// ============================================================================

// --- m2c ---

s32 test_0(void) {
    return 0;
}

// --- Ghidra ---

undefined8 test_0(void)
{
    return 0;
}


// ============================================================================
// Test 1: Iterates a linked data structure, dispatching via a vtable pointer
// ============================================================================

// --- m2c ---

void *test_1(void *self) {
    s64 data_ptr;

    if ((u32) M2C_FIELD(self, u32 *, 4) != 0U) {
        unksp-20 = M2C_FIELD(self, s64 *, 0x10);
        data_ptr = M2C_FIELD(self, s64 *, 0);
        unksp-18 = data_ptr;
        unksp-10 = data_ptr;
        if ((s32) unksp-20 > 0) {
            return (void *) unksp-18;
        }
    }
    return self;
}

// --- Ghidra ---

void test_1(undefined8 *self, undefined8 extra_param)
{
    int count;
    undefined4 *node_ptr;
    undefined4 data_hi;

    if (*(int *)((int)self + 4) != 0) {
        count = (int)((ulonglong)self[2] >> 0x20);
        if (0 < count) {
            node_ptr = (undefined4 *)self[2];
            data_hi = (undefined4)((ulonglong)*self >> 0x20);
            /* WARNING: Could not recover jumptable at 0x820869f8. Too many branches */
            /* WARNING: Treating indirect jump as call */
            (**(code **)(((uint)node_ptr[1] >> 0x1d) * 4 + -0x7df79604))
                      (data_hi, extra_param, data_hi, count, *node_ptr, 0);
            return;
        }
    }
    return;
}


// ============================================================================
// Test 2: Clamps a float value based on a mode enum; asserts on invalid mode
// ============================================================================

// --- m2c ---

M2C_UNK assert_fail();
M2C_UNK assert_msg(M2C_UNK, M2C_UNK);
M2C_UNK assert_notify(M2C_UNK);

void *test_2(void *self, f32 *out_value, f32 input_value) {
    if ((u32) M2C_FIELD(self, u32 *, 0xA68) <= 3U) {
        return self;
    }
    assert_notify(0x8202B674);
    assert_msg(0x8202B628, 0x15F);
    assert_fail();
    *out_value = input_value;
    return NULL;
}

// --- Ghidra ---

undefined8 test_2(double input_value, int self, undefined8 unused, float *out_value)
{
    undefined8 result;

    switch (*(undefined4 *)(self + 0xa68)) {
    case 0:
    case 3:
        break;
    case 1:
        if (input_value < (double)*(float *)(self + 0xa5c)) {
            *out_value = *(float *)(self + 0xa5c);
            return 1;
        }
        break;
    case 2:
        if (((double)*(float *)(self + 0xa60) < input_value) &&
            (*(char *)(self + 0xa6f) == '\0')) {
            *out_value = *(float *)(self + 0xa60);
            return 1;
        }
        break;
    default:
        result = assert_notify();
        assert_msg(result, 0xffffffff8202b628, 0x15f);
        assert_fail();
    }
    *out_value = (float)input_value;
    return 0;
}


// ============================================================================
// Test 3: VMX128 vector spline/curve evaluation with reciprocal refinement
// ============================================================================

// --- m2c ---

void test_3(s32 num_iterations, s32 offset, s32 dest_offset, f32 initial_value) {
    s32 loop_counter;

    unksp-20 = initial_value;
    M2C_ERROR(/* unknown instruction: lvrx $v0, $r8, $r10 */);
    M2C_ERROR(/* unknown instruction: lvlx $v13, $r0, $r10 */);
    M2C_ERROR(/* unknown instruction: vor $v12, $v13, $v0 */);
    M2C_ERROR(/* unknown instruction: vspltw $v9, $v11, 0x0 */);
    M2C_ERROR(/* unknown instruction: vxor $v8, $v12, $v0 */);
    M2C_ERROR(/* unknown instruction: lvrx $v7, $r8, $r11 */);
    M2C_ERROR(/* unknown instruction: lvlx $v6, $r0, $r11 */);
    M2C_ERROR(/* unknown instruction: vor $v4, $v6, $v7 */);
    M2C_ERROR(/* unknown instruction: vaddfp $v5, $v8, $v9 */);
    M2C_ERROR(/* unknown instruction: vsubfp $v11, $v4, $v9 */);
    if (num_iterations >= 1) {
        M2C_ERROR(/* unknown instruction: vspltisw $v9, 0x0 */);
        loop_counter = num_iterations;
        do {
            M2C_ERROR(/* unknown instruction: vaddfp $v8, $v11, $v0 */);
            loop_counter -= 1;
            M2C_ERROR(/* unknown instruction: vrefp $v13, $v8 */);
        } while (loop_counter != 0);
    }
    if ((u32) num_iterations <= 3U) {
        return;
    }
    *(M2C_ERROR(/* Read from unset register $r0 */) + dest_offset) =
        M2C_BITWISE(f128, M2C_ERROR(/* unknown instruction: vxor $v0, $v0, $v0 */));
}

// --- Ghidra ---

void test_3(undefined8 param_1, ulonglong param_2, longlong base_addr,
            undefined8 param_4, int dest_offset)
{
    undefined4 *aligned_src;
    undefined4 *aligned_dst;
    ulonglong in_r0;
    uint num_iterations;
    longlong load_addr;
    undefined1 auVar_right [16];
    undefined1 auVar_left [16];
    undefined1 auVar_merged [16];
    undefined1 auVar_delta [16];
    undefined1 in_vs42 [16];
    undefined1 in_vs43 [16];
    undefined1 auVar_recip [16];
    undefined1 auVar_refined [16];
    undefined4 saved_w1;
    float t_param;
    undefined4 saved_w2;
    undefined4 saved_w3;
    undefined1 in_vr3 [16];
    undefined1 auVar_product [16];
    float in_register_00010040;
    float in_register_00010044;
    float in_register_00010048;
    float in_vr4;
    float in_register_00010054;
    float in_register_00010058;
    undefined1 in_vr9 [16];
    float in_register_000100c0;
    float in_register_000100c4;
    float in_register_000100c8;
    float in_vr12;
    undefined1 local_stack [24];

    num_iterations = (uint)param_2;
    load_addr = (param_2 - 3 & 0x3fffffff) * 4 + base_addr;
    auVar_right = loadVectorRightIndexed128(0x10, load_addr);
    auVar_left = loadVectorLeftIndexed128(in_r0, load_addr);
    base_addr = (param_2 & 0x3fffffff) * 4 + base_addr;
    auVar_delta = in_vs43 >> 0x60;
    auVar_delta = auVar_delta & (undefined1 [16])0xffffffff |
                  auVar_delta << 0x20 | auVar_delta << 0x40 | auVar_delta << 0x60;
    auVar_merged = loadVectorRightIndexed128(0x10, base_addr);
    auVar_left = loadVectorLeftIndexed128(in_r0, base_addr);
    vectorAddFloatingPoint((auVar_left | auVar_right) ^ auVar_right, auVar_delta);
    auVar_delta = vectorSubtractFloatingPoint(auVar_left | auVar_merged, auVar_delta);
    auVar_left = in_vs42;
    t_param = in_register_00010058;
    if (0 < (int)num_iterations) {
        do {
            auVar_recip = vectorAddFloatingPoint(auVar_delta, auVar_right);
            param_2 = param_2 - 1;
            auVar_refined = vectorReciprocalEstimateFloatingPoint(auVar_recip);
            auVar_recip = vectorNegativeMultiplySubtractFloatingPoint(
                              auVar_refined, auVar_recip, in_vs42);
            vectorMultiplyAddFloatingPoint(auVar_recip, auVar_refined, auVar_refined);
            auVar_recip._8_8_ = in_vr3._8_8_;
            auVar_recip._4_4_ = in_register_00010054 * in_register_000100c4 *
                                in_register_00010044;
            auVar_recip._0_4_ = in_register_00010054 * in_register_000100c0 *
                                in_register_00010040;
            auVar_product._0_8_ = auVar_recip._0_8_;
            auVar_product._8_4_ = t_param * in_register_000100c8 * in_register_00010048;
            auVar_product._12_4_ = in_register_00010058 * in_vr12 * in_vr4;
            in_vr3 = vectorRotateLeftImmediateMaskInsert128(auVar_product, in_vr9, 1, 0);
            in_vr12 = in_vr3._12_4_;
            in_register_000100c8 = in_vr3._0_4_;
            auVar_recip = vectorMultiplyAddFloatingPoint(auVar_delta, auVar_refined, auVar_left);
            auVar_left = vectorConditionalSelect(auVar_recip, auVar_left, auVar_merged);
            t_param = in_register_00010054;
            in_register_000100c4 = in_register_000100c8;
            in_register_000100c0 = in_vr12;
        } while (param_2 != 0);
    }
    aligned_src = (undefined4 *)((uint)(local_stack + (int)in_r0) & 0xfffffff0);
    saved_w1 = aligned_src[1];
    saved_w2 = aligned_src[2];
    saved_w3 = aligned_src[3];
    auVar_right = (undefined1 [16])0x0;
    if (num_iterations < 4) {
        in_r0 = (ulonglong)*(uint *)(num_iterations * 4 + -0x7d044b9c);
        switch (num_iterations) {
        case 3:
            auVar_right = vectorMultiplyAddFloatingPoint(
                auVar_delta,
                auVar_left & (undefined1 [16])0xffffffff | auVar_left << 0x20 |
                (auVar_left & (undefined1 [16])0xffffffff) << 0x40 | auVar_left << 0x60,
                (undefined1 [16])0x0);
        case 2:
            auVar_merged = auVar_left >> 0x20;
            auVar_right = vectorMultiplyAddFloatingPoint(
                auVar_delta,
                auVar_merged & (undefined1 [16])0xffffffff | auVar_merged << 0x20 |
                (auVar_merged & (undefined1 [16])0xffffffff) << 0x40 | auVar_merged << 0x60,
                auVar_right);
        case 1:
            auVar_merged = auVar_left >> 0x40;
            auVar_right = vectorMultiplyAddFloatingPoint(
                auVar_delta,
                auVar_merged & (undefined1 [16])0xffffffff | auVar_merged << 0x20 |
                (auVar_merged & (undefined1 [16])0xffffffff) << 0x40 | auVar_merged << 0x60,
                auVar_right);
        case 0:
            auVar_merged = auVar_left >> 0x60;
            vectorMultiplyAddFloatingPoint(
                auVar_left,
                auVar_merged & (undefined1 [16])0xffffffff | auVar_merged << 0x20 |
                auVar_merged << 0x40 | auVar_merged << 0x60,
                auVar_right);
        }
    }
    aligned_dst = (undefined4 *)((int)in_r0 + dest_offset & 0xfffffff0);
    *aligned_dst = *aligned_src;
    aligned_dst[1] = saved_w1;
    aligned_dst[2] = saved_w2;
    aligned_dst[3] = saved_w3;
    return;
}


// ============================================================================
// Test 4: Maps a raw input scan code to an internal button enum value
// ============================================================================

// --- m2c ---

u32 get_raw_input();
s32 query_input_device(M2C_UNK, M2C_UNK, u8 *, M2C_UNK, s16 *);

s32 test_4(void) {
    s16 report_id;
    u8 scan_code;
    s32 query_result;
    u32 raw_input;
    u8 device_type;
    u8 button_id;

    report_id = 0;
    query_result = query_input_device(3, 0xE, &scan_code, 1, &report_id);
    if ((query_result >= 0) && (scan_code <= 0x6EU) && ((void *) (scan_code - 5) <= 0x68U)) {
        return query_result;
    }
    button_id = 0;
    if ((0 == 0) || (0U > 0x25U)) {
        raw_input = get_raw_input();
        device_type = (u8) (raw_input >> 8U);
        if (device_type == 1) {
            button_id = ((((raw_input - 0x101) == 0) & 1) ^ 1) + 0x14;
        } else {
            button_id = ((((device_type - 2) == 0) & 1) ^ 1) + 0x23;
        }
    }
    return (s32) button_id;
}

// --- Ghidra ---

ulonglong test_4(void)
{
    int query_result;
    longlong raw_input;
    ulonglong button_id;
    byte scan_code_buf [2];
    undefined2 report_id_buf [7];

    report_id_buf[0] = 0;
    query_result = query_input_device(3, 0xe, scan_code_buf, 1, report_id_buf);
    if (query_result < 0) {
LAB_no_match:
        button_id = 0;
    }
    else {
        switch (scan_code_buf[0]) {
        case 5:
            button_id = 2;
            break;
        case 6:
            button_id = 1;
            break;
        default:
            goto LAB_no_match;
        case 8:
            button_id = 3;
            break;
        case 0xd:
            button_id = 4;
            break;
        case 0x10:
            button_id = 5;
            break;
        case 0x12:
            button_id = 0x21;
            break;
        case 0x13:
            button_id = 6;
            break;
        case 0x14:
            button_id = 7;
            break;
        case 0x15:
            button_id = 8;
            break;
        case 0x17:
            button_id = 9;
            break;
        case 0x18:
            button_id = 0xd;
            break;
        case 0x19:
            button_id = 10;
            break;
        case 0x1f:
            button_id = 0x1f;
            break;
        case 0x20:
            button_id = 0xb;
            break;
        case 0x22:
            button_id = 0xc;
            break;
        case 0x23:
            button_id = 0x23;
            break;
        case 0x25:
            button_id = 0xe;
            break;
        case 0x27:
            button_id = 0xf;
            break;
        case 0x2a:
            button_id = 0x10;
            break;
        case 0x2c:
            button_id = 0x12;
            break;
        case 0x2e:
            button_id = 0x11;
            break;
        case 0x32:
            button_id = 0x13;
            break;
        case 0x35:
            button_id = 0x14;
            break;
        case 0x38:
            button_id = 0x15;
            break;
        case 0x47:
            button_id = 0x16;
            break;
        case 0x4a:
            button_id = 0x17;
            break;
        case 0x4b:
            button_id = 0x19;
            break;
        case 0x4c:
            button_id = 0x18;
            break;
        case 0x52:
            button_id = 0x1a;
            break;
        case 0x54:
            button_id = 0x1b;
            break;
        case 0x58:
            button_id = 0x25;
            break;
        case 0x5a:
            button_id = 0x20;
            break;
        case 0x5b:
            button_id = 0x1c;
            break;
        case 0x5d:
            button_id = 0x1d;
            break;
        case 0x65:
            button_id = 0x22;
            break;
        case 0x67:
            button_id = 0x24;
            break;
        case 0x6d:
            button_id = 0x1e;
        }
    }
    if ((button_id == 0) || (0x25 < button_id)) {
        raw_input = get_raw_input();
        button_id = (ulonglong)(raw_input << 0x20) >> 0x28 & 0xff;
        if (button_id == 1) {
            button_id = ((ulonglong)(LZCOUNT((int)raw_input + -0x101) << 0x20) >> 0x25 ^ 1) + 0x14;
        }
        else {
            button_id = ((ulonglong)(LZCOUNT((int)button_id + -2) << 0x20) >> 0x25 ^ 1) + 0x23;
        }
    }
    return button_id;
}

// ============================================================================
// Test 5: Computes a weighted float value from a type-keyed iterator
// ============================================================================

// --- m2c ---

M2C_UNK iter_init(s32 *);                              /* extern */
M2C_UNK iter_destroy(s32 *);                            /* extern */
s32 iter_get_key(s32 *);                                /* extern */
u32 iter_has_next(s32 *);                               /* extern */
f32 iter_get_value(s32 *, M2C_UNK);                     /* extern */
f32 get_base_weight();                                  /* extern */
f32 get_scale_factor(s32);                              /* extern */

f32 test_5(void ***self) {
    s32 iterator;
    f32 current_value;
    f32 weighted_result;
    f32 result;
    s32 key;

    iter_init(&iterator);
    iterator = 0x8202C418;
    current_value = iter_get_value(&iterator, 0);
    if ((void *) **self <= 0x1BU) {
        return current_value;
    }
    if (iter_has_next(&iterator) != 0U) {
        key = iter_get_key(&iterator);
        iter_get_key(&iterator);
        weighted_result = get_base_weight();
        result = weighted_result * get_scale_factor(key);
    } else {
        result = *(f32 *)0x8200D72C;
    }
    iter_destroy(&iterator);
    return result;
}

// --- Ghidra ---

double test_5(undefined8 unused, int *self)
{
    undefined4 *vtable_ptr;
    float fallback_value;
    undefined1 *cleanup_target;
    int key;
    undefined8 temp_result;
    double base_weight;
    double scale_factor;
    undefined4 stack_iter [2];
    undefined1 case_buf_0 [8];
    undefined1 case_buf_4 [8];
    undefined1 case_buf_10 [8];
    undefined1 case_buf_11 [8];
    undefined1 case_buf_16 [8];
    undefined1 case_buf_17 [8];
    undefined1 case_buf_18 [8];
    undefined1 case_buf_19 [8];
    undefined1 case_buf_1a [8];
    undefined1 case_buf_1b [16];

    func_0x830b1ec0(stack_iter);
    stack_iter[0] = 0x8202c418;
    func_0x830b1f98(stack_iter, 0);
    vtable_ptr = (undefined4 *)*self;
    switch (*vtable_ptr) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 0x12:
    case 0x15:
        temp_result = func_0x830b1f28(vtable_ptr + 1);
        temp_result = func_0x830b4918(case_buf_0, temp_result, 0xffffffff8202d980);
        func_0x830b2028(stack_iter, temp_result);
        cleanup_target = case_buf_0;
        break;
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 0xb:
    case 0xc:
    case 0xd:
    case 0xe:
    case 0xf:
        temp_result = func_0x830b1f28(vtable_ptr + 1);
        temp_result = func_0x830b4918(case_buf_4, temp_result, 0xffffffff8200d504);
        func_0x830b2028(stack_iter, temp_result);
        cleanup_target = case_buf_4;
        break;
    case 0x10:
    case 0x13:
        temp_result = func_0x830b1f28(vtable_ptr + 1);
        temp_result = func_0x830b4918(case_buf_10, temp_result, 0xffffffff82010bc0);
        func_0x830b2028(stack_iter, temp_result);
        cleanup_target = case_buf_10;
        break;
    case 0x11:
    case 0x14:
        temp_result = func_0x830b1f28(vtable_ptr + 1);
        temp_result = func_0x830b4918(case_buf_11, temp_result, 0xffffffff82010ba8);
        func_0x830b2028(stack_iter, temp_result);
        cleanup_target = case_buf_11;
        break;
    case 0x16:
        temp_result = func_0x830b1f28(vtable_ptr + 1);
        temp_result = func_0x830b4918(case_buf_16, temp_result, 0xffffffff8202d974);
        func_0x830b2028(stack_iter, temp_result);
        cleanup_target = case_buf_16;
        break;
    case 0x17:
        temp_result = func_0x830b1f28(vtable_ptr + 1);
        temp_result = func_0x830b4918(case_buf_17, temp_result, 0xffffffff8202d968);
        func_0x830b2028(stack_iter, temp_result);
        cleanup_target = case_buf_17;
        break;
    case 0x18:
        temp_result = func_0x830b1f28(vtable_ptr + 1);
        temp_result = func_0x830b4918(case_buf_18, temp_result, 0xffffffff8202d95c);
        func_0x830b2028(stack_iter, temp_result);
        cleanup_target = case_buf_18;
        break;
    case 0x19:
        temp_result = func_0x830b1f28(vtable_ptr + 1);
        temp_result = func_0x830b4918(case_buf_19, temp_result, 0xffffffff8202d94c);
        func_0x830b2028(stack_iter, temp_result);
        cleanup_target = case_buf_19;
        break;
    case 0x1a:
        temp_result = func_0x830b1f28(vtable_ptr + 1);
        temp_result = func_0x830b4918(case_buf_1a, temp_result, 0xffffffff8202d93c);
        func_0x830b2028(stack_iter, temp_result);
        cleanup_target = case_buf_1a;
        break;
    case 0x1b:
        temp_result = func_0x830b1f28(vtable_ptr + 1);
        temp_result = func_0x830b4918(case_buf_1b, temp_result, 0xffffffff8202d930);
        func_0x830b2028(stack_iter, temp_result);
        cleanup_target = case_buf_1b;
        break;
    default:
        goto after_switch;
    }
    func_0x830b1ed8(cleanup_target);
after_switch:
    key = func_0x830b1f80(stack_iter);
    fallback_value = fRam8200d72c;
    if (key != 0) {
        temp_result = func_0x830b1f28(stack_iter);
        func_0x830b1f28(stack_iter);
        base_weight = (double)func_0x830b6ed8();
        scale_factor = (double)func_0x830b72f8(temp_result);
        fallback_value = (float)(base_weight * scale_factor);
    }
    base_weight = (double)fallback_value;
    func_0x830b1ed8(stack_iter);
    return base_weight;
}


// ============================================================================
// Test 6: Looks up a resource entry from a table using parsed input descriptors
// ============================================================================

// --- m2c ---

u32 log_and_lookup(M2C_UNK, M2C_UNK, M2C_UNK);        /* extern */
void *get_descriptor_list();                            /* extern */

u32 test_6(u32 stored_field0) {
    u32 table_entry_data;
    u32 table_entry_data_2;
    u32 table_offset;
    u32 remaining;
    u32 field1;
    u32 lookup_result;
    u32 field2;
    void *descriptor_base;
    void *entry_cursor;
    void *table_cursor;

    descriptor_base = get_descriptor_list();
    table_entry_data = M2C_FIELD(descriptor_base, u32 *, 0x18);
    field2 = 0U;
    entry_cursor = descriptor_base + 0x34;
    field1 = 0U;
    stored_field0 = 0U;
    if (table_entry_data != 0U) {
        remaining = table_entry_data;
        lookup_result = 0x82000000U;
loop_2:
        if ((u16) M2C_FIELD(entry_cursor, u16 *, 0) != 0) {
            lookup_result = log_and_lookup(0x82002AE0, 0x82004700);
        }
        if ((u8) M2C_FIELD(entry_cursor, u8 *, 9) <= 0xAU) {
            return lookup_result;
        }
        lookup_result = log_and_lookup(0x82004840);
        remaining -= 1;
        entry_cursor += 0xC;
        if (remaining == 0U) {
            field2 = stored_field0;
            goto search_table;
        }
        goto loop_2;
    }
search_table:
    table_offset = 0U;
    table_cursor = (void *)0x820043E8;
loop_47:
    if (((u32) M2C_FIELD(table_cursor, u32 *, 0) != field2) || ((u32) M2C_FIELD(table_cursor, u32 *, 4) != 0U) || ((u32) M2C_FIELD(table_cursor, u32 *, 8) != 0U)) {
        table_offset += 0x10;
        table_cursor += 0x10;
        if (table_offset >= 0x110U) {
            goto not_found;
        }
        goto loop_47;
    }
    table_entry_data_2 = M2C_FIELD(table_cursor, u32 *, 0xC);
    if (table_entry_data_2 != 0U) {
        field1 = table_entry_data_2;
    } else {
not_found:
        log_and_lookup(0x82004688, 0, 0);
    }
    return field1;
}

// --- Ghidra ---

/* WARNING: Control flow encountered bad instruction data */

void test_6(void)
{
    int descriptor_list;
    ulonglong loop_counter;
    uint table_offset;
    ulonglong entry_count;
    int *table_cursor;
    int field0;
    int field1;
    short *entry_cursor;
    int stored_field0;

    descriptor_list = func_0x82278b30();
    entry_cursor = (short *)(descriptor_list + 0x34);
    stored_field0 = 0;
    field0 = 0;
    field1 = 0;
    for (entry_count = (ulonglong)*(uint *)(descriptor_list + 0x18); entry_count != 0; entry_count = entry_count - 1) {
        if (*entry_cursor != 0) {
            func_0x8214c430(0xffffffff82002ae0, 0xffffffff82004700);
        }
        switch (*(undefined1 *)((int)entry_cursor + 9)) {
        case 0:
            if (*(char *)(entry_cursor + 5) != '\0') {
                func_0x8214c430(0xffffffff82002ae0, 0xffffffff8200471c);
            }
            stored_field0 = *(int *)(entry_cursor + 2);
            break;
        case 1:
            if (*(char *)(entry_cursor + 5) != '\0') {
                func_0x8214c430(0xffffffff82002ae0, 0xffffffff8200471c);
            }
            field0 = *(int *)(entry_cursor + 2);
            break;
        case 2:
            if (*(char *)(entry_cursor + 5) != '\0') {
                func_0x8214c430(0xffffffff82002ae0, 0xffffffff8200471c);
            }
            field1 = *(int *)(entry_cursor + 2);
            break;
        case 3:
            if (*(int *)(entry_cursor + 2) != 0x2a23b9) {
                func_0x8214c430(0xffffffff82002ae0, 0xffffffff8200476c);
            }
            if (*(char *)(entry_cursor + 5) != '\0') {
                func_0x8214c430(0xffffffff82002ae0, 0xffffffff8200471c);
            }
            break;
        case 4:
            if (*(int *)(entry_cursor + 2) != 0x2c83a4) {
                func_0x8214c430(0xffffffff82002ae0, 0xffffffff82004798);
            }
            if (*(char *)(entry_cursor + 5) != '\0') {
                func_0x8214c430(0xffffffff82002ae0, 0xffffffff8200471c);
            }
            break;
        case 5:
            loop_counter = (ulonglong)*(uint *)(entry_cursor + 2);
            if ((((loop_counter != 0x1a23a6) && (loop_counter != 0x2a23b9)) && (loop_counter - 0x2c23a5 != 0)) &&
               ((loop_counter - 0x2c23a5 & 0xffffffff) != 0x5fff)) {
                func_0x8214c430(0xffffffff82004830);
            }
            break;
        default:
            func_0x8214c430(0xffffffff82004840);
            break;
        case 9:
            func_0x8214c430(0xffffffff8200473c);
            break;
        case 10:
            if (*(int *)(entry_cursor + 2) != 0x182886) {
                func_0x8214c430(0xffffffff82002ae0, 0xffffffff820047c4);
            }
            if (1 < *(byte *)(entry_cursor + 5)) {
                func_0x8214c430(0xffffffff82002ae0, 0xffffffff820047f0);
            }
        }
        entry_cursor = entry_cursor + 6;
    }
    table_offset = 0;
    table_cursor = (int *)0x820043e8;
    while (((*table_cursor != stored_field0 || (table_cursor[1] != field1)) || (table_cursor[2] != field0))) {
        table_offset = table_offset + 0x10;
        table_cursor = table_cursor + 4;
        if (0x10f < table_offset) {
not_found:
            func_0x8214c430(0xffffffff82004688, stored_field0, field1, field0);
            /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
        }
    }
    if (table_cursor[3] != 0) {
        halt_baddata();
    }
    goto not_found;
}


// ============================================================================
// Test 7: Dispatches a command on an object based on its type nibble
// ============================================================================

// --- m2c ---

s32 get_render_mode();                                  /* extern */
M2C_UNK log_assert(M2C_UNK);                           /* extern */
M2C_UNK finalize_command(s32 *);                        /* extern */

void test_7(s32 *self) {
    if (!(*self & 0x100000)) {
        log_assert(0x82008D40);
    }
    if (get_render_mode() == 2) {

    }
    if ((void *) ((*self & 0xF) - 1) <= 0xBU) {
        return;
    }
    *self = 0xF;
    finalize_command(self);
}

// --- Ghidra ---

void test_7(uint *self)
{
    int *render_target;
    int render_mode;
    uint flags;
    undefined8 dispatch_param;

    if ((*self & 0x100000) == 0) {
        func_0x8214c430(0xffffffff82008d40);
    }
    render_mode = func_0x82141160();
    render_target = piRam82710644;
    if (render_mode == 2) {
        render_target = piRam82710640;
    }
    render_mode = *render_target;
    flags = *self;
    switch (flags & 0xf) {
    case 1:
        if ((self[2] != 0) && (render_mode != 0)) {
            func_0x82161cd0(render_mode, 0);
            func_0x82158ea0(render_mode, self[2], 9, self, 0);
        }
        flags = self[6] & 0xfffffffc;
        goto apply_value;
    case 2:
        if ((self[2] != 0) && (render_mode != 0)) {
            func_0x82161cd0(render_mode, 0);
            dispatch_param = 0xb;
dispatch_shared:
            func_0x82158ea0(render_mode, self[2], dispatch_param, self, 0);
        }
        goto use_field6;
    case 3:
        if ((self[2] != 0) && (render_mode != 0)) {
            func_0x82161cd0(render_mode, 0);
            func_0x82158ea0(render_mode, self[2], 0xd, self, 0);
        }
        func_0x8214df40(self, 1, 1);
        flags = self[0xc] & 0xfffff000;
        func_0x8214e210(self[8] & 0xfffff000, 3);
        goto apply_value;
    case 4:
        if ((flags & 0x40000000) == 0) {
            if ((flags & 0x80000000) != 0) {
                func_0x8213abd0(self[7] & 0xfff, (ulonglong)self[0xb] / 0x1400);
            }
            if ((self[8] & 1) != 0) {
                uRam826fe644 = 0;
            }
        }
        break;
    case 6:
        if ((self[2] != 0) && (render_mode != 0)) {
            func_0x82161cd0(render_mode, 0);
            func_0x82158ea0(render_mode, self[2], 7, self, 0);
        }
        flags = self[8];
        goto apply_value;
    case 7:
        if ((self[2] != 0) && (render_mode != 0)) {
            func_0x82161cd0(render_mode, 0);
            dispatch_param = 8;
            goto dispatch_shared;
        }
        goto use_field6;
    case 8:
        if ((self[2] != 0) && (render_mode != 0)) {
            func_0x82161cd0(render_mode, 0);
            dispatch_param = 0x11;
            goto dispatch_shared;
        }
use_field6:
        flags = self[6];
apply_value:
        func_0x8214e210(flags, 3);
        break;
    case 9:
        if ((self[2] != 0) && (render_mode != 0)) {
            func_0x82161cd0(render_mode, 0);
            func_0x82158ea0(render_mode, self[2], 0xf, self, 0);
        }
        func_0x82134c50(self);
        break;
    case 10:
        if ((self[2] != 0) && (render_mode != 0)) {
            func_0x82161cd0(render_mode, 0);
            func_0x82158ea0(render_mode, self[2], 0x15, self, 0);
        }
        func_0x82159280(self);
        break;
    case 0xb:
        if ((self[2] != 0) && (render_mode != 0)) {
            func_0x82161cd0(render_mode, 0);
            func_0x82158ea0(render_mode, self[2], 0x17, self, 0);
        }
        func_0x82148ba0(self);
        break;
    case 0xc:
        if ((self[2] != 0) && (render_mode != 0)) {
            func_0x82161cd0(render_mode, 0);
            func_0x82158ea0(render_mode, self[2], 0x19, self, 0);
        }
        func_0x821394d0(self);
    }
    *self = 0xf;
    func_0x821553e0(self);
    return;
}


// ============================================================================
// Test 8: State machine update with switch on current state index
// ============================================================================

// --- m2c ---

void *get_state_context();                              /* extern */

void test_8(void) {
    if ((void *) M2C_FIELD(get_state_context(), void **, 0x54) <= 0xBU) {

    }
}

// --- Ghidra ---

/* WARNING: Control flow encountered bad instruction data */

void test_8(void)
{
    int context;
    int *query_result;
    int sub_context;
    undefined4 *symbol_result;
    char status;
    ulonglong next_state;
    ulonglong next_state_2;
    double elapsed_delta;
    double threshold;
    undefined1 symbol_buf_2 [4];
    undefined1 symbol_buf_3a [4];
    undefined1 symbol_buf_3b [4];
    undefined1 symbol_buf_6 [4];
    undefined1 param_buf [4];
    undefined4 symbol_value;
    undefined1 symbol_buf_7 [4];
    undefined1 anim_buf [4];
    undefined4 vtable_result_2;
    uint vtable_flags_2;
    undefined4 vtable_result_3;
    uint vtable_flags_3;
    undefined4 vtable_result_7;
    uint vtable_flags_7;

    context = func_0x82624b1c();
    next_state_2 = 0xffffffffffffffff;
    switch (*(undefined4 *)(context + 0x54)) {
    case 0:
        status = func_0x82254db8(uRam82a41fcc);
        if (status == '\0') {
            halt_baddata();
        }
        status = func_0x82252590(uRam82a41fcc);
        goto check_status;
    case 1:
        status = func_0x8236f4f8(*(undefined4 *)(context + 0x4c));
check_status:
        if (status != '\0') {
            halt_baddata();
        }
        next_state_2 = 3;
        break;
    case 2:
        status = func_0x8236f4f8(*(undefined4 *)(context + 0x4c));
        if (status != '\0') {
            halt_baddata();
        }
        func_0x82317638(context, 0xffffffffffffffff);
        symbol_result = (undefined4 *)func_0x82512998(symbol_buf_2, 0xffffffff82047a90);
        func_0x821d3c98(param_buf, *symbol_result);
        sub_context = *(int *)(*(int *)(context + 4) + 4) + context;
        (**(code **)(*(int *)(sub_context + 4) + 0x18))(&vtable_result_2, sub_context + 4, symbol_value, 1);
        if ((vtable_flags_2 & 0x10) != 0) {
            func_0x821d0348(vtable_result_2);
        }
        *(undefined1 *)(context + 0x120) = 1;
        goto cleanup_and_halt;
    case 3:
        status = func_0x8236f4f8(*(undefined4 *)(context + 0x4c));
        if (status != '\0') {
            halt_baddata();
        }
        query_result = (int *)func_0x82315b08(symbol_buf_3a, *(undefined4 *)(context + 0x100));
        if (*query_result == iRam829feaa8) {
            query_result = (int *)func_0x82315a00(symbol_buf_3b, *(undefined4 *)(context + 0x100));
            if (*query_result == iRam829feaa8) {
                halt_baddata();
            }
            next_state_2 = 4;
        }
        else {
            symbol_result = (undefined4 *)func_0x82315b08(symbol_buf_6);
            next_state_2 = 0xb;
            *(undefined4 *)(context + 0x74) = *symbol_result;
        }
        break;
    default:
        goto final_halt;
    case 5:
        status = func_0x82315e20(*(undefined4 *)(context + 0x104));
        if (status != '\0') {
            elapsed_delta = (double)(*(float *)(context + 0x5c) - *(float *)(context + 0x108));
            threshold = (double)func_0x82315c10(*(undefined4 *)(context + 0x100));
            if (elapsed_delta <= threshold) {
                func_0x82252dd8(uRam82a41fcc, 0);
                sub_context = func_0x822848b8();
                if (sub_context < 100) {
                    halt_baddata();
                }
            }
        }
        status = func_0x82315f28(*(undefined4 *)(context + 0x104));
        if (status == '\0') {
            next_state_2 = 7;
        }
        else {
            if (*(float *)(context + 0x5c) < *(float *)(context + 0x10c)) {
                *(float *)(context + 0x10c) = *(float *)(context + 0x5c);
            }
            elapsed_delta = (double)(*(float *)(context + 0x5c) - *(float *)(context + 0x10c));
            threshold = (double)func_0x82315d18(*(undefined4 *)(context + 0x100));
            if (elapsed_delta < threshold) {
                halt_baddata();
            }
            next_state_2 = 6;
        }
        break;
    case 6:
        status = func_0x8236f4f8(*(undefined4 *)(context + 0x4c));
        if (status != '\0') {
            halt_baddata();
        }
        symbol_result = (undefined4 *)func_0x82512998(symbol_buf_7, 0xffffffff82047a7c);
        func_0x821d3c98(param_buf, *symbol_result);
        context = *(int *)(*(int *)(context + 4) + 4) + context;
        (**(code **)(*(int *)(context + 4) + 0x18))(&vtable_result_3, context + 4, symbol_value, 1);
        if ((vtable_flags_3 & 0x10) != 0) {
            func_0x821d0348(vtable_result_3);
        }
cleanup_and_halt:
        func_0x821d0348(symbol_value);
        halt_baddata();
    case 7:
        status = func_0x8236f4f8(*(undefined4 *)(context + 0x4c));
        if (status != '\0') {
            halt_baddata();
        }
        if ((uRam82a458ec & 1) == 0) {
            uRam82a458ec = uRam82a458ec | 1;
            symbol_result = (undefined4 *)func_0x82512998(anim_buf, 0xffffffff82047a68);
            func_0x821d3c98(0xffffffff82a458e4, *symbol_result);
            func_0x82625588(0xffffffff829d0eb8);
        }
        sub_context = *(int *)(*(int *)(context + 4) + 4) + context;
        (**(code **)(*(int *)(sub_context + 4) + 0x18))(&vtable_result_7, sub_context + 4, uRam82a458e8, 1);
        if ((vtable_flags_7 & 0x10) != 0) {
            func_0x821d0348(vtable_result_7);
        }
        next_state_2 = 0xc;
        break;
    case 9:
        status = func_0x823156d0(context);
        goto check_completion;
    case 10:
        status = func_0x823157e8(context);
check_completion:
        if (status == '\0') {
            halt_baddata();
        }
        next_state_2 = (ulonglong)*(uint *)(context + 0x58);
check_valid_state:
        if ((int)next_state_2 == -1) {
            halt_baddata();
        }
        break;
    case 0xb:
        func_0x82316100(context);
        goto check_valid_state;
    }
    next_state = (ulonglong)*(uint *)(context + 0x58);
    if (*(uint *)(context + 0x58) == 0xffffffff) {
        next_state = next_state_2;
    }
    func_0x82317638(context, next_state);
final_halt:
    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
}


// ============================================================================
// Test 9: Constructs a result object from a type enum and optional source data
// ============================================================================

// --- m2c ---

s32 *resolve_source(s32, s32 *);                        /* extern */
M2C_UNK make_symbol(s32 *, M2C_UNK);                   /* extern */

s32 *test_9(s32 *result, u32 type_enum, void *source_data) {
    s32 sym_default;
    s32 sym_null_source;
    s32 sym_case2;
    s32 sym_case3;
    s32 sym_case4;
    s32 sym_case5;
    s32 sym_case6;
    s32 *source_vtable;
    s32 *resolved;
    s32 *source_ptr;
    s32 resolved_value;

    *result = *(s32 *)0x829FEAA8;
    if (type_enum >= 1U) {
        if (type_enum != 1U) {
            switch (type_enum) {                        /* irregular */
            case 6:
                make_symbol(&sym_case6, 0x8204E6F4);
                resolved_value = sym_case6;
                goto assign_result;
            case 5:
                make_symbol(&sym_case5, 0x8204E6C8);
                resolved_value = sym_case5;
                goto assign_result;
            case 4:
                make_symbol(&sym_case4, 0x8204E6A8);
                resolved_value = sym_case4;
                goto assign_result;
            case 3:
                make_symbol(&sym_case3, 0x8204E68C);
                resolved_value = sym_case3;
                goto assign_result;
            default:
                make_symbol(&sym_case2, 0x8204E670);
                resolved_value = sym_case2;
                goto assign_result;
            }
            /* Duplicate return node #33. Try simplifying control flow for better match */
            return result;
        }
        if (source_data == NULL) {
            make_symbol(&sym_null_source, 0x8204E650);
            resolved_value = sym_null_source;
            goto assign_result;
        }
        source_ptr = M2C_FIELD(source_data, s32 **, 4);
        resolved = resolve_source(*source_ptr + 0x10, source_ptr);
        if ((void *) (resolved - 1) <= 9U) {
            return resolved;
        }
        source_vtable = M2C_FIELD(source_data, s32 **, 4);
        resolve_source(*source_vtable + 0x10, source_vtable);
        /* Duplicate return node #33. Try simplifying control flow for better match */
        return result;
    }
    make_symbol(&sym_default, 0x8204E55C);
    resolved_value = sym_default;
assign_result:
    *result = resolved_value;
    return result;
}

// --- Ghidra ---

undefined4 *test_9(undefined4 *result, undefined8 unused, uint type_enum, int source_data)
{
    uint *source_vtable;
    int resolve_result;
    undefined4 *symbol_result;
    undefined8 vtable_call_result;
    longlong vtable_offset;
    undefined4 sym_case6;
    undefined4 sym_case5;
    undefined4 sym_case4;
    undefined4 sym_case3;
    undefined4 sym_case2;
    undefined4 sym_null_source;
    undefined4 sym_source_found;
    undefined4 sym_source_default;
    undefined4 sym_result_3;
    undefined4 sym_result_3b;
    undefined4 sym_result_0;
    undefined4 sym_result_2;
    undefined4 sym_result_4;
    undefined4 sym_default;
    undefined1 sym_extra_buf [16];

    *result = uRam829feaa8;
    if (type_enum == 0) {
        func_0x82512998(&sym_default, 0xffffffff8204e55c);
        sym_case6 = sym_default;
    }
    else if (type_enum == 1) {
        if (source_data == 0) {
            func_0x82512998(&sym_null_source, 0xffffffff8204e650);
            sym_case6 = sym_null_source;
        }
        else {
            resolve_result = func_0x823a52f8((ulonglong)**(uint **)(source_data + 4) + 0x10);
            switch (resolve_result + -1) {
            case 0:
            case 1:
            case 4:
            case 5:
            case 7:
                func_0x823a52f8((ulonglong)**(uint **)(source_data + 4) + 0x10, *(uint **)(source_data + 4));
                func_0x82512998(&sym_source_found, 0xffffffff8204e650);
                sym_case6 = sym_source_found;
                break;
            case 2:
                func_0x82512998(&sym_source_default, 0xffffffff8204e634);
                sym_case6 = sym_source_default;
                break;
            case 3:
                func_0x82512998(&sym_result_3, 0xffffffff8204e618);
                sym_case6 = sym_result_3;
                break;
            default:
                source_vtable = *(uint **)(source_data + 4);
                vtable_offset = (ulonglong)*source_vtable + 0x10;
fallthrough_return:
                func_0x823a52f8(vtable_offset, source_vtable);
                return result;
            case 9:
                resolve_result = func_0x823a52f8((ulonglong)**(uint **)(source_data + 4) + 0x18);
                if ((resolve_result == 0) || (resolve_result == 2)) {
                    func_0x82512998(&sym_result_0, 0xffffffff8204e578);
                    sym_case6 = sym_result_0;
                }
                else if (resolve_result == 3) {
                    func_0x82512998(&sym_result_3b, 0xffffffff8204e59c);
                    sym_case6 = sym_result_3b;
                }
                else {
                    if (resolve_result != 4) {
                        source_vtable = *(uint **)(source_data + 4);
                        vtable_offset = (ulonglong)*source_vtable + 0x18;
                        goto fallthrough_return;
                    }
                    symbol_result = (undefined4 *)func_0x82512998(sym_extra_buf, 0xffffffff8201e3f0);
                    vtable_call_result = func_0x823b6540(*(int *)(*piRam82a42830 + 4) + (int)piRam82a42830, *symbol_result, 1);
                    resolve_result = func_0x823a52f8(vtable_call_result, 0);
                    if (resolve_result == 0) {
                        func_0x82512998(&sym_result_2, 0xffffffff8204e5c0);
                        sym_case6 = sym_result_2;
                    }
                    else {
                        func_0x82512998(&sym_result_4, 0xffffffff8204e5ec);
                        sym_case6 = sym_result_4;
                    }
                }
            }
        }
    }
    else if (type_enum < 3) {
        func_0x82512998(&sym_case2, 0xffffffff8204e670);
        sym_case6 = sym_case2;
    }
    else if (type_enum == 3) {
        func_0x82512998(&sym_case3, 0xffffffff8204e68c);
        sym_case6 = sym_case3;
    }
    else if (type_enum < 5) {
        func_0x82512998(&sym_case4, 0xffffffff8204e6a8);
        sym_case6 = sym_case4;
    }
    else if (type_enum == 5) {
        func_0x82512998(&sym_case5, 0xffffffff8204e6c8);
        sym_case6 = sym_case5;
    }
    else {
        if (6 < type_enum) {
            return result;
        }
        func_0x82512998(&sym_case6, 0xffffffff8204e6f4);
    }
    *result = sym_case6;
    return result;
}

// ============================================================================
// Test 10: Switch dispatch with string construction fallback
// ============================================================================

// --- m2c ---

M2C_UNK func_82515370(M2C_UNK *);                   /* extern */
M2C_UNK func_825156D8(M2C_UNK *, M2C_UNK);          /* extern */

void test_10(void *self) {
    M2C_UNK str_buf;

    if ((void *) M2C_FIELD(self, void **, 4) <= 0x14U) {
        return;
    }
    func_825156D8(&str_buf, 0x820C14E8);
    func_82515370(&str_buf);
}

// --- Ghidra ---

ulonglong test_10(int self)

{
    undefined4 *format_result;
    char has_value;
    int accessor_result;
    uint *data_ptr;
    ulonglong result;
    undefined8 str_arg;
    undefined1 scratch_buf_small[4];
    undefined1 scratch_buf_mid[12];
    undefined1 str_buf[2080];

    switch(*(undefined4 *)(self + 4)) {
    case 0:
        str_arg = func_0x823a52f8(self, 0);
        result = func_0x823f7120(0xffffffff82071004, str_arg);
        break;
    case 1:
        func_0x823a53f8(self, 0);
        result = func_0x823ca218(0xffffffff820c151c);
        break;
    case 2:
        func_0x823a4d30(self, 0);
        result = func_0x823a5578();
        goto format_and_return;
    case 3:
        str_arg = func_0x823a4d30(self, 0);
        format_result = (undefined4 *)func_0x823c0100(scratch_buf_mid, str_arg);
        result = func_0x823f7120(0xffffffff8200fe44, *format_result);
        break;
    case 4:
        has_value = func_0x823a54b0(self);
        if (has_value == '\0') {
            str_arg = 0xffffffff82067da0;
            goto build_string;
        }
        accessor_result = func_0x823a5440(self, 0);
        result = (ulonglong)*(uint *)(accessor_result + 0x18);
format_and_return:
        result = func_0x823f7120(0xffffffff8200fe44, result);
        break;
    case 5:
        data_ptr = (uint *)func_0x823a5320(scratch_buf_small, self, 0);
        result = (ulonglong)*data_ptr;
        break;
    default:
        str_arg = 0xffffffff820c14e8;
        goto build_string;
    case 0x10:
        str_arg = 0xffffffff820c1514;
        goto build_string;
    case 0x11:
        str_arg = 0xffffffff820c1508;
        goto build_string;
    case 0x12:
        result = func_0x823a53b8(self, 0);
        break;
    case 0x13:
        str_arg = 0xffffffff820c14fc;
        goto build_string;
    case 0x14:
        str_arg = 0xffffffff820c14f4;
build_string:
        func_0x825156d8(str_buf, str_arg);
        result = func_0x82515370(str_buf);
    }
    return result;
}


// ============================================================================
// Test 11: Streaming data decoder / inflate state machine
// ============================================================================

// --- m2c ---

void *func_8248726C();                              /* extern */

void *test_11(void) {
    u32 *state_header;
    void *stream;
    void *result;

    result = func_8248726C();
    stream = result;
    if (stream != NULL) {
        state_header = M2C_FIELD(stream, u32 **, 0x1C);
        if ((state_header != NULL) && ((u32) M2C_FIELD(stream, u32 *, 0) != 0U)) {
            if ((s32) (u32) (u64) result != 4) {

            }
            if ((u32) *state_header <= 0xDU) {
                return stream;
            }
            goto error;
        }
    }
error:
    return (void *)-2U;
}

// --- Ghidra ---

void test_11(undefined8 unused, int flush_mode)

{
    byte input_byte;
    uint decoded_value;
    undefined4 *state;
    int *stream;
    ulonglong accum;
    undefined8 window_bits;
    undefined8 status;

    stream = (int *)func_0x8248726c();
    if (((stream == (int *)0x0) || ((uint *)stream[7] == (uint *)0x0)) || (*stream == 0)) {
        halt_baddata();
    }
    window_bits = 0xfffffffffffffffb;
    if (flush_mode != 4) {
        window_bits = 0;
    }
    decoded_value = *(uint *)stream[7];
    status = 0xfffffffffffffffb;
joined_r0x8222c188:
    if (0xd < decoded_value) {
        halt_baddata();
    }
    switch(*(ushort *)(&UNK_82020ec8 + decoded_value * 2) + 0x8222c1e0) {
    case 0x8222c1e0:
        if (stream[1] == 0) {
            halt_baddata();
        }
        stream[1] = stream[1] + -1;
        stream[2] = stream[2] + 1;
        *(uint *)(stream[7] + 4) = (uint)*(byte *)*stream;
        state = (undefined4 *)stream[7];
        decoded_value = state[1];
        *stream = *stream + 1;
        if ((decoded_value & 0xf) == 8) {
            if (((uint)state[1] >> 4) + 8 <= (uint)state[4]) {
                *state = 1;
                goto state_header_decode;
            }
            *state = 0xd;
            stream[6] = -0x7dfdf0f0;
        }
        else {
            *state = 0xd;
            stream[6] = -0x7dfdf10c;
        }
        goto set_error_substate;
    case 0x8222c26c:
state_header_decode:
        if (stream[1] == 0) {
            halt_baddata();
        }
        state = (undefined4 *)stream[7];
        stream[1] = stream[1] + -1;
        stream[2] = stream[2] + 1;
        input_byte = *(byte *)*stream;
        *stream = (int)((byte *)*stream + 1);
        accum = ((ulonglong)(uint)state[1] & 0xffffff) * 0x100 + (ulonglong)input_byte;
        if (accum != ((accum & 0xffffffff) / 0x1f) * 0x1f) {
            *state = 0xd;
            stream[6] = -0x7dfdf0dc;
            goto set_error_substate;
        }
        if ((input_byte & 0x20) != 0) {
            *(undefined4 *)stream[7] = 2;
            goto state_dict_id;
        }
        *state = 7;
        status = window_bits;
        break;
    case 0x8222c2e4:
        status = func_0x8222dae0(*(undefined4 *)(stream[7] + 0x14), stream, status);
        if ((int)status == -3) {
            *(undefined4 *)stream[7] = 0xd;
            *(undefined4 *)(stream[7] + 4) = 0;
        }
        else {
            if ((int)status == 0) {
                status = window_bits;
            }
            if ((int)status != 1) {
                halt_baddata();
            }
            func_0x8222d930(*(undefined4 *)(stream[7] + 0x14), stream, stream[7] + 4);
            state = (undefined4 *)stream[7];
            if (state[3] == 0) {
                *state = 8;
                goto state_read_checksum_byte0;
            }
            *state = 0xc;
            status = window_bits;
        }
        break;
    case 0x8222c364:
state_read_checksum_byte0:
        if (stream[1] == 0) {
            halt_baddata();
        }
        stream[1] = stream[1] + -1;
        stream[2] = stream[2] + 1;
        *(uint *)(stream[7] + 8) = (uint)*(byte *)*stream << 0x18;
        *stream = *stream + 1;
        *(undefined4 *)stream[7] = 9;
    case 0x8222c3b4:
        if (stream[1] == 0) {
            halt_baddata();
        }
        stream[1] = stream[1] + -1;
        stream[2] = stream[2] + 1;
        *(uint *)(stream[7] + 8) = (uint)*(byte *)*stream * 0x10000 + *(int *)(stream[7] + 8);
        *stream = *stream + 1;
        *(undefined4 *)stream[7] = 10;
    case 0x8222c40c:
        goto state_read_checksum_byte2;
    case 0x8222c464:
        goto state_read_checksum_byte3;
    case 0x8222c500:
state_dict_id:
        if (stream[1] == 0) {
            halt_baddata();
        }
        stream[1] = stream[1] + -1;
        stream[2] = stream[2] + 1;
        *(uint *)(stream[7] + 8) = (uint)*(byte *)*stream << 0x18;
        *stream = *stream + 1;
        *(undefined4 *)stream[7] = 3;
    case 0x8222c550:
        if (stream[1] == 0) {
            halt_baddata();
        }
        stream[1] = stream[1] + -1;
        stream[2] = stream[2] + 1;
        *(uint *)(stream[7] + 8) = (uint)*(byte *)*stream * 0x10000 + *(int *)(stream[7] + 8);
        *stream = *stream + 1;
        *(undefined4 *)stream[7] = 4;
    case 0x8222c5a8:
        goto state_read_dict_byte2;
    case 0x8222c5fc:
        goto state_read_dict_byte3;
    case 0x8222c65c:
        *(undefined4 *)stream[7] = 0xd;
        stream[6] = -0x7dfdf11c;
        *(undefined4 *)(stream[7] + 4) = 0;
        halt_baddata();
    case 0x8222c684:
        goto LAB_824872bc;
    case 0x8222c68c:
        halt_baddata();
    }
next_state:
    decoded_value = *(uint *)stream[7];
    goto joined_r0x8222c188;
state_read_checksum_byte2:
    if (stream[1] == 0) {
        halt_baddata();
    }
    stream[1] = stream[1] + -1;
    stream[2] = stream[2] + 1;
    *(uint *)(stream[7] + 8) = (uint)*(byte *)*stream * 0x100 + *(int *)(stream[7] + 8);
    *stream = *stream + 1;
    *(undefined4 *)stream[7] = 0xb;
state_read_checksum_byte3:
    if (stream[1] == 0) {
        halt_baddata();
    }
    stream[1] = stream[1] + -1;
    stream[2] = stream[2] + 1;
    *(uint *)(stream[7] + 8) = (uint)*(byte *)*stream + *(int *)(stream[7] + 8);
    state = (undefined4 *)stream[7];
    *stream = *stream + 1;
    if (state[1] == state[2]) {
        *(undefined4 *)stream[7] = 0xc;
LAB_824872bc:
        halt_baddata();
    }
    *state = 0xd;
    stream[6] = -0x7dfdf0c4;
set_error_substate:
    *(undefined4 *)(stream[7] + 4) = 5;
    status = window_bits;
    goto next_state;
state_read_dict_byte2:
    if (stream[1] == 0) {
        halt_baddata();
    }
    stream[1] = stream[1] + -1;
    stream[2] = stream[2] + 1;
    *(uint *)(stream[7] + 8) = (uint)*(byte *)*stream * 0x100 + *(int *)(stream[7] + 8);
    *stream = *stream + 1;
    *(undefined4 *)stream[7] = 5;
state_read_dict_byte3:
    if (stream[1] != 0) {
        stream[1] = stream[1] + -1;
        stream[2] = stream[2] + 1;
        *(uint *)(stream[7] + 8) = (uint)*(byte *)*stream + *(int *)(stream[7] + 8);
        *stream = *stream + 1;
        stream[0xc] = ((undefined4 *)stream[7])[2];
        *(undefined4 *)stream[7] = 6;
        halt_baddata();
    }
    halt_baddata();
}


// ============================================================================
// Test 12: Stack-based VM opcode dispatch with linked-list operand pool
// ============================================================================

// --- m2c ---

M2C_UNK func_822A7180(void *, void *, M2C_UNK, M2C_UNK); /* extern */
u32 func_822CD240(M2C_UNK, M2C_UNK);                /* extern */
void *func_822CD3A0(M2C_UNK, void *, M2C_UNK);      /* extern */
void *func_82487284();                              /* extern */
M2C_UNK func_82487ED0(s32 *, M2C_UNK, s32);         /* extern */

void test_12(s32 operand_stack) {
    M2C_UNK error_msg;
    s32 *operand_ptr;
    s32 loop_counter;
    u32 num_operands;
    void *free_node;
    void *vm_context;
    void *result;
    void *new_node;

    result = func_82487284();
    num_operands = M2C_ERROR(/* Read from unset register $r5 */);
    vm_context = result;
    if (num_operands > 0x10U) {
        M2C_FIELD(vm_context, s32 *, 0x44) = 1;
    }
    if ((s32) M2C_FIELD(vm_context, s32 *, 0x44) == 0) {
        func_82487ED0(&(&operand_stack)[num_operands], 0, (0x10 - num_operands) * 4);
        loop_counter = num_operands - 1;
        if (loop_counter >= 0) {
            operand_ptr = &(&operand_stack)[loop_counter];
pop_loop:
            free_node = M2C_FIELD(vm_context, void **, 0x5C);
            if (free_node != NULL) {
                loop_counter -= 1;
                M2C_FIELD(vm_context, void **, 0x5C) = (void *) M2C_FIELD(free_node, void **, 0xC);
                *operand_ptr = M2C_FIELD(free_node, s32 *, 8);
                operand_ptr -= 4;
                M2C_FIELD(free_node, s32 *, 8) = 0;
                M2C_FIELD(free_node, void **, 0xC) = (void *) M2C_FIELD(vm_context, void **, 0x60);
                M2C_FIELD(vm_context, void **, 0x60) = free_node;
                if (loop_counter < 0) {
                    goto dispatch;
                }
                goto pop_loop;
            }
            error_msg = 0x8202C0F4;
            goto report_error;
        }
dispatch:
        if ((u32) (u64) result <= 0x2EU) {
            return;
        }
        if ((s32) M2C_FIELD(vm_context, s32 *, 0x44) == 0) {
            new_node = M2C_FIELD(vm_context, void **, 0x60);
            if (new_node != NULL) {
                M2C_FIELD(vm_context, void **, 0x60) = (void *) M2C_FIELD(new_node, void **, 0xC);
                M2C_FIELD(new_node, s32 *, 8) = 0;
                M2C_FIELD(new_node, void **, 0xC) = (void *) M2C_FIELD(vm_context, void **, 0x5C);
                goto push_node;
            }
            if (func_822CD240(0x14, 0x10) != 0U) {
                new_node = func_822CD3A0(0, M2C_FIELD(vm_context, void **, 0x5C), 0x8202C0C0);
            } else {
                new_node = NULL;
            }
            if (new_node == NULL) {
                error_msg = 0x8202C0A0;
report_error:
                func_822A7180(vm_context + 0x18, vm_context + 0x278, 0, error_msg);
                M2C_FIELD(vm_context, s32 *, 0x44) = 1;
            } else {
push_node:
                M2C_FIELD(vm_context, void **, 0x5C) = new_node;
            }
        }
    }
}

// --- Ghidra ---

void test_12(undefined8 unused, undefined4 opcode, ulonglong num_operands)

{
    int vm_context;
    undefined4 node_value;
    int push_value;
    ulonglong alloc_result;
    int free_node;
    undefined8 error_msg;
    longlong operand_ptr;
    uint operand_result;
    bool cmp_result;
    int operand_0;
    int operand_1;
    int operand_2;

    vm_context = func_0x82487284();
    push_value = 0;
    if (0x10 < (num_operands & 0xffffffff)) {
        *(undefined4 *)(vm_context + 0x44) = 1;
    }
    if (*(int *)(vm_context + 0x44) != 0) {
        halt_baddata();
    }
    func_0x82487ed0((num_operands & 0x3fffffff) * 4 + (ZEXT48(&stack0x00000000) - 0x70), 0,
                    (0x10 - num_operands & 0x3fffffff) << 2);
    num_operands = num_operands - 1;
    if (-1 < (longlong)num_operands) {
        operand_ptr = (num_operands & 0x3fffffff) * 4 + (ZEXT48(&stack0x00000000) - 0x70);
        do {
            free_node = *(int *)(vm_context + 0x5c);
            if (free_node == 0) {
                error_msg = 0xffffffff8202c0f4;
                goto report_error;
            }
            num_operands = num_operands - 1;
            node_value = *(undefined4 *)(free_node + 8);
            *(undefined4 *)(vm_context + 0x5c) = *(undefined4 *)(free_node + 0xc);
            *(undefined4 *)operand_ptr = node_value;
            operand_ptr = operand_ptr + -4;
            *(undefined4 *)(free_node + 8) = 0;
            *(undefined4 *)(free_node + 0xc) = *(undefined4 *)(vm_context + 0x60);
            *(int *)(vm_context + 0x60) = free_node;
        } while (-1 < (longlong)num_operands);
    }
    switch(opcode) {
    case 0:
        func_0x8229eae0(vm_context, *(undefined4 *)(operand_0 + 0x18), 1);
        break;
    case 1:
        func_0x8229dcc8(vm_context, *(undefined4 *)(operand_0 + 0x18));
        break;
    case 2:
        *(undefined4 *)(*(int *)(vm_context + 0x26c) + 0x1c) = *(undefined4 *)(operand_0 + 0x18);
        if (*(int *)(vm_context + 0x278) != 0xc) {
            *(int *)(*(int *)(vm_context + 0x26c) + 0x1c) = *(int *)(*(int *)(vm_context + 0x26c) + 0x1c) + -1;
        }
        break;
    case 3:
        free_node = *(int *)(operand_1 + 0x18);
        *(undefined4 *)(*(int *)(vm_context + 0x26c) + 0x1c) = *(undefined4 *)(operand_0 + 0x18);
        if (*(int *)(vm_context + 0x278) != 0xc) {
            *(int *)(*(int *)(vm_context + 0x26c) + 0x1c) = *(int *)(*(int *)(vm_context + 0x26c) + 0x1c) + -1;
        }
        if (free_node != 0) {
            *(int *)(*(int *)(vm_context + 0x26c) + 0x18) = free_node;
        }
        break;
    case 4:
        func_0x8229f4d0(vm_context);
        break;
    case 5:
        func_0x8229c678(vm_context);
        break;
    case 6:
        alloc_result = (ulonglong)*(uint *)(operand_0 + 0x18);
        goto dispatch_value;
    case 7:
        alloc_result = func_0x8229cf28(vm_context, *(undefined4 *)(operand_0 + 0x18), 0, 0);
        goto dispatch_value;
    case 8:
        node_value = func_0x8229cf28(vm_context, *(undefined4 *)(operand_0 + 0x18), 0, 0);
        alloc_result = (ulonglong)(LZCOUNT(node_value) << 0x20) >> 0x25;
dispatch_value:
        func_0x8229dd78(vm_context, alloc_result);
        break;
    case 9:
        func_0x8229c7e0(vm_context, *(undefined4 *)(operand_0 + 0x18));
        break;
    case 10:
        func_0x8229c8a0(vm_context);
        break;
    case 0xb:
        func_0x8229de30(vm_context);
        break;
    case 0xc:
        func_0x8229dd78(vm_context, 1);
        goto clear_display;
    case 0xd:
        func_0x8229c7e0(vm_context, 1);
clear_display:
        func_0x822a77a0(*(undefined4 *)(vm_context + 0x26c), 0);
        break;
    case 0xe:
        func_0x8229ee60(vm_context);
        break;
    case 0xf:
    case 0x10:
    case 0x13:
    case 0x16:
    case 0x17:
    case 0x1a:
    case 0x1d:
    case 0x22:
    case 0x25:
    case 0x27:
    case 0x29:
    case 0x2b:
        push_value = operand_0;
        break;
    case 0x11:
        *(undefined4 *)(operand_0 + 0x10) = 2;
        node_value = func_0x8229e8f8(vm_context, *(undefined4 *)(operand_0 + 0x18));
        *(undefined4 *)(operand_0 + 0x18) = node_value;
        push_value = operand_0;
        break;
    case 0x12:
        *(undefined4 *)(operand_0 + 0x10) = 2;
        node_value = func_0x8229cf28(vm_context, *(undefined4 *)(operand_0 + 0x18), 0, 0);
        *(undefined4 *)(operand_0 + 0x18) = node_value;
        *(undefined4 *)(vm_context + 0x58) = 1;
        push_value = operand_0;
        break;
    case 0x14:
        push_value = *(int *)(operand_0 + 0x18);
        goto compute_is_zero;
    case 0x15:
        operand_result = -*(int *)(operand_0 + 0x18);
        goto store_result;
    case 0x18:
        operand_result = *(int *)(operand_1 + 0x18) * *(int *)(operand_0 + 0x18);
        goto store_result;
    case 0x19:
        operand_result = *(uint *)(operand_1 + 0x18);
        if ((ulonglong)operand_result == 0) {
            func_0x822a7180(vm_context + 0x18, vm_context + 0x278, 0x5df, 0xffffffff8202c0c8);
            *(undefined4 *)(vm_context + 0x44) = 1;
            push_value = operand_0;
        }
        else {
            trapWord(6, (ulonglong)operand_result, 0);
            *(uint *)(operand_0 + 0x18) = *(uint *)(operand_0 + 0x18) / operand_result;
            push_value = operand_0;
        }
        break;
    case 0x1b:
        operand_result = *(int *)(operand_1 + 0x18) + *(int *)(operand_0 + 0x18);
        goto store_and_push;
    case 0x1c:
        operand_result = *(int *)(operand_0 + 0x18) - *(int *)(operand_1 + 0x18);
        goto store_result;
    case 0x1e:
        cmp_result = *(uint *)(operand_1 + 0x18) <= *(uint *)(operand_0 + 0x18);
        goto negate_bool;
    case 0x1f:
        cmp_result = *(uint *)(operand_0 + 0x18) <= *(uint *)(operand_1 + 0x18);
negate_bool:
        operand_result = -(uint)!cmp_result & 1;
        goto store_result;
    case 0x20:
        cmp_result = *(uint *)(operand_0 + 0x18) <= *(uint *)(operand_1 + 0x18);
        goto keep_bool;
    case 0x21:
        cmp_result = *(uint *)(operand_1 + 0x18) <= *(uint *)(operand_0 + 0x18);
keep_bool:
        operand_result = (uint)cmp_result;
store_and_push:
        *(uint *)(operand_0 + 0x18) = operand_result;
        push_value = operand_0;
        break;
    case 0x23:
        push_value = *(int *)(operand_1 + 0x18) - *(int *)(operand_0 + 0x18);
compute_is_zero:
        operand_result = (uint)LZCOUNT(push_value) >> 5;
        goto store_result;
    case 0x24:
        operand_result = (uint)LZCOUNT(*(int *)(operand_1 + 0x18) - *(int *)(operand_0 + 0x18)) >> 5 ^ 1;
        goto store_result;
    case 0x26:
        if ((*(int *)(operand_0 + 0x18) == 0) || (operand_result = 1, *(int *)(operand_1 + 0x18) == 0)) {
            operand_result = 0;
        }
        goto store_result;
    case 0x28:
        if ((*(int *)(operand_0 + 0x18) != 0) || (operand_result = 0, *(int *)(operand_1 + 0x18) != 0)) {
            operand_result = 1;
        }
        goto store_result;
    case 0x2a:
        if (*(int *)(operand_0 + 0x18) == 0) {
            operand_1 = operand_2;
        }
        operand_result = *(uint *)(operand_1 + 0x18);
store_result:
        *(uint *)(operand_0 + 0x18) = operand_result;
        push_value = operand_0;
        break;
    case 0x2c:
    case 0x2d:
    case 0x2e:
        alloc_result = func_0x822cd240(0x30, 0x10);
        if ((alloc_result & 0xffffffff) == 0) {
            push_value = 0;
        }
        else {
            push_value = func_0x822cd6f0(alloc_result, vm_context + 0x278);
        }
        func_0x8229d090(vm_context, push_value);
    }
    if (*(int *)(vm_context + 0x44) == 0) {
        free_node = *(int *)(vm_context + 0x60);
        if (free_node == 0) {
            alloc_result = func_0x822cd240(0x14, 0x10);
            if ((alloc_result & 0xffffffff) == 0) {
                free_node = 0;
            }
            else {
                free_node = func_0x822cd3a0(alloc_result, push_value, *(undefined4 *)(vm_context + 0x5c), 0xffffffff8202c0c0);
            }
            if (free_node == 0) {
                error_msg = 0xffffffff8202c0a0;
report_error:
                func_0x822a7180(vm_context + 0x18, vm_context + 0x278, 0, error_msg);
                *(undefined4 *)(vm_context + 0x44) = 1;
                halt_baddata();
            }
        }
        else {
            *(undefined4 *)(vm_context + 0x60) = *(undefined4 *)(free_node + 0xc);
            *(int *)(free_node + 8) = push_value;
            *(undefined4 *)(free_node + 0xc) = *(undefined4 *)(vm_context + 0x5c);
        }
        *(int *)(vm_context + 0x5c) = free_node;
    }
    halt_baddata();
}


// ============================================================================
// Test 13: Expression evaluator with operand stack and type coercion
// ============================================================================

// --- m2c ---

M2C_UNK func_822A7180(s32, void *, M2C_UNK, M2C_UNK); /* extern */
u32 func_822CD240(M2C_UNK, M2C_UNK);                /* extern */
void *func_822CD3A0(M2C_UNK, void *, M2C_UNK);      /* extern */
void *func_82487288();                              /* extern */
M2C_UNK func_824872D8();                            /* extern */

void test_13(s32 operand_stack) {
    s32 *operand_ptr;
    s32 remaining;
    void *free_node;
    void *eval_context;
    void *result;
    void *new_node;

    result = func_82487288();
    eval_context = result;
    if ((s32) M2C_FIELD(eval_context, s32 *, 0x50) == 0) {
        remaining = M2C_ERROR(/* Read from unset register $r5 */);
        if ((u32) M2C_ERROR(/* Read from unset register $r5 */) != 0U) {
            operand_ptr = &(&operand_stack)[M2C_ERROR(/* Read from unset register $r5 */)];
pop_loop:
            free_node = M2C_FIELD(eval_context, void **, 0x34);
            operand_ptr -= 4;
            if (free_node != NULL) {
                M2C_FIELD(eval_context, void **, 0x34) = (void *) M2C_FIELD(free_node, void **, 0xC);
                *operand_ptr = M2C_FIELD(free_node, s32 *, 8);
                M2C_FIELD(free_node, s32 *, 8) = 0;
                M2C_FIELD(free_node, void **, 0xC) = NULL;
                remaining -= 1;
                if (remaining == 0) {
                    goto dispatch;
                }
                goto pop_loop;
            }
            func_822A7180(M2C_FIELD(eval_context, s32 *, 0), eval_context + 0x10, 0, 0x8202C0F4);
            M2C_FIELD(eval_context, s32 *, 0x4C) = 1;
            func_824872D8();
            return;
        }
dispatch:
        if ((u32) (u64) result <= 0x3FU) {
            return;
        }
        if ((s32) M2C_FIELD(eval_context, s32 *, 0x50) == 0) {
            if (func_822CD240(0x14, 0x10) != 0U) {
                new_node = func_822CD3A0(0, M2C_FIELD(eval_context, void **, 0x34), 0x8202C0C0);
            } else {
                new_node = NULL;
            }
            if (new_node == NULL) {
                func_822A7180(M2C_FIELD(eval_context, s32 *, 0), eval_context + 0x10, 0, 0x8202C0A0);
                M2C_FIELD(eval_context, s32 *, 0x50) = 1;
                M2C_FIELD(eval_context, s32 *, 0x4C) = 1;
            } else {
                M2C_FIELD(eval_context, void **, 0x34) = new_node;
            }
        }
        func_824872D8();
        return;
    }
    func_824872D8();
}

// --- Ghidra ---

void test_13(undefined8 unused, undefined4 opcode, ulonglong num_operands)

{
    int node_type;
    undefined4 *eval_context;
    undefined4 node_value;
    ulonglong alloc_result;
    int push_value;
    undefined4 *error_target;
    undefined8 error_line;
    undefined8 error_msg;
    longlong operand_ptr;
    longlong src_ptr;
    ulonglong counter;
    double float_val;
    int operand_0;
    int operand_1;

    alloc_result = ZEXT48(&stack0x00000000);
    eval_context = (undefined4 *)func_0x82487288();
    if (eval_context[0x14] != 0) {
        halt_baddata();
    }
    if ((num_operands & 0xffffffff) != 0) {
        operand_ptr = (num_operands & 0x3fffffff) * 4 + (alloc_result - 0x70);
        counter = num_operands;
        do {
            push_value = eval_context[0xd];
            operand_ptr = operand_ptr + -4;
            if (push_value == 0) {
                func_0x822a7180(*eval_context, eval_context + 4, 0, 0xffffffff8202c0f4);
                eval_context[0x13] = 1;
                halt_baddata();
            }
            node_value = *(undefined4 *)(push_value + 8);
            eval_context[0xd] = *(undefined4 *)(push_value + 0xc);
            *(undefined4 *)operand_ptr = node_value;
            *(undefined4 *)(push_value + 8) = 0;
            *(undefined4 *)(push_value + 0xc) = 0;
            counter = counter - 1;
        } while (counter != 0);
    }
    push_value = 0;
    switch(opcode) {
    case 0:
    case 6:
        goto passthrough;
    case 1:
    case 2:
    case 4:
    case 5:
    case 10:
    case 0x17:
    case 0x19:
    case 0x1d:
    case 0x23:
    case 0x29:
    case 0x2a:
    case 0x2f:
    case 0x30:
        push_value = operand_0;
        break;
    case 3:
        push_value = func_0x822cd338(operand_1, operand_0);
        break;
    case 7:
        if (eval_context[0x1d] == 0) {
            eval_context[0x1d] = *(undefined4 *)(operand_0 + 0x18);
        }
        goto passthrough;
    case 8:
        goto reset_state;
    case 9:
        if (((int)eval_context[0xe] < 6) || (9 < (int)eval_context[0xe])) {
            error_line = 0x7eb;
            error_msg = 0xffffffff8202fa20;
            error_target = (undefined4 *)(operand_0 + 0x10);
            operand_1 = operand_0;
            goto report_error;
        }
        *(undefined4 *)(operand_0 + 0x54) = 1;
reset_state:
        func_0x822aa720(eval_context);
        push_value = operand_0;
        break;
    case 0xb:
        node_type = eval_context[0xe];
        if (((1 < node_type) && (node_type < 6)) || ((0xb < node_type && (node_type < 0x10)))) {
            *(int *)(operand_1 + 0x40) = operand_0;
            push_value = operand_1;
            break;
        }
        error_line = 0x7ec;
        error_msg = 0xffffffff8202f9e0;
        error_target = (undefined4 *)(operand_1 + 0x10);
        goto report_error;
    case 0xc:
    case 0xd:
    case 0xe:
    case 0xf:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13:
    case 0x14:
        if (1 < (num_operands & 0xffffffff)) {
            *(int *)(operand_0 + 0x3c) = operand_1;
        }
        push_value = operand_0;
        if (2 < (num_operands & 0xffffffff)) {
            src_ptr = alloc_result - 0x68;
            error_target = (undefined4 *)(operand_0 + 0x44);
            operand_ptr = num_operands - 2;
            do {
                node_value = *(undefined4 *)src_ptr;
                operand_ptr = operand_ptr + -1;
                *(undefined4 *)src_ptr = 0;
                src_ptr = src_ptr + 4;
                *error_target = node_value;
                error_target = error_target + 1;
            } while (operand_ptr != 0);
        }
        break;
    case 0x15:
    case 0x16:
        push_value = operand_0;
        if (1 < (num_operands & 0xffffffff)) {
            src_ptr = alloc_result - 0x6c;
            error_target = (undefined4 *)(operand_0 + 0x44);
            operand_ptr = num_operands - 1;
            do {
                node_value = *(undefined4 *)src_ptr;
                operand_ptr = operand_ptr + -1;
                *(undefined4 *)src_ptr = 0;
                src_ptr = src_ptr + 4;
                *error_target = node_value;
                error_target = error_target + 1;
            } while (operand_ptr != 0);
        }
        break;
    case 0x18:
        if (*(int *)(operand_0 + 0x1c) == 0) {
            node_value = func_0x822a8dc0(eval_context, operand_1 + 0x10);
            *(undefined4 *)(operand_0 + 0x20) = node_value;
            push_value = operand_0;
        }
        else {
            func_0x822a7180(*eval_context, eval_context + 4, 0x7e6, 0xffffffff8202f9b8);
            eval_context[0x13] = 1;
            *(undefined4 *)(operand_0 + 0x20) = 0xf0000;
            push_value = operand_0;
        }
        break;
    case 0x1a:
        if (*(int *)(operand_0 + 0x14) == 0) {
            node_value = 0xd000000;
            operand_1 = operand_0;
            goto store_type;
        }
        error_line = 0x7e2;
        error_msg = 0xffffffff8202f990;
        operand_1 = operand_0;
        goto report_error_alt;
    case 0x1b:
        node_type = *(int *)(operand_0 + 0x14);
        if (node_type == 0) {
            node_value = 0x1000000;
            operand_1 = operand_0;
        }
        else if (node_type == 0x2000000) {
            node_value = 0x3000000;
            operand_1 = operand_0;
        }
        else if (node_type == 0x4000000) {
            node_value = 0x5000000;
            operand_1 = operand_0;
        }
        else if (node_type == 0x7000000) {
            node_value = 0x8000000;
            operand_1 = operand_0;
        }
        else {
            if ((node_type == 0x9000000) || (node_type == 0xa000000)) {
                error_line = 0x7db;
                error_msg = 0xffffffff8202f960;
                operand_1 = operand_0;
                goto report_error_alt;
            }
            push_value = operand_0;
            if (node_type != 0xb000000) break;
            node_value = 0xc000000;
            operand_1 = operand_0;
        }
store_type:
        *(undefined4 *)(operand_1 + 0x14) = node_value;
        push_value = operand_1;
        break;
    case 0x1c:
        if (*(int *)(operand_0 + 0x18) == 1) {
            if (((int)eval_context[0xe] < 6) || (9 < (int)eval_context[0xe])) {
                error_line = 0x7ed;
                error_msg = 0xffffffff8202f8dc;
            }
            else {
                if (*(int *)(operand_1 + 0x14) == 0) {
                    node_value = 0x6000000;
                    goto store_type;
                }
                error_line = 0x7dc;
                error_msg = 0xffffffff8202f910;
            }
        }
        else {
            error_line = 0x7da;
            error_msg = 0xffffffff8202f940;
        }
report_error_alt:
        error_target = eval_context + 4;
report_error:
        func_0x822a7180(*eval_context, error_target, error_line, error_msg);
        eval_context[0x13] = 1;
        push_value = operand_1;
        break;
    case 0x1e:
        if (*(int *)(operand_0 + 0x1c) == 0) {
            node_value = func_0x822a8ed0(eval_context, operand_1 + 0x10);
            *(undefined4 *)(operand_0 + 0x24) = node_value;
            push_value = operand_0;
        }
        else {
            func_0x822a7180(*eval_context, eval_context + 4, 0x7e6, 0xffffffff8202f8b8);
            eval_context[0x13] = 1;
            *(undefined4 *)(operand_0 + 0x24) = 0xe40000;
            push_value = operand_0;
        }
        break;
    case 0x21:
        operand_1 = 0;
        goto eval_expression;
    case 0x22:
eval_expression:
        push_value = func_0x822a9e38(eval_context, operand_0 + 0x10, operand_1);
        goto push_result;
    case 0x24:
        *(int *)(operand_0 + 0x18) = *(int *)(operand_1 + 0x18) + *(int *)(operand_0 + 0x18);
        if (*(int *)(operand_0 + 0x28) == 0) {
            *(undefined4 *)(operand_0 + 0x28) = *(undefined4 *)(operand_1 + 0x28);
            *(undefined4 *)(operand_1 + 0x28) = 0;
            push_value = operand_0;
            break;
        }
        push_value = operand_0;
        if (*(int *)(operand_1 + 0x28) == 0) break;
        error_line = 0x7d9;
        error_msg = 0xffffffff8202f868;
        operand_1 = operand_0;
        goto report_error_alt;
    case 0x25:
        alloc_result = func_0x822cd240(0x2c, 0x10);
        if ((alloc_result & 0xffffffff) == 0) goto alloc_failed;
        node_value = 0;
alloc_and_create:
        push_value = func_0x822d1318(alloc_result, 0, 0, node_value, 0, operand_0);
        goto push_result;
    case 0x26:
        alloc_result = func_0x822cd240(0x2c, 0x10);
        if ((alloc_result & 0xffffffff) != 0) {
            node_value = *(undefined4 *)(operand_0 + 0x18);
            operand_0 = 0;
            goto alloc_and_create;
        }
        goto alloc_failed;
    case 0x27:
        alloc_result = func_0x822cd240(0x30, 0x10);
        if ((alloc_result & 0xffffffff) == 0) {
            push_value = 0;
        }
        else {
            push_value = func_0x822cd6f0(alloc_result, eval_context + 4);
        }
        func_0x822a8d48(eval_context, push_value);
        *(undefined4 *)(push_value + 0x18) = 1;
        *(undefined4 *)(push_value + 0x10) = 2;
        break;
    case 0x28:
        alloc_result = func_0x822cd240(0x30, 0x10);
        if ((alloc_result & 0xffffffff) == 0) {
            push_value = 0;
        }
        else {
            push_value = func_0x822cd6f0(alloc_result, eval_context + 4);
        }
        func_0x822a8d48(eval_context, push_value);
        *(undefined4 *)(push_value + 0x18) = 0;
        *(undefined4 *)(push_value + 0x10) = 2;
        break;
    case 0x2b:
        *(int *)(operand_0 + 0x18) = -*(int *)(operand_0 + 0x18);
        push_value = operand_0;
        break;
    case 0x2c:
    case 0x2d:
        *(undefined4 *)(operand_0 + 0x10) = 5;
        float_val = (double)*(uint *)(operand_0 + 0x18);
        goto store_float;
    case 0x2e:
        *(undefined4 *)(operand_0 + 0x10) = 5;
        float_val = (double)*(uint *)(operand_0 + 0x18);
        goto negate_float;
    case 0x31:
        float_val = *(double *)(operand_0 + 0x18);
negate_float:
        float_val = -float_val;
store_float:
        *(double *)(operand_0 + 0x18) = float_val;
        push_value = operand_0;
        break;
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x36:
    case 0x37:
    case 0x38:
    case 0x39:
    case 0x3a:
    case 0x3b:
    case 0x3c:
        alloc_result = func_0x822cd240(0x60, 0x10);
        if ((alloc_result & 0xffffffff) != 0) {
            push_value = func_0x822d1218(alloc_result, eval_context + 4, eval_context[0x10], eval_context[0x11], eval_context[0x12]);
            goto push_result;
        }
        goto alloc_failed;
    case 0x3d:
    case 0x3e:
    case 0x3f:
        alloc_result = func_0x822cd240(0x30, 0x10);
        if ((alloc_result & 0xffffffff) != 0) {
            push_value = func_0x822cd6f0(alloc_result, eval_context + 4);
            goto push_result;
        }
alloc_failed:
        push_value = 0;
push_result:
        func_0x822a8d48(eval_context, push_value);
    }
    if (eval_context[0x14] == 0) {
        alloc_result = func_0x822cd240(0x14, 0x10);
        if ((alloc_result & 0xffffffff) == 0) {
            push_value = 0;
        }
        else {
            push_value = func_0x822cd3a0(alloc_result, push_value, eval_context[0xd], 0xffffffff8202c0c0);
        }
        if (push_value == 0) {
            func_0x822a7180(*eval_context, eval_context + 4, 0, 0xffffffff8202c0a0);
            eval_context[0x14] = 1;
            eval_context[0x13] = 1;
        }
        else {
            eval_context[0xd] = push_value;
        }
    }
    halt_baddata();
passthrough:
    push_value = 0;
    goto LAB_822ac0c8;
}


// ============================================================================
// Test 14: Gameplay scoring/animation setup with per-difficulty branch logic
// ============================================================================

// --- m2c ---

M2C_UNK func_822C0890();                            /* extern */
s32 func_823053E8(s32);                             /* extern */
s32 *func_82508528(s32);                            /* extern */
u32 *func_8250F4C8(M2C_UNK *, s32);                 /* extern */
s32 func_82A13598(s32);                             /* extern */
M2C_UNK func_82BB2CB8(M2C_UNK *, s32, M2C_UNK *, f32); /* extern */
s32 func_82DF1C90(M2C_UNK *);                       /* extern */
M2C_UNK func_82DF3428(M2C_UNK *);                   /* extern */
M2C_UNK func_82DF3A08(M2C_UNK *, s32);              /* extern */
M2C_UNK func_82E3FF08(M2C_UNK *, s32);              /* extern */
s32 func_83154600();                                /* extern */
u64 func_831A8160();                                /* extern */

s32 test_14(M2C_UNK output_buf, M2C_UNK symbol_name, M2C_UNK anim_data, u32 anim_has_error, M2C_UNK score_query, M2C_UNK anim_data_alt, u32 alt_has_error) {
    f32 time_scale;
    s32 song_data;
    s32 score_result;
    s32 difficulty_index;
    u32 raw_score;
    u32 context_flags;

    context_flags = (u32) func_831A8160();
    song_data = func_83154600();
    func_82DF3A08(&symbol_name, *(s32 *)0x83267658);
    time_scale = *(f32 *)0x820008A4;
    func_82BB2CB8(&anim_data, func_823053E8(song_data), &symbol_name, time_scale);
    if (anim_has_error != 0U) {
        func_822C0890();
    }
    func_82DF3428(&symbol_name);
    func_82DF3A08(&symbol_name, *(s32 *)0x83267C74);
    func_82BB2CB8(&anim_data_alt, func_823053E8(song_data), &symbol_name, time_scale);
    if (alt_has_error != 0U) {
        func_822C0890();
    }
    func_82DF3428(&symbol_name);
    raw_score = *func_8250F4C8(&score_query, func_82A13598(song_data));
    difficulty_index = raw_score - 4;
    if (raw_score == 0U) {
        difficulty_index = 0;
    }
    func_82E3FF08(&output_buf, *func_82508528(difficulty_index));
    score_result = func_82DF1C90(&score_query);
    if ((u32) M2C_FIELD(context_flags, u32 *, 0x18) <= 7U) {
        return score_result;
    }
    return 1;
}

// --- Ghidra ---

void test_14(undefined8 unused, int switch_param)

{
    int context;
    longlong song_data;
    undefined8 track_id;
    uint *score_ptr;
    longlong adjusted_score;
    undefined4 *anim_result;
    undefined1 *cleanup_target;
    double time_scale;
    undefined1 output_buf[4];
    undefined1 symbol_name[4];
    undefined1 symbol_name_2[4];
    undefined1 symbol_name_3[4];
    undefined1 symbol_name_4[4];
    undefined1 symbol_name_5[4];
    undefined1 symbol_name_6[4];
    undefined1 symbol_name_7[4];
    undefined1 symbol_name_8[4];
    undefined1 symbol_name_9[4];
    undefined1 symbol_name_10[4];
    undefined1 symbol_name_11[4];
    undefined1 symbol_name_12[4];
    undefined1 symbol_name_13[4];
    undefined1 symbol_name_14[4];
    undefined1 symbol_name_15[4];
    undefined1 symbol_name_16[4];
    undefined1 symbol_name_17[4];
    undefined1 symbol_name_18[4];
    undefined1 symbol_name_19[4];
    undefined1 anim_buf_0[8];
    undefined1 anim_buf_0b[4];
    int anim_0_has_error;
    undefined1 anim_buf_1[4];
    int anim_1_has_error;
    undefined1 anim_buf_2[4];
    int anim_2_has_error;
    undefined1 score_query[8];
    undefined1 score_result_0[4];
    int score_0_has_error;
    undefined1 score_result_1[4];
    int score_1_has_error;
    undefined1 score_result_2[4];
    int score_2_has_error;
    undefined1 score_result_3[4];
    int score_3_has_error;
    undefined1 score_result_4[4];
    int score_4_has_error;
    undefined1 score_result_5[4];
    int score_5_has_error;
    undefined1 score_result_6[4];
    int score_6_has_error;
    undefined1 score_result_7[4];
    int score_7_has_error;
    undefined1 anim_data_alt[4];
    int alt_has_error;
    undefined1 anim_result_0[4];
    int anim_result_0_error;
    undefined1 anim_result_1[4];
    int anim_result_1_error;
    undefined1 anim_result_2[4];
    int anim_result_2_error;
    undefined1 anim_result_3[4];
    int anim_result_3_error;

    context = func_0x831a8160();
    song_data = func_0x83154600();
    func_0x82df3a08(symbol_name, uRam83267658);
    track_id = func_0x823053e8(song_data);
    time_scale = (double)fRam820008a4;
    func_0x82bb2cb8(time_scale, anim_buf_0b, track_id, symbol_name);
    if (anim_0_has_error != 0) {
        func_0x822c0890();
    }
    func_0x82df3428(symbol_name);
    func_0x82df3a08(symbol_name, uRam83267c74);
    track_id = func_0x823053e8(song_data);
    func_0x82bb2cb8(time_scale, anim_data_alt, track_id, symbol_name);
    if (alt_has_error != 0) {
        func_0x822c0890();
    }
    func_0x82df3428(symbol_name);
    track_id = func_0x82a13598(song_data);
    score_ptr = (uint *)func_0x8250f4c8(score_query, track_id);
    adjusted_score = (ulonglong)*score_ptr - 4;
    if ((ulonglong)*score_ptr == 0) {
        adjusted_score = 0;
    }
    anim_result = (undefined4 *)func_0x82508528(adjusted_score);
    func_0x82e3ff08(output_buf, *anim_result);
    func_0x82df1c90(score_query);
    switch(*(undefined4 *)(switch_param + 0x18)) {
    case 0:
        func_0x82df3a08(symbol_name, uRam83267658);
        track_id = func_0x823053e8(song_data);
        func_0x82bb2c20(time_scale, score_result_6, track_id, symbol_name);
        if (score_6_has_error != 0) {
            func_0x822c0890();
        }
        cleanup_target = symbol_name;
        break;
    case 1:
        func_0x82df3a08(symbol_name_11, uRam83267c74);
        track_id = func_0x823053e8(song_data);
        func_0x82bb2c20(time_scale, score_result_1, track_id, symbol_name_11);
        if (score_1_has_error != 0) {
            func_0x822c0890();
        }
        cleanup_target = symbol_name_11;
        break;
    case 2:
        *(undefined1 *)(context + 0x71) = 1;
        func_0x82df3878(song_data + 0x2e8, uRam83267c8c);
        func_0x82df3a08(symbol_name_19, uRam83267c8c);
        track_id = func_0x823053e8(song_data);
        func_0x82bb2c20(time_scale, anim_result_3, track_id, symbol_name_19);
        if (anim_result_3_error != 0) {
            func_0x822c0890();
        }
        func_0x82df3428(symbol_name_19);
        func_0x82df3a08(symbol_name_5, 0xffffffff82023334);
        anim_result = (undefined4 *)func_0x82e40a68(score_result_3, output_buf, symbol_name_5, 0);
        context = func_0x82a13598(song_data);
        *(undefined4 *)(context + 0x3c8) = *anim_result;
        func_0x822c4460(context + 0x3cc, anim_result + 1);
        if (score_3_has_error != 0) {
            func_0x822c0890();
        }
        func_0x82df3428(symbol_name_5);
        func_0x82df3a08(symbol_name_14, 0xffffffff82023318);
        anim_result = (undefined4 *)func_0x82e40a68(score_result_7, output_buf, symbol_name_14, 0);
        context = func_0x82a13598(song_data);
        *(undefined4 *)(context + 0x3dc) = *anim_result;
        func_0x822c4460(context + 0x3e0, anim_result + 1);
        if (score_7_has_error != 0) {
            func_0x822c0890();
        }
        cleanup_target = symbol_name_14;
        break;
    case 3:
        *(undefined1 *)(context + 0x71) = 1;
        func_0x82df3878(song_data + 0x2e8, uRam83267c78);
        func_0x82df3a08(symbol_name_8, uRam83267c78);
        track_id = func_0x823053e8(song_data);
        func_0x82bb2c20(time_scale, score_result_4, track_id, symbol_name_8);
        if (score_4_has_error != 0) {
            func_0x822c0890();
        }
        func_0x82df3428(symbol_name_8);
        func_0x82df3a08(symbol_name_17, 0xffffffff820232fc);
        anim_result = (undefined4 *)func_0x82e40a68(anim_result_0, output_buf, symbol_name_17, 0);
        context = func_0x82a13598(song_data);
        *(undefined4 *)(context + 0x3c8) = *anim_result;
        func_0x822c4460(context + 0x3cc, anim_result + 1);
        if (anim_result_0_error != 0) {
            func_0x822c0890();
        }
        func_0x82df3428(symbol_name_17);
        func_0x82df3a08(symbol_name_9, 0xffffffff820232e0);
        anim_result = (undefined4 *)func_0x82e40a68(score_result_5, output_buf, symbol_name_9, 0);
        context = func_0x82a13598(song_data);
        *(undefined4 *)(context + 0x3dc) = *anim_result;
        func_0x822c4460(context + 0x3e0, anim_result + 1);
        if (score_5_has_error != 0) {
            func_0x822c0890();
        }
        cleanup_target = symbol_name_9;
        break;
    case 4:
        *(undefined1 *)(context + 0x71) = 1;
        func_0x82df3878(song_data + 0x2e8, uRam83267c7c);
        func_0x82df3a08(symbol_name_15, uRam83267c7c);
        track_id = func_0x823053e8(song_data);
        func_0x82bb2c20(time_scale, anim_buf_1, track_id, symbol_name_15);
        if (anim_1_has_error != 0) {
            func_0x822c0890();
        }
        func_0x82df3428(symbol_name_15);
        func_0x82df3a08(symbol_name_2, 0xffffffff820232c4);
        anim_result = (undefined4 *)func_0x82e40a68(anim_buf_2, output_buf, symbol_name_2, 0);
        context = func_0x82a13598(song_data);
        *(undefined4 *)(context + 0x3c8) = *anim_result;
        func_0x822c4460(context + 0x3cc, anim_result + 1);
        if (anim_2_has_error != 0) {
            func_0x822c0890();
        }
        func_0x82df3428(symbol_name_2);
        func_0x82df3a08(symbol_name_3, 0xffffffff820232a8);
        anim_result = (undefined4 *)func_0x82e40a68(score_result_0, output_buf, symbol_name_3, 0);
        context = func_0x82a13598(song_data);
        *(undefined4 *)(context + 0x3dc) = *anim_result;
        func_0x822c4460(context + 0x3e0, anim_result + 1);
        if (score_0_has_error != 0) {
            func_0x822c0890();
        }
        cleanup_target = symbol_name_3;
        break;
    case 5:
        *(undefined1 *)(context + 0x71) = 1;
        func_0x82df3878(song_data + 0x2e8, uRam83267c80);
        func_0x82df3a08(symbol_name_4, uRam83267c80);
        track_id = func_0x823053e8(song_data);
        func_0x82bb2c20(time_scale, score_result_2, track_id, symbol_name_4);
        if (score_2_has_error != 0) {
            func_0x822c0890();
        }
        func_0x82df3428(symbol_name_4);
        func_0x82df3a08(symbol_name_6, 0xffffffff8202328c);
        anim_result = (undefined4 *)func_0x82e40a68(score_result_4, output_buf, symbol_name_6, 0);
        context = func_0x82a13598(song_data);
        *(undefined4 *)(context + 0x3c8) = *anim_result;
        func_0x822c4460(context + 0x3cc, anim_result + 1);
        if (score_4_has_error != 0) {
            func_0x822c0890();
        }
        func_0x82df3428(symbol_name_6);
        func_0x82df3a08(symbol_name_7, 0xffffffff82023270);
        anim_result = (undefined4 *)func_0x82e40a68(score_result_5, output_buf, symbol_name_7, 0);
        context = func_0x82a13598(song_data);
        *(undefined4 *)(context + 0x3dc) = *anim_result;
        func_0x822c4460(context + 0x3e0, anim_result + 1);
        if (score_5_has_error != 0) {
            func_0x822c0890();
        }
        cleanup_target = symbol_name_7;
        break;
    case 6:
        *(undefined1 *)(context + 0x71) = 1;
        func_0x82df3878(song_data + 0x2e8, uRam83267c84);
        func_0x82df3a08(symbol_name_10, uRam83267c84);
        track_id = func_0x823053e8(song_data);
        func_0x82bb2c20(time_scale, score_result_6, track_id, symbol_name_10);
        if (score_6_has_error != 0) {
            func_0x822c0890();
        }
        func_0x82df3428(symbol_name_10);
        func_0x82df3a08(symbol_name_12, 0xffffffff82023254);
        anim_result = (undefined4 *)func_0x82e40a68(score_result_7, output_buf, symbol_name_12, 0);
        context = func_0x82a13598(song_data);
        *(undefined4 *)(context + 0x3c8) = *anim_result;
        func_0x822c4460(context + 0x3cc, anim_result + 1);
        if (score_7_has_error != 0) {
            func_0x822c0890();
        }
        func_0x82df3428(symbol_name_12);
        func_0x82df3a08(symbol_name_13, 0xffffffff82023238);
        anim_result = (undefined4 *)func_0x82e40a68(anim_data_alt, output_buf, symbol_name_13, 0);
        context = func_0x82a13598(song_data);
        *(undefined4 *)(context + 0x3dc) = *anim_result;
        func_0x822c4460(context + 0x3e0, anim_result + 1);
        if (alt_has_error != 0) {
            func_0x822c0890();
        }
        cleanup_target = symbol_name_13;
        break;
    case 7:
        *(undefined1 *)(context + 0x71) = 1;
        func_0x82df3878(song_data + 0x2e8, uRam83267c88);
        func_0x82df3a08(symbol_name_16, uRam83267c88);
        track_id = func_0x823053e8(song_data);
        func_0x82bb2c20(time_scale, anim_result_1, track_id, symbol_name_16);
        if (anim_result_1_error != 0) {
            func_0x822c0890();
        }
        func_0x82df3428(symbol_name_16);
        func_0x82df3a08(symbol_name_18, 0xffffffff8202321c);
        anim_result = (undefined4 *)func_0x82e40a68(anim_result_2, output_buf, symbol_name_18, 0);
        context = func_0x82a13598(song_data);
        *(undefined4 *)(context + 0x3c8) = *anim_result;
        func_0x822c4460(context + 0x3cc, anim_result + 1);
        if (anim_result_2_error != 0) {
            func_0x822c0890();
        }
        func_0x82df3428(symbol_name_18);
        func_0x82df3a08(anim_buf_0, 0xffffffff82023200);
        anim_result = (undefined4 *)func_0x82e40a68(anim_result_3, output_buf, anim_buf_0, 0);
        context = func_0x82a13598(song_data);
        *(undefined4 *)(context + 0x3dc) = *anim_result;
        func_0x822c4460(context + 0x3e0, anim_result + 1);
        if (anim_result_3_error != 0) {
            func_0x822c0890();
        }
        cleanup_target = anim_buf_0;
        break;
    default:
        goto exit;
    }
    func_0x82df3428(cleanup_target);
exit:
    halt_baddata();
}

// ============================================================================
// Test 15: Registers multiple string constants with a context, then dispatches by state index
// ============================================================================

// --- m2c ---

void *get_context();                                   /* extern: func_831A8144 */
void init_string(void *, u32);                         /* extern: func_82DF3A08 */
void register_string(u32, void *, int);                /* extern: func_825A1588 */
void destroy_string(void *);                           /* extern: func_82DF3428 */
void fallback_handler();                               /* extern: func_831A8194 */

void test_15(void *str_buf) {
    u32 context_lo;
    u64 context_hi;
    u64 context_ret;

    context_ret = get_context();
    context_hi = context_ret;
    context_lo = (u32) context_ret;
    init_string(&str_buf, 0x82024A98);
    register_string(context_lo, &str_buf, 0);
    destroy_string(&str_buf);
    init_string(&str_buf, 0x8204132C);
    register_string(context_lo, &str_buf, 0);
    destroy_string(&str_buf);
    init_string(&str_buf, 0x82041310);
    register_string(context_lo, &str_buf, 0);
    destroy_string(&str_buf);
    init_string(&str_buf, 0x8203FD08);
    register_string(context_lo, &str_buf, 0);
    destroy_string(&str_buf);
    init_string(&str_buf, 0x82044370);
    register_string(context_lo, &str_buf, 0);
    destroy_string(&str_buf);
    init_string(&str_buf, 0x8204D2D0);
    register_string(context_lo, &str_buf, 0);
    destroy_string(&str_buf);
    init_string(&str_buf, 0x82051160);
    register_string(context_lo, &str_buf, 0);
    destroy_string(&str_buf);
    init_string(&str_buf, 0x82051154);
    register_string(context_lo, &str_buf, 0);
    destroy_string(&str_buf);
    init_string(&str_buf, 0x8204D2E8);
    register_string(context_lo, &str_buf, 0);
    destroy_string(&str_buf);
    init_string(&str_buf, 0x8205114C);
    register_string(context_lo, &str_buf, 0);
    destroy_string(&str_buf);
    init_string(&str_buf, 0x8205113C);
    register_string(context_lo, &str_buf, 0);
    destroy_string(&str_buf);
    init_string(&str_buf, 0x82024A98);
    register_string(context_lo, &str_buf, 1);
    destroy_string(&str_buf);
    if ((u32) (M2C_FIELD(context_hi, s32 *, 0x64) - 1) <= 9U) {
        return;
    }
    fallback_handler();
}

// --- Ghidra ---

void test_15(undefined8 unused_param, undefined8 context_pair)
{
    int context;
    undefined1 *last_buf;
    undefined1 str_buf_0 [4];
    undefined1 str_buf_1 [4];
    undefined1 str_buf_2 [4];
    undefined1 str_buf_3 [4];
    undefined1 str_buf_4 [4];
    undefined1 str_buf_5 [4];
    undefined1 str_buf_6 [4];
    undefined1 str_buf_7 [4];
    undefined1 str_buf_8 [4];
    undefined1 str_buf_9 [4];
    undefined1 str_buf_10 [4];
    undefined1 str_buf_11 [4];
    undefined1 str_buf_12 [4];
    undefined1 str_buf_13 [4];
    undefined1 str_buf_14 [4];
    undefined1 str_buf_15 [4];
    undefined1 str_buf_16 [4];
    undefined1 str_buf_17 [4];
    undefined1 str_buf_18 [4];
    undefined1 str_buf_19 [4];
    undefined1 str_buf_20 [4];
    undefined1 str_buf_21 [4];
    undefined1 str_buf_22 [4];
    undefined1 str_buf_23 [4];
    undefined1 str_buf_24 [4];
    undefined1 str_buf_25 [4];
    undefined1 str_buf_26 [4];
    undefined1 str_buf_27 [4];
    undefined1 str_buf_28 [4];
    undefined1 str_buf_29 [4];
    undefined1 str_buf_30 [4];
    undefined1 str_buf_31 [4];
    undefined1 str_buf_32 [4];
    undefined1 str_buf_33 [4];
    undefined1 str_buf_34 [4];
    undefined1 str_buf_35 [4];
    undefined1 str_buf_36 [4];
    undefined1 str_buf_37 [4];
    undefined1 str_buf_38 [4];
    undefined1 str_buf_39 [4];
    undefined1 str_buf_40 [4];
    undefined1 str_buf_41 [4];
    undefined1 str_buf_42 [4];
    undefined1 str_buf_43 [4];
    undefined1 str_buf_44 [4];
    undefined1 str_buf_45 [4];
    undefined1 str_buf_46 [4];
    undefined1 str_buf_47 [4];
    undefined1 str_buf_48 [4];
    undefined1 str_buf_49 [4];
    undefined1 str_buf_50 [4];
    undefined1 str_buf_tail [128];

    context = func_0x831a8144();
    func_0x82df3a08(str_buf_0, 0xffffffff82024a98);
    func_0x825a1588(context_pair, str_buf_0, 0);
    func_0x82df3428(str_buf_0);
    func_0x82df3a08(str_buf_0, 0xffffffff8204132c);
    func_0x825a1588(context_pair, str_buf_0, 0);
    func_0x82df3428(str_buf_0);
    func_0x82df3a08(str_buf_0, 0xffffffff82041310);
    func_0x825a1588(context_pair, str_buf_0, 0);
    func_0x82df3428(str_buf_0);
    func_0x82df3a08(str_buf_0, 0xffffffff8203fd08);
    func_0x825a1588(context_pair, str_buf_0, 0);
    func_0x82df3428(str_buf_0);
    func_0x82df3a08(str_buf_0, 0xffffffff82044370);
    func_0x825a1588(context_pair, str_buf_0, 0);
    func_0x82df3428(str_buf_0);
    func_0x82df3a08(str_buf_0, 0xffffffff8204d2d0);
    func_0x825a1588(context_pair, str_buf_0, 0);
    func_0x82df3428(str_buf_0);
    func_0x82df3a08(str_buf_0, 0xffffffff82051160);
    func_0x825a1588(context_pair, str_buf_0, 0);
    func_0x82df3428(str_buf_0);
    func_0x82df3a08(str_buf_0, 0xffffffff82051154);
    func_0x825a1588(context_pair, str_buf_0, 0);
    func_0x82df3428(str_buf_0);
    func_0x82df3a08(str_buf_0, 0xffffffff8204d2e8);
    func_0x825a1588(context_pair, str_buf_0, 0);
    func_0x82df3428(str_buf_0);
    func_0x82df3a08(str_buf_0, 0xffffffff8205114c);
    func_0x825a1588(context_pair, str_buf_0, 0);
    func_0x82df3428(str_buf_0);
    func_0x82df3a08(str_buf_0, 0xffffffff8205113c);
    func_0x825a1588(context_pair, str_buf_0, 0);
    func_0x82df3428(str_buf_0);
    func_0x82df3a08(str_buf_0, 0xffffffff82024a98);
    func_0x825a1588(context_pair, str_buf_0, 1);
    func_0x82df3428(str_buf_0);
    switch (*(undefined4 *)(context + 100)) {
    case 1:
        func_0x82df3a08(str_buf_0, 0xffffffff8204132c);
        func_0x825a1588(context_pair, str_buf_0, 1);
        func_0x82df3428(str_buf_0);
        func_0x82df3a08(str_buf_28, 0xffffffff82041310);
        func_0x825a1588(context_pair, str_buf_28, 1);
        func_0x82df3428(str_buf_28);
        func_0x82df3a08(str_buf_3, 0xffffffff82044370);
        func_0x825a1588(context_pair, str_buf_3, 1);
        func_0x82df3428(str_buf_3);
        func_0x82df3a08(str_buf_39, 0xffffffff8204d2d0);
        func_0x825a1588(context_pair, str_buf_39, 1);
        func_0x82df3428(str_buf_39);
        func_0x82df3a08(str_buf_5, 0xffffffff8204d2e8);
        func_0x825a1588(context_pair, str_buf_5, 1);
        func_0x82df3428(str_buf_5);
        func_0x82df3a08(str_buf_30, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_30, 1);
        last_buf = str_buf_30;
        break;
    case 2:
        func_0x82df3a08(str_buf_7, 0xffffffff8204132c);
        func_0x825a1588(context_pair, str_buf_7, 1);
        func_0x82df3428(str_buf_7);
        func_0x82df3a08(str_buf_42, 0xffffffff82041310);
        func_0x825a1588(context_pair, str_buf_42, 1);
        func_0x82df3428(str_buf_42);
        func_0x82df3a08(str_buf_9, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_9, 1);
        func_0x82df3428(str_buf_9);
        func_0x82df3a08(str_buf_32, 0xffffffff8204d2d0);
        func_0x825a1588(context_pair, str_buf_32, 1);
        func_0x82df3428(str_buf_32);
        func_0x82df3a08(str_buf_11, 0xffffffff82051154);
        func_0x825a1588(context_pair, str_buf_11, 1);
        func_0x82df3428(str_buf_11);
        func_0x82df3a08(str_buf_44, 0xffffffff8204d2e8);
        func_0x825a1588(context_pair, str_buf_44, 1);
        func_0x82df3428(str_buf_44);
        func_0x82df3a08(str_buf_13, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_13, 1);
        last_buf = str_buf_13;
        break;
    case 3:
        func_0x82df3a08(str_buf_34, 0xffffffff8204132c);
        func_0x825a1588(context_pair, str_buf_34, 1);
        func_0x82df3428(str_buf_34);
        func_0x82df3a08(str_buf_15, 0xffffffff82041310);
        func_0x825a1588(context_pair, str_buf_15, 1);
        func_0x82df3428(str_buf_15);
        func_0x82df3a08(str_buf_43, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_43, 1);
        func_0x82df3428(str_buf_43);
        func_0x82df3a08(str_buf_17, 0xffffffff8204d2d0);
        func_0x825a1588(context_pair, str_buf_17, 1);
        func_0x82df3428(str_buf_17);
        func_0x82df3a08(str_buf_36, 0xffffffff82051154);
        func_0x825a1588(context_pair, str_buf_36, 1);
        func_0x82df3428(str_buf_36);
        func_0x82df3a08(str_buf_19, 0xffffffff8204d2e8);
        func_0x825a1588(context_pair, str_buf_19, 1);
        func_0x82df3428(str_buf_19);
        func_0x82df3a08(str_buf_47, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_47, 1);
        last_buf = str_buf_47;
        break;
    case 4:
        func_0x82df3a08(str_buf_21, 0xffffffff8204132c);
        func_0x825a1588(context_pair, str_buf_21, 1);
        func_0x82df3428(str_buf_21);
        func_0x82df3a08(str_buf_38, 0xffffffff82041310);
        func_0x825a1588(context_pair, str_buf_38, 1);
        func_0x82df3428(str_buf_38);
        func_0x82df3a08(str_buf_23, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_23, 1);
        func_0x82df3428(str_buf_23);
        func_0x82df3a08(str_buf_45, 0xffffffff82044370);
        func_0x825a1588(context_pair, str_buf_45, 1);
        func_0x82df3428(str_buf_45);
        func_0x82df3a08(str_buf_25, 0xffffffff8204d2e8);
        func_0x825a1588(context_pair, str_buf_25, 1);
        func_0x82df3428(str_buf_25);
        func_0x82df3a08(str_buf_40, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_40, 1);
        last_buf = str_buf_40;
        break;
    case 5:
        func_0x82df3a08(str_buf_2, 0xffffffff8204132c);
        func_0x825a1588(context_pair, str_buf_2, 1);
        func_0x82df3428(str_buf_2);
        func_0x82df3a08(str_buf_1, 0xffffffff82041310);
        func_0x825a1588(context_pair, str_buf_1, 1);
        func_0x82df3428(str_buf_1);
        func_0x82df3a08(str_buf_4, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_4, 1);
        func_0x82df3428(str_buf_4);
        func_0x82df3a08(str_buf_6, 0xffffffff82051154);
        func_0x825a1588(context_pair, str_buf_6, 1);
        func_0x82df3428(str_buf_6);
        func_0x82df3a08(str_buf_8, 0xffffffff8204d2e8);
        func_0x825a1588(context_pair, str_buf_8, 1);
        func_0x82df3428(str_buf_8);
        func_0x82df3a08(str_buf_10, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_10, 1);
        last_buf = str_buf_10;
        break;
    case 6:
        func_0x82df3a08(str_buf_12, 0xffffffff8204132c);
        func_0x825a1588(context_pair, str_buf_12, 1);
        func_0x82df3428(str_buf_12);
        func_0x82df3a08(str_buf_14, 0xffffffff82041310);
        func_0x825a1588(context_pair, str_buf_14, 1);
        func_0x82df3428(str_buf_14);
        func_0x82df3a08(str_buf_16, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_16, 1);
        func_0x82df3428(str_buf_16);
        func_0x82df3a08(str_buf_18, 0xffffffff82051154);
        func_0x825a1588(context_pair, str_buf_18, 1);
        func_0x82df3428(str_buf_18);
        func_0x82df3a08(str_buf_20, 0xffffffff8204d2e8);
        func_0x825a1588(context_pair, str_buf_20, 1);
        func_0x82df3428(str_buf_20);
        func_0x82df3a08(str_buf_22, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_22, 1);
        last_buf = str_buf_22;
        break;
    case 7:
        func_0x82df3a08(str_buf_24, 0xffffffff82044370);
        func_0x825a1588(context_pair, str_buf_24, 1);
        func_0x82df3428(str_buf_24);
        func_0x82df3a08(str_buf_26, 0xffffffff82051160);
        func_0x825a1588(context_pair, str_buf_26, 1);
        func_0x82df3428(str_buf_26);
        func_0x82df3a08(str_buf_27, 0xffffffff8204d2e8);
        func_0x825a1588(context_pair, str_buf_27, 1);
        func_0x82df3428(str_buf_27);
        func_0x82df3a08(str_buf_29, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_29, 1);
        func_0x82df3428(str_buf_29);
        if (*(char *)(context + 0x84) == '\0') {
            halt_baddata();
        }
        func_0x82df3a08(str_buf_31, 0xffffffff82051154);
        func_0x825a1588(context_pair, str_buf_31, 1);
        last_buf = str_buf_31;
        break;
    case 8:
        func_0x82df3a08(str_buf_33, 0xffffffff82051154);
        func_0x825a1588(context_pair, str_buf_33, 1);
        func_0x82df3428(str_buf_33);
        func_0x82df3a08(str_buf_35, 0xffffffff82051160);
        func_0x825a1588(context_pair, str_buf_35, 1);
        func_0x82df3428(str_buf_35);
        func_0x82df3a08(str_buf_37, 0xffffffff8204d2e8);
        func_0x825a1588(context_pair, str_buf_37, 1);
        func_0x82df3428(str_buf_37);
        func_0x82df3a08(str_buf_41, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_41, 1);
        last_buf = str_buf_41;
        break;
    case 9:
        func_0x82df3a08(str_buf_46, 0xffffffff82051154);
        func_0x825a1588(context_pair, str_buf_46, 1);
        func_0x82df3428(str_buf_46);
        func_0x82df3a08(str_buf_48, 0xffffffff82051160);
        func_0x825a1588(context_pair, str_buf_48, 1);
        func_0x82df3428(str_buf_48);
        func_0x82df3a08(str_buf_49, 0xffffffff8204d2e8);
        func_0x825a1588(context_pair, str_buf_49, 1);
        func_0x82df3428(str_buf_49);
        func_0x82df3a08(str_buf_50, 0xffffffff8203fd08);
        func_0x825a1588(context_pair, str_buf_50, 1);
        last_buf = str_buf_50;
        break;
    case 10:
        func_0x82df3a08(str_buf_51, 0xffffffff8205114c);
        func_0x825a1588(context_pair, str_buf_51, 1);
        func_0x82df3428(str_buf_51);
        func_0x82df3a08(str_buf_tail, 0xffffffff8205113c);
        func_0x825a1588(context_pair, str_buf_tail, 1);
        last_buf = str_buf_tail;
        break;
    default:
        goto LAB_fallback;
    }
    func_0x82df3428(last_buf);
LAB_fallback:
    halt_baddata();
}


// ============================================================================
// Test 16: Property getter dispatcher - reads typed fields from a global config by property ID
// ============================================================================

// --- m2c ---

s32 get_property_id();                                 /* extern: func_82696F38 */
void finalize_property(u32);                           /* extern: func_82696F88 */
void lock_config(u32);                                 /* extern: func_82960C04 */
void unlock_config(u32);                               /* extern: func_82960C14 */

void test_16(void) {
    u32 status;
    s32 property_id;
    s32 property_id_ret;
    s32 field_value;
    u32 *out_size;
    u32 buf_size;
    u32 out_buf;

    property_id_ret = get_property_id();
    property_id = property_id_ret;
    out_buf = (u32) (u64) property_id_ret;
    out_size = M2C_ERROR(/* Read from unset register $r5 */);
    lock_config(0x8297D2D4);
    if (property_id <= 0x1000) {
        if (property_id != 0x1000) {
            if ((u32) (property_id - 1) <= 0x1BU) {
                return;
            }
            status = 0x807A1009;
            /* Duplicate return node #88. Try simplifying control flow for better match */
            unlock_config(0x8297D2D4);
            finalize_property(status);
            return;
        }
        if ((u32) *out_size >= 4U) {
            field_value = M2C_FIELD((void *)0x8297D248, s32 *, 0x60);
            goto write_value;
        }
        goto set_error;
        goto update_size;
    }
    buf_size = property_id - 0x1003;
    switch (buf_size) {                                /* irregular */
    case 0:
        if ((u32) *out_size >= 4U) {
            field_value = M2C_FIELD((void *)0x8297D248, s32 *, 0x30);
write_value:
            status = 0;
            *out_buf = field_value;
        } else {
set_error:
            status = 0x807A1001;
        }
update_size:
        *out_size = 4U;
        break;
    case 1:
        if ((u32) *out_size >= 4U) {
            field_value = (s32) M2C_FIELD((void *)0x8297D248, u16 *, 0x38);
            goto write_value;
        }
        goto set_error;
        goto update_size;
    case 2:
        if ((u32) *out_size >= 4U) {
            field_value = (s32) M2C_FIELD((void *)0x8297D248, u16 *, 0x3A);
            goto write_value;
        }
        goto set_error;
        goto update_size;
    case 3:
        if ((u32) *out_size >= 4U) {
            field_value = (s32) M2C_FIELD((void *)0x8297D248, u16 *, 0x3C);
            goto write_value;
        }
        goto set_error;
        goto update_size;
    case 4:
        if ((u32) *out_size >= 4U) {
            field_value = M2C_FIELD((void *)0x8297D248, s32 *, 0x64);
            goto write_value;
        }
        goto set_error;
        goto update_size;
    case 5:
        if ((u32) *out_size >= 4U) {
            field_value = M2C_FIELD((void *)0x8297D248, s32 *, 0x80);
            goto write_value;
        }
        goto set_error;
        goto update_size;
    case 6:
        if ((u32) *out_size >= 4U) {
            field_value = M2C_FIELD((void *)0x8297D248, s32 *, 0x44);
            goto write_value;
        }
        goto set_error;
        goto update_size;
    default:
        if ((u32) *out_size >= 4U) {
            field_value = M2C_FIELD((void *)0x8297D248, s32 *, 0x48);
            goto write_value;
        }
        goto set_error;
        goto update_size;
    }
    unlock_config(0x8297D2D4);
    finalize_property(status);
}

// --- Ghidra ---

void test_16(undefined8 unused_param, uint *out_value, uint *io_size)
{
    uint buf_size;
    int property_id;
    uint field_value;

    property_id = func_0x82696f38();
    func_0x82960c04(0xffffffff8297d2d4);
    if (0x1000 < property_id) {
        if (property_id - 0x1003U < 8) {
            if (property_id == 0x1004) {
                if (3 < *io_size) {
                    field_value = (uint)uRam8297d280;
                    goto LAB_write_value;
                }
            }
            else if (property_id == 0x1005) {
                if (3 < *io_size) {
                    field_value = (uint)uRam8297d282;
                    goto LAB_write_value;
                }
            }
            else {
                if (property_id != 0x1006) {
                    if (property_id == 0x1007) {
                        buf_size = *io_size;
                        field_value = uRam8297d2ac;
                    }
                    else if (property_id == 0x1008) {
                        buf_size = *io_size;
                        field_value = uRam8297d2c8;
                    }
                    else if (property_id == 0x1009) {
                        buf_size = *io_size;
                        field_value = uRam8297d28c;
                    }
                    else if (property_id == 0x1003) {
                        buf_size = *io_size;
                        field_value = uRam8297d278;
                    }
                    else {
                        buf_size = *io_size;
                        field_value = uRam8297d290;
                    }
                    goto joined_size_check;
                }
                if (3 < *io_size) {
                    field_value = (uint)uRam8297d284;
                    goto LAB_write_value;
                }
            }
            goto LAB_update_size;
        }
LAB_unknown_prop:
        goto LAB_unlock;
    }
    if (property_id == 0x1000) {
        buf_size = *io_size;
        field_value = uRam8297d2a8;
        goto joined_size_check;
    }
    switch (property_id + -1) {
    case 0:
        buf_size = *io_size;
        field_value = uRam8297d294;
        break;
    case 1:
        buf_size = *io_size;
        field_value = uRam8297d298;
        goto joined_size_check;
    case 2:
        buf_size = *io_size;
        field_value = uRam8297d29c;
joined_size_check:
        if (buf_size < 4) goto LAB_update_size;
        goto LAB_write_value;
    case 3:
        buf_size = *io_size;
        field_value = uRam8297d248;
        break;
    case 4:
        buf_size = *io_size;
        field_value = uRam8297d2a0;
        break;
    case 5:
        buf_size = *io_size;
        field_value = uRam8297d2a4;
        break;
    case 6:
        buf_size = *io_size;
        field_value = uRam8297d2b0;
        break;
    case 7:
        buf_size = *io_size;
        field_value = uRam8297d2b4;
        break;
    case 8:
        buf_size = *io_size;
        field_value = uRam8297d254;
        break;
    case 9:
        if (*io_size < 4) goto LAB_update_size;
        field_value = (uint)uRam8297d2bc;
        goto LAB_write_value;
    case 10:
        if (3 < *io_size) {
            field_value = (uint)uRam8297d2be;
            goto LAB_write_value;
        }
        goto LAB_update_size;
    case 0xb:
        if (3 < *io_size) {
            field_value = (uint)uRam8297d2c0;
            goto LAB_write_value;
        }
        goto LAB_update_size;
    case 0xc:
        if (3 < *io_size) {
            field_value = (uint)uRam8297d2c2;
            goto LAB_write_value;
        }
        goto LAB_update_size;
    case 0xd:
        buf_size = *io_size;
        field_value = uRam8297d258;
        break;
    case 0xe:
        buf_size = *io_size;
        field_value = uRam8297d2b8;
        break;
    case 0xf:
        buf_size = *io_size;
        field_value = uRam8297d260;
        break;
    case 0x10:
        buf_size = *io_size;
        field_value = uRam8297d264;
        break;
    case 0x11:
        buf_size = *io_size;
        field_value = uRam8297d24c;
        break;
    case 0x12:
        buf_size = *io_size;
        field_value = uRam8297d250;
        break;
    case 0x13:
        buf_size = *io_size;
        field_value = uRam8297d268;
        break;
    case 0x14:
        buf_size = *io_size;
        field_value = uRam8297d2c4;
        break;
    case 0x15:
        buf_size = *io_size;
        field_value = uRam8297d25c;
        break;
    case 0x16:
        buf_size = *io_size;
        field_value = uRam8297d26c;
        break;
    case 0x17:
        buf_size = *io_size;
        field_value = uRam8297d270;
        break;
    case 0x18:
        buf_size = *io_size;
        field_value = uRam8297d274;
        break;
    default:
        goto LAB_unknown_prop;
    case 0x1a:
        buf_size = *io_size;
        field_value = uRam8297d27c;
        break;
    case 0x1b:
        buf_size = *io_size;
        field_value = uRam8297d288;
    }
    if (3 < buf_size) {
LAB_write_value:
        *out_value = field_value;
    }
LAB_update_size:
    *io_size = 4;
LAB_unlock:
    func_0x82960c14(0xffffffff8297d2d4);
    halt_baddata();
}


// ============================================================================
// Test 17: Factory function - allocates and initializes an object based on type index
// ============================================================================

// --- m2c ---

u32 test_17(u32 type_index) {
    if (type_index <= 0x1DU) {
        return type_index;
    }
    return 0U;
}

// --- Ghidra ---

undefined4 * test_17(undefined4 type_index)
{
    undefined4 *obj;
    undefined4 vtable_addr;
    undefined4 obj_type;

    switch (type_index) {
    case 0:
        obj = (undefined4 *)func_0x822c4330(0x20, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        obj[1] = 0xff7fffff;
        obj[2] = 0xff7fffff;
        obj[4] = 0;
        *obj = 0x820985bc;
        obj[5] = 0;
        obj[6] = 0x14;
        obj[7] = 0x14;
        obj[3] = 0;
        return obj;
    case 1:
        obj = (undefined4 *)func_0x822c4330(0x20, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        obj[1] = 0xff7fffff;
        obj[2] = 0xff7fffff;
        vtable_addr = 0x820985d0;
        obj_type = 1;
        goto init_standard;
    case 2:
        obj = (undefined4 *)func_0x822c4330(0x20, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        obj[1] = 0xff7fffff;
        obj[2] = 0xff7fffff;
        vtable_addr = 0x820985e4;
        obj_type = 2;
        goto init_standard;
    case 3:
        obj = (undefined4 *)func_0x822c4330(0x24, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        obj[1] = 0xff7fffff;
        obj[2] = 0xff7fffff;
        vtable_addr = 0x820985f8;
        obj_type = 3;
        goto init_extended;
    case 4:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x8209860c;
        obj[1] = 0xff7fffff;
        obj_type = 4;
        obj[2] = 0xff7fffff;
        break;
    case 5:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x82098620;
        obj[1] = 0xff7fffff;
        obj_type = 5;
        obj[2] = 0xff7fffff;
        break;
    case 6:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x82098698;
        obj[1] = 0xff7fffff;
        obj_type = 6;
        obj[2] = 0xff7fffff;
        break;
    case 7:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x820986ac;
        obj[1] = 0xff7fffff;
        obj_type = 7;
        obj[2] = 0xff7fffff;
        break;
    case 8:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x820986c0;
        obj[1] = 0xff7fffff;
        obj_type = 8;
        obj[2] = 0xff7fffff;
        break;
    case 9:
        obj = (undefined4 *)func_0x822c4330(0x24, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        obj[1] = 0xff7fffff;
        obj[2] = 0xff7fffff;
        vtable_addr = 0x82098710;
        obj_type = 9;
        goto init_extended;
    case 10:
        obj = (undefined4 *)func_0x822c4330(0x24, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        obj[1] = 0xff7fffff;
        obj[2] = 0xff7fffff;
        vtable_addr = 0x82098724;
        obj_type = 10;
init_extended:
        obj[8] = 0x14;
        goto init_standard;
    case 0xb:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x82098738;
        obj[1] = 0xff7fffff;
        obj_type = 0xb;
        obj[2] = 0xff7fffff;
        break;
    case 0xc:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x8209874c;
        obj[1] = 0xff7fffff;
        obj_type = 0xc;
        obj[2] = 0xff7fffff;
        break;
    case 0xd:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x82098760;
        obj[1] = 0xff7fffff;
        obj_type = 0xd;
        obj[2] = 0xff7fffff;
        break;
    case 0xe:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x82098774;
        obj[1] = 0xff7fffff;
        obj_type = 0xe;
        obj[2] = 0xff7fffff;
        break;
    case 0xf:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x82098788;
        obj[1] = 0xff7fffff;
        obj_type = 0xf;
        obj[2] = 0xff7fffff;
        break;
    case 0x10:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x8209879c;
        obj[1] = 0xff7fffff;
        obj_type = 0x10;
        obj[2] = 0xff7fffff;
        break;
    case 0x11:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x820987b0;
        obj[1] = 0xff7fffff;
        obj_type = 0x11;
        obj[2] = 0xff7fffff;
        break;
    case 0x12:
        obj = (undefined4 *)func_0x822c4330(0x20, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        obj[1] = 0xff7fffff;
        obj[2] = 0xff7fffff;
        vtable_addr = 0x820987c4;
        obj_type = 0x12;
        goto init_standard;
    case 0x13:
        obj = (undefined4 *)func_0x822c4330(0x20, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        obj[1] = 0xff7fffff;
        obj[2] = 0xff7fffff;
        vtable_addr = 0x820987d8;
        obj_type = 0x13;
        goto init_standard;
    case 0x14:
        obj = (undefined4 *)func_0x822c4330(0x20, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        obj[1] = 0xff7fffff;
        obj[2] = 0xff7fffff;
        obj[4] = 0;
        obj[5] = 0;
        *obj = 0x820987ec;
        obj[6] = 0x14;
        obj[7] = 0x14;
        obj[3] = 0x14;
        return obj;
    case 0x15:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x820986d4;
        obj[1] = 0xff7fffff;
        obj_type = 0x15;
        obj[2] = 0xff7fffff;
        break;
    case 0x16:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x820986e8;
        obj[1] = 0xff7fffff;
        obj_type = 0x16;
        obj[2] = 0xff7fffff;
        break;
    case 0x17:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x820986fc;
        obj[1] = 0xff7fffff;
        obj_type = 0x17;
        obj[2] = 0xff7fffff;
        break;
    case 0x18:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x82098634;
        obj[1] = 0xff7fffff;
        obj_type = 0x18;
        obj[2] = 0xff7fffff;
        break;
    case 0x19:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x82098648;
        obj[1] = 0xff7fffff;
        obj_type = 0x19;
        obj[2] = 0xff7fffff;
        break;
    case 0x1a:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x8209865c;
        obj[1] = 0xff7fffff;
        obj_type = 0x1a;
        obj[2] = 0xff7fffff;
        break;
    case 0x1b:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x82098670;
        obj[1] = 0xff7fffff;
        obj_type = 0x1b;
        obj[2] = 0xff7fffff;
        break;
    case 0x1c:
        obj = (undefined4 *)func_0x822c4330(0x1c, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        vtable_addr = 0x82098684;
        obj[1] = 0xff7fffff;
        obj_type = 0x1c;
        obj[2] = 0xff7fffff;
        break;
    case 0x1d:
        obj = (undefined4 *)func_0x822c4330(0x20, 0x209c0000);
        if (obj == (undefined4 *)0x0) {
            return (undefined4 *)0x0;
        }
        obj[1] = 0xff7fffff;
        obj[2] = 0xff7fffff;
        vtable_addr = 0x82098800;
        obj_type = 0x1d;
init_standard:
        obj[4] = 0;
        obj[5] = 0;
        *obj = vtable_addr;
        obj[6] = 0x14;
        obj[7] = 0x14;
        goto set_type;
    default:
        return (undefined4 *)0x0;
    }
    obj[4] = 0;
    obj[5] = 0;
    *obj = vtable_addr;
    obj[6] = 0x14;
set_type:
    obj[3] = obj_type;
    return obj;
}


// ============================================================================
// Test 18: Inflate/decompress state machine - processes compressed stream into output buffer
// ============================================================================

// --- m2c ---

void *get_stream_state();                              /* extern: func_8258DFB8 */
void flush_output(void *, u32, s32);                   /* extern: func_825F06E8 */

void test_18(void) {
    s32 delta;
    s32 saved_pos;
    u32 write_pos;
    u32 pending_size;
    void *state;
    void *state_ret;

    state_ret = get_stream_state();
    state = state_ret;
    pending_size = (u32) (u64) state_ret;
    write_pos = M2C_FIELD(state, u32 *, 0x34);
    saved_pos = M2C_FIELD(pending_size, s32 *, 0);
    if (write_pos < (u32) M2C_FIELD(state, u32 *, 0x30)) {

    }
    if ((u32) M2C_FIELD(state, u32 *, 0) <= 9U) {
        return;
    }
    M2C_FIELD(state, s32 *, 0x20) = (s32) M2C_FIELD(state, s32 *, 0x20);
    M2C_FIELD(state, s32 *, 0x1C) = (s32) M2C_FIELD(state, s32 *, 0x1C);
    M2C_FIELD(pending_size, s32 *, 4) = (s32) M2C_FIELD(pending_size, s32 *, 4);
    delta = saved_pos - M2C_FIELD(pending_size, s32 *, 0);
    M2C_FIELD(pending_size, s32 *, 0) = saved_pos;
    M2C_FIELD(pending_size, s32 *, 8) = (s32) (delta + M2C_FIELD(pending_size, s32 *, 8));
    M2C_FIELD(state, u32 *, 0x34) = write_pos;
    flush_output(state, pending_size, -2);
}

// --- Ghidra ---

void test_18(undefined8 unused_param1, undefined8 unused_param2, longlong flush_mode)
{
    byte cur_byte;
    byte extra_byte;
    uint *state;
    longlong build_result;
    uint avail_out;
    int *stream;
    uint bits_held;
    undefined4 error_code;
    uint copy_count;
    uint code_index;
    ulonglong bit_buffer;
    uint bits_available;
    uint state_val;
    uint avail_in;
    ulonglong decoded_sym;
    uint bits_in_buffer;
    byte *input_ptr;
    undefined4 saved_hold_lo;
    undefined4 saved_bits;
    undefined4 saved_buf_hi;
    undefined4 saved_buf_lo;
    undefined4 saved_avail;
    undefined4 saved_mode;
    undefined4 saved_state;
    undefined4 work_area [37];

    state = (uint *)func_0x8258dfb8();
    write_pos = state[0xd];
    stream = (int *)unused_param2;
    input_ptr = (byte *)*stream;
    avail_in = stream[1];
    bit_buffer_lo = state[8];
    bit_buffer = (ulonglong)bit_buffer_lo;
    bits_in_buffer = state[7];
    if (write_pos < state[0xc]) {
        avail_out = (state[0xc] - write_pos) - 1;
    }
    else {
        avail_out = state[0xb] - write_pos;
    }
    state_val = *state;
    while (state_val < 10) {
        bit_buffer_lo = (uint)bit_buffer;
        switch (state_val) {
        case 0:
            for (; bit_buffer_lo = (uint)bit_buffer, bits_in_buffer < 3; bits_in_buffer = bits_in_buffer + 8) {
                if (avail_in == 0) goto save_and_return;
                cur_byte = *input_ptr;
                flush_mode = 0;
                avail_in = avail_in - 1;
                input_ptr = input_ptr + 1;
                bit_buffer = (uint)cur_byte << (bits_in_buffer & 0x3f) | bit_buffer;
            }
            decoded_sym = ((bit_buffer & 7) << 0x20) >> 0x21;
            state[6] = (uint)(bit_buffer & 7) & 1;
            if (decoded_sym == 0) {
                *state = 1;
                code_index = bits_in_buffer - 3 & 7;
                bits_in_buffer = (bits_in_buffer - 3) - code_index;
                bit_buffer = (ulonglong)((bit_buffer_lo >> 3) >> code_index);
            }
            else if (decoded_sym == 1) {
                func_0x825f06b8(&saved_state, &saved_avail, &saved_buf_lo, &saved_buf_hi, unused_param2);
                code_index = func_0x825ef8e8(saved_state, saved_avail, saved_buf_lo, saved_buf_hi, unused_param2);
                state[1] = code_index;
                if (code_index == 0) goto alloc_failure;
                bit_buffer = (bit_buffer << 0x20) >> 0x23;
                *state = 6;
                bits_in_buffer = bits_in_buffer - 3;
            }
            else {
                if (decoded_sym < 3) {
                    bit_buffer = (bit_buffer << 0x20) >> 0x23;
                    bits_in_buffer = bits_in_buffer - 3;
                    bit_buffer_lo = 3;
                    goto set_state;
                }
                if (decoded_sym == 3) {
                    *state = 9;
                    flush_mode = -3;
                    stream[6] = -0x7dfbc184;
                    state[8] = bit_buffer_lo >> 3;
                    state[7] = bits_in_buffer - 3;
                    goto save_stream;
                }
            }
            break;
        case 1:
            for (; bit_buffer_lo = (uint)bit_buffer, bits_in_buffer < 0x20; bits_in_buffer = bits_in_buffer + 8) {
                if (avail_in == 0) goto save_and_return;
                cur_byte = *input_ptr;
                flush_mode = 0;
                avail_in = avail_in - 1;
                input_ptr = input_ptr + 1;
                bit_buffer = (uint)cur_byte << (bits_in_buffer & 0x3f) | bit_buffer;
            }
            decoded_sym = bit_buffer & 0xffff;
            if ((~bit_buffer << 0x20) >> 0x30 != decoded_sym) {
                error_code = -0x7dfbc170;
set_error_state:
                *state = 9;
                stream[6] = error_code;
                goto save_bits_and_stream;
            }
            state[1] = (uint)decoded_sym;
            bits_in_buffer = 0;
            bit_buffer = 0;
            if (decoded_sym == 0) goto check_final;
            bit_buffer_lo = 2;
set_state:
            *state = bit_buffer_lo;
            break;
        case 2:
            if (avail_in == 0) {
save_and_return:
                state[8] = bit_buffer_lo;
                state[7] = bits_in_buffer;
                stream[1] = 0;
                goto save_input_ptr;
            }
            if (avail_out == 0) {
                if (write_pos == state[0xb]) {
                    avail_out = state[0xc];
                    code_index = state[10];
                    if (avail_out != code_index) {
                        if (code_index < avail_out) {
                            avail_out = (avail_out - code_index) - 1;
                        }
                        else {
                            avail_out = state[0xb] - code_index;
                        }
                        write_pos = code_index;
                        if (avail_out != 0) goto do_copy;
                    }
                }
                state[0xd] = write_pos;
                flush_mode = func_0x825f06e8(state, unused_param2, flush_mode);
                write_pos = state[0xd];
                code_index = state[0xc];
                if (write_pos < code_index) {
                    avail_out = (code_index - write_pos) - 1;
                }
                else {
                    avail_out = state[0xb] - write_pos;
                }
                if ((write_pos == state[0xb]) && (bits_held = state[10], code_index != bits_held)) {
                    write_pos = bits_held;
                    if (bits_held < code_index) {
                        avail_out = (code_index - bits_held) - 1;
                    }
                    else {
                        avail_out = state[0xb] - bits_held;
                    }
                }
                if (avail_out == 0) goto finalize_output;
            }
do_copy:
            flush_mode = 0;
            copy_count = state[1];
            if (avail_in < state[1]) {
                copy_count = avail_in;
            }
            if (avail_out < copy_count) {
                copy_count = avail_out;
            }
            func_0x8258e090(write_pos, input_ptr, copy_count);
            code_index = state[1];
            input_ptr = input_ptr + copy_count;
            avail_in = avail_in - copy_count;
            write_pos = copy_count + write_pos;
            avail_out = avail_out - copy_count;
            state[1] = code_index - copy_count;
            if (code_index - copy_count == 0) {
check_final:
                bit_buffer_lo = -(uint)(state[6] != 0) & 7;
                goto set_state;
            }
            break;
        case 3:
            for (; bit_buffer_lo = (uint)bit_buffer, bits_in_buffer < 0xe; bits_in_buffer = bits_in_buffer + 8) {
                if (avail_in == 0) goto save_and_return;
                cur_byte = *input_ptr;
                flush_mode = 0;
                avail_in = avail_in - 1;
                input_ptr = input_ptr + 1;
                bit_buffer = (uint)cur_byte << (bits_in_buffer & 0x3f) | bit_buffer;
            }
            state[1] = (uint)(bit_buffer & 0x3fff);
            if ((0x1d < (bit_buffer & 0x1f)) ||
               (decoded_sym = ((bit_buffer & 0x3fff) << 0x20) >> 0x25 & 0x1f, 0x1d < decoded_sym)) {
                error_code = -0x7dfbc150;
                goto set_error_state;
            }
            avail_out = (*(code *)stream[8])(stream[10], decoded_sym + (bit_buffer & 0x1f) + 0x102, 4);
            state[3] = avail_out;
            if (avail_out != 0) {
                state[2] = 0;
                bit_buffer = (bit_buffer << 0x20) >> 0x2e;
                bits_in_buffer = bits_in_buffer - 0xe;
                *state = 4;
                goto decode_code_lengths;
            }
            goto alloc_failure;
        case 4:
decode_code_lengths:
            while (bit_buffer_lo = (uint)bit_buffer, state[2] < (state[1] >> 10) + 4) {
                for (; bit_buffer_lo = (uint)bit_buffer, bits_in_buffer < 3; bits_in_buffer = bits_in_buffer + 8) {
                    if (avail_in == 0) goto save_and_return;
                    cur_byte = *input_ptr;
                    flush_mode = 0;
                    avail_in = avail_in - 1;
                    input_ptr = input_ptr + 1;
                    bit_buffer = (uint)cur_byte << (bits_in_buffer & 0x3f) | bit_buffer;
                }
                bit_buffer = (bit_buffer << 0x20) >> 0x23;
                bits_in_buffer = bits_in_buffer - 3;
                *(uint *)(*(int *)(state[2] * 4 + -0x7dfee740) * 4 + state[3]) = bit_buffer_lo & 7;
                state[2] = state[2] + 1;
            }
            while (state[2] < 0x13) {
                *(undefined4 *)(*(int *)(state[2] * 4 + -0x7dfee740) * 4 + state[3]) = 0;
                state[2] = state[2] + 1;
            }
            state[4] = 7;
            build_result = func_0x825f0418(state[3], state + 4, state + 5, state[9], unused_param2);
            if (build_result == 0) {
                state[2] = 0;
                *state = 5;
                goto decode_lit_dist;
            }
            error_code = (int)build_result;
            flush_mode = build_result;
check_fatal_error:
            if (error_code == -3) {
                (*(code *)stream[9])(stream[10], state[3]);
                *state = 9;
            }
            goto finalize_output;
        case 5:
decode_lit_dist:
            while (bit_buffer_lo = (uint)bit_buffer, state[2] < (state[1] >> 5 & 0x1f) + (state[1] & 0x1f) + 0x102
                  ) {
                for (; bit_buffer_lo = (uint)bit_buffer, bits_in_buffer < state[4]; bits_in_buffer = bits_in_buffer + 8) {
                    if (avail_in == 0) goto save_and_return;
                    cur_byte = *input_ptr;
                    flush_mode = 0;
                    avail_in = avail_in - 1;
                    input_ptr = input_ptr + 1;
                    bit_buffer = (uint)cur_byte << (bits_in_buffer & 0x3f) | bit_buffer;
                }
                error_code = (int)((*(uint *)(state[4] * 4 + -0x7dfed3b8) & bit_buffer) << 3) + state[5];
                avail_out = *(uint *)(error_code + 4);
                cur_byte = *(byte *)(error_code + 1);
                code_index = (uint)cur_byte;
                if (avail_out < 0x10) {
                    bits_in_buffer = bits_in_buffer - code_index;
                    bit_buffer = (ulonglong)(bit_buffer_lo >> (cur_byte & 0x3f));
                    *(uint *)(state[2] * 4 + state[3]) = avail_out;
                    state[2] = state[2] + 1;
                }
                else {
                    if (avail_out == 0x12) {
                        bits_held = 7;
                        build_result = 0xb;
                    }
                    else {
                        bits_held = avail_out - 0xe;
                        build_result = 3;
                    }
                    for (; bit_buffer_lo = (uint)bit_buffer, bits_in_buffer < bits_held + code_index; bits_in_buffer = bits_in_buffer + 8) {
                        if (avail_in == 0) goto save_and_return;
                        extra_byte = *input_ptr;
                        flush_mode = 0;
                        avail_in = avail_in - 1;
                        input_ptr = input_ptr + 1;
                        bit_buffer = (uint)extra_byte << (bits_in_buffer & 0x3f) | bit_buffer;
                    }
                    bits_in_buffer = (bits_in_buffer - bits_held) - code_index;
                    bit_buffer_lo = bit_buffer_lo >> (cur_byte & 0x3f);
                    build_result = (ulonglong)(*(uint *)(bits_held * 4 + -0x7dfed3b8) & bit_buffer_lo) + build_result;
                    bit_buffer_lo = bit_buffer_lo >> (bits_held & 0x3f);
                    bit_buffer = (ulonglong)bit_buffer_lo;
                    code_index = state[2];
                    decoded_sym = (ulonglong)code_index;
                    if (((ulonglong)(state[1] >> 5) & 0x1f) + ((ulonglong)state[1] & 0x1f) + 0x102 <
                        (build_result + decoded_sym & 0xffffffff)) {
free_and_error:
                        (*(code *)stream[9])(stream[10], state[3]);
                        error_code = -0x7dfbc12c;
                        goto set_error_state;
                    }
                    if (avail_out == 0x10) {
                        if (decoded_sym == 0) goto free_and_error;
                        saved_hold_lo = *(undefined4 *)(code_index * 4 + state[3] + -4);
                    }
                    else {
                        saved_hold_lo = 0;
                    }
                    error_code = code_index << 2;
                    do {
                        build_result = build_result + -1;
                        decoded_sym = decoded_sym + 1;
                        *(undefined4 *)(state[3] + error_code) = saved_hold_lo;
                        error_code = error_code + 4;
                    } while (build_result != 0);
                    state[2] = (uint)decoded_sym;
                }
            }
            state[5] = 0;
            saved_bits = 9;
            saved_hold_lo = 6;
            build_result = func_0x825f04f8((state[1] & 0x1f) + 0x101, (state[1] >> 5 & 0x1f) + 1, state[3],
                                           &saved_bits, &saved_hold_lo, work_area, &saved_state, state[9]);
            if (build_result != 0) {
                error_code = (int)build_result;
                flush_mode = build_result;
                goto check_fatal_error;
            }
            avail_out = func_0x825ef8e8(saved_bits, saved_hold_lo, work_area[0], saved_state, unused_param2);
            if (avail_out != 0) {
                state[1] = avail_out;
                (*(code *)stream[9])(stream[10], state[3]);
                *state = 6;
                goto inflate_codes;
            }
alloc_failure:
            flush_mode = -4;
            goto finalize_output;
        case 6:
inflate_codes:
            state[8] = bit_buffer_lo;
            state[7] = bits_in_buffer;
            error_code = *stream;
            stream[1] = avail_in;
            *stream = (int)input_ptr;
            stream[2] = (int)(input_ptr + (stream[2] - error_code));
            state[0xd] = write_pos;
            flush_mode = func_0x825ef948(state, unused_param2, flush_mode);
            if ((int)flush_mode != 1) goto LAB_final_flush;
            flush_mode = 0;
            func_0x825eff88(state[1], unused_param2);
            write_pos = state[0xd];
            input_ptr = (byte *)*stream;
            avail_in = stream[1];
            bit_buffer_lo = state[8];
            bit_buffer = (ulonglong)bit_buffer_lo;
            bits_in_buffer = state[7];
            if (write_pos < state[0xc]) {
                avail_out = (state[0xc] - write_pos) - 1;
            }
            else {
                avail_out = state[0xb] - write_pos;
            }
            if (state[6] != 0) {
                *state = 7;
                goto check_window_wrap;
            }
            *state = 0;
            break;
        case 7:
check_window_wrap:
            state[0xd] = write_pos;
            flush_mode = func_0x825f06e8(state, unused_param2, flush_mode);
            write_pos = state[0xd];
            if (state[0xc] == write_pos) {
                *state = 8;
                goto inflate_done;
            }
            goto finalize_output;
        case 8:
inflate_done:
            flush_mode = 1;
            goto finalize_output;
        case 9:
save_bits_and_stream:
            flush_mode = -3;
            goto finalize_output;
        }
        bit_buffer_lo = (uint)bit_buffer;
        state_val = *state;
    }
    flush_mode = -2;
finalize_output:
    state[8] = bit_buffer_lo;
    state[7] = bits_in_buffer;
save_stream:
    stream[1] = avail_in;
save_input_ptr:
    error_code = *stream;
    *stream = (int)input_ptr;
    stream[2] = (int)(input_ptr + (stream[2] - error_code));
    state[0xd] = write_pos;
LAB_final_flush:
    func_0x825f06e8(state, unused_param2, flush_mode);
    halt_baddata();
}


// ============================================================================
// Test 19: Virtual method dispatch trampoline - calls setup then dispatches via vtable
// ============================================================================

// --- m2c ---

void setup_dispatch(s32, s32, s32);                    /* extern: func_8214BC60 */

void test_19(s32 self, s32 method_offset, s32 arg, s32 spill_self, s32 spill_offset, s32 spill_arg) {
    spill_self = self;
    spill_offset = method_offset;
    spill_arg = arg;
    setup_dispatch(spill_self, spill_offset, spill_arg);
    *(spill_self + 0x40 + spill_offset)(spill_self, spill_arg);
}

// --- Ghidra ---

void test_19(int self, int method_offset, undefined4 arg)
{
    int spill_self;
    int spill_offset;
    undefined4 spill_arg;

    spill_self = self;
    spill_offset = method_offset;
    spill_arg = arg;
    func_0x8214bc60(self, method_offset, arg);
    (**(code **)(spill_self + 0x40 + spill_offset))(spill_self, spill_arg);
    return;
}
