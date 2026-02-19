// ============================================================================
// Test 0: test_0
// ============================================================================

s32 test_0(void) {
    return 0;
}

// ============================================================================
// Test 1: test_1
// ============================================================================

void *test_1(void *arg0) {
    s64 temp_r11;                                   /* artifact */

    if ((u32) M2C_FIELD(arg0, u32 *, 4) != 0U) {
        unksp-20 = M2C_FIELD(arg0, s64 *, 0x10);
        temp_r11 = M2C_FIELD(arg0, s64 *, 0);
        unksp-18 = temp_r11;
        unksp-10 = temp_r11;
        if ((s32) unksp-20 > 0) {
            return (void *) unksp-18;
        }
    }
    return arg0;
}

// ============================================================================
// Test 2: test_2
// ============================================================================

M2C_UNK func_8368D180();                            /* extern */
M2C_UNK func_839102E0(M2C_UNK, M2C_UNK);            /* extern */
M2C_UNK func_83910388(M2C_UNK);                     /* extern */

void *test_2(void *arg0, f32 *arg2, f32 farg0) {
    if ((u32) M2C_FIELD(arg0, u32 *, 0xA68) <= 3U) {
        return arg0;
    }
    func_83910388(0x8202B674);
    func_839102E0(0x8202B628, 0x15F);
    func_8368D180();
    *arg2 = farg0;
    return NULL;
}

// ============================================================================
// Test 3: test_3
// ============================================================================

void test_3(s32 arg1, s32 arg2, s32 arg4, f32 farg0) {
    s32 var_r11;                                    /* artifact */

    unksp-20 = farg0;
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
    if (arg1 >= 1) {
        M2C_ERROR(/* unknown instruction: vspltisw $v9, 0x0 */);
        var_r11 = arg1;
        do {
            M2C_ERROR(/* unknown instruction: vaddfp $v8, $v11, $v0 */);
            var_r11 -= 1;
            M2C_ERROR(/* unknown instruction: vrefp $v13, $v8 */);
        } while (var_r11 != 0);
    }
    if ((u32) arg1 <= 3U) {
        return;
    }
    *(M2C_ERROR(/* Read from unset register $r0 */) + arg4) = M2C_BITWISE(f128, M2C_ERROR(/* unknown instruction: vxor $v0, $v0, $v0 */));
}

// ============================================================================
// Test 4: test_4
// ============================================================================

u32 func_82960854();                                /* extern */
s32 func_82960D34(M2C_UNK, M2C_UNK, u8 *, M2C_UNK, s16 *); /* extern */

s32 test_4(void) {
    s16 sp52;
    u8 sp50;
    s32 temp_r3;                                    /* artifact */
    u32 temp_r3_2;                                  /* artifact */
    u8 temp_r11;                                    /* artifact */
    u8 var_r11;                                     /* artifact */

    sp52 = 0;
    temp_r3 = func_82960D34(3, 0xE, &sp50, 1, &sp52);
    if ((temp_r3 >= 0) && (sp50 <= 0x6EU) && ((void *) (sp50 - 5) <= 0x68U)) {
        return temp_r3;
    }
    var_r11 = 0;
    if ((0 == 0) || (0U > 0x25U)) {
        temp_r3_2 = func_82960854();
        temp_r11 = (u8) (temp_r3_2 >> 8U);
        if (temp_r11 == 1) {
            var_r11 = ((((temp_r3_2 - 0x101) == 0) & 1) ^ 1) + 0x14;
        } else {
            var_r11 = ((((temp_r11 - 2) == 0) & 1) ^ 1) + 0x23;
        }
    }
    return (s32) var_r11;
}

// ============================================================================
// Test 5: 
// ============================================================================

M2C_UNK func_830B1EC0(s32 *);                       /* extern */
M2C_UNK func_830B1ED8(s32 *);                       /* extern */
s32 func_830B1F28(s32 *);                           /* extern */
u32 func_830B1F80(s32 *);                           /* extern */
f32 func_830B1F98(s32 *, M2C_UNK);                  /* extern */
f32 func_830B6ED8();                                /* extern */
f32 func_830B72F8(s32);                             /* extern */

f32 test_5(void ***arg1) {
    s32 sp50;
    f32 temp_f1;                                    /* artifact */
    f32 temp_f31;                                   /* artifact */
    f32 var_f31;                                    /* artifact */
    s32 temp_r31;                                   /* artifact */

    func_830B1EC0(&sp50);
    sp50 = 0x8202C418;
    temp_f1 = func_830B1F98(&sp50, 0);
    if ((void *) **arg1 <= 0x1BU) {
        return temp_f1;
    }
    if (func_830B1F80(&sp50) != 0U) {
        temp_r31 = func_830B1F28(&sp50);
        func_830B1F28(&sp50);
        temp_f31 = func_830B6ED8();
        var_f31 = temp_f31 * func_830B72F8(temp_r31);
    } else {
        var_f31 = *(f32 *)0x8200D72C;
    }
    func_830B1ED8(&sp50);
    return var_f31;
}

// ============================================================================
// Test 6: test_6
// ============================================================================

u32 func_8214C430(M2C_UNK, M2C_UNK, M2C_UNK);       /* extern */
void *func_82278B30();                              /* extern */

u32 test_6(u32 arg_sp50) {
    u32 temp_r11;                                   /* artifact */
    u32 temp_r11_2;                                 /* artifact */
    u32 var_r10;                                    /* artifact */
    u32 var_r16;                                    /* artifact */
    u32 var_r17;                                    /* artifact */
    u32 var_r3;                                     /* artifact */
    u32 var_r4;                                     /* artifact */
    void *temp_r3;                                  /* artifact */
    void *var_r11;                                  /* artifact */
    void *var_r29;                                  /* artifact */

    temp_r3 = func_82278B30();
    temp_r11 = M2C_FIELD(temp_r3, u32 *, 0x18);
    var_r4 = 0U;
    var_r29 = temp_r3 + 0x34;
    var_r17 = 0U;
    arg_sp50 = 0U;
    if (temp_r11 != 0U) {
        var_r16 = temp_r11;
        var_r3 = 0x82000000U;
loop_2:
        if ((u16) M2C_FIELD(var_r29, u16 *, 0) != 0) {
            var_r3 = func_8214C430(0x82002AE0, 0x82004700);
        }
        if ((u8) M2C_FIELD(var_r29, u8 *, 9) <= 0xAU) {
            return var_r3;
        }
        var_r3 = func_8214C430(0x82004840);
        var_r16 -= 1;
        var_r29 += 0xC;
        if (var_r16 == 0U) {
            var_r4 = arg_sp50;
            goto block_46;
        }
        goto loop_2;
    }
block_46:
    var_r10 = 0U;
    var_r11 = (void *)0x820043E8;
loop_47:
    if (((u32) M2C_FIELD(var_r11, u32 *, 0) != var_r4) || ((u32) M2C_FIELD(var_r11, u32 *, 4) != 0U) || ((u32) M2C_FIELD(var_r11, u32 *, 8) != 0U)) {
        var_r10 += 0x10;
        var_r11 += 0x10;
        if (var_r10 >= 0x110U) {
            goto block_51;
        }
        goto loop_47;
    }
    temp_r11_2 = M2C_FIELD(var_r11, u32 *, 0xC);
    if (temp_r11_2 != 0U) {
        var_r17 = temp_r11_2;
    } else {
block_51:
        func_8214C430(0x82004688, 0, 0);
    }
    return var_r17;
}

// ============================================================================
// Test 7: 
// ============================================================================

s32 func_82141160();                                /* extern */
M2C_UNK func_8214C430(M2C_UNK);                     /* extern */
M2C_UNK func_821553E0(s32 *);                       /* extern */

void test_7(s32 *arg0) {
    if (!(*arg0 & 0x100000)) {
        func_8214C430(0x82008D40);
    }
    if (func_82141160() == 2) {

    }
    if ((void *) ((*arg0 & 0xF) - 1) <= 0xBU) {
        return;
    }
    *arg0 = 0xF;
    func_821553E0(arg0);
}

// ============================================================================
// Test 8: 
// ============================================================================

void *func_82624B1C();                              /* extern */

void test_8(void) {
    if ((void *) M2C_FIELD(func_82624B1C(), void **, 0x54) <= 0xBU) {

    }
}

// ============================================================================
// Test 9: test_9
// ============================================================================

s32 *func_823A52F8(s32, s32 *);                     /* extern */
M2C_UNK func_82512998(s32 *, M2C_UNK);              /* extern */

s32 *test_9(s32 *arg0, u32 arg2, void *arg3) {
    s32 sp84;
    s32 sp64;
    s32 sp60;
    s32 sp5C;
    s32 sp58;
    s32 sp54;
    s32 sp50;
    s32 *temp_r11;                                  /* artifact */
    s32 *temp_r3;                                   /* artifact */
    s32 *temp_r4;                                   /* artifact */
    s32 var_r11;                                    /* artifact */

    *arg0 = *(s32 *)0x829FEAA8;
    if (arg2 >= 1U) {
        if (arg2 != 1U) {
            switch (arg2) {                         /* irregular */
            case 6:
                func_82512998(&sp50, 0x8204E6F4);
                var_r11 = sp50;
                goto block_32;
            case 5:
                func_82512998(&sp54, 0x8204E6C8);
                var_r11 = sp54;
                goto block_32;
            case 4:
                func_82512998(&sp58, 0x8204E6A8);
                var_r11 = sp58;
                goto block_32;
            case 3:
                func_82512998(&sp5C, 0x8204E68C);
                var_r11 = sp5C;
                goto block_32;
            default:
                func_82512998(&sp60, 0x8204E670);
                var_r11 = sp60;
                goto block_32;
            }
            /* Duplicate return node #33. Try simplifying control flow for better match */
            return arg0;
        }
        if (arg3 == NULL) {
            func_82512998(&sp64, 0x8204E650);
            var_r11 = sp64;
            goto block_32;
        }
        temp_r4 = M2C_FIELD(arg3, s32 **, 4);
        temp_r3 = func_823A52F8(*temp_r4 + 0x10, temp_r4);
        if ((void *) (temp_r3 - 1) <= 9U) {
            return temp_r3;
        }
        temp_r11 = M2C_FIELD(arg3, s32 **, 4);
        func_823A52F8(*temp_r11 + 0x10, temp_r11);
        /* Duplicate return node #33. Try simplifying control flow for better match */
        return arg0;
    }
    func_82512998(&sp84, 0x8204E55C);
    var_r11 = sp84;
block_32:
    *arg0 = var_r11;
    return arg0;
}

// ============================================================================
// Test 10: 
// ============================================================================

M2C_UNK func_82515370(M2C_UNK *);                   /* extern */
M2C_UNK func_825156D8(M2C_UNK *, M2C_UNK);          /* extern */

void test_10(void *arg0) {
    M2C_UNK sp60;

    if ((void *) M2C_FIELD(arg0, void **, 4) <= 0x14U) {
        return;
    }
    func_825156D8(&sp60, 0x820C14E8);
    func_82515370(&sp60);
}

// ============================================================================
// Test 11: test_11
// ============================================================================

void *func_8248726C();                              /* extern */

void *test_11(void) {
    u32 *temp_r11;                                  /* artifact */
    void *temp_r3;                                  /* artifact */
    void *temp_ret;                                 /* artifact */

    temp_ret = func_8248726C();
    temp_r3 = temp_ret;
    if (temp_r3 != NULL) {
        temp_r11 = M2C_FIELD(temp_r3, u32 **, 0x1C);
        if ((temp_r11 != NULL) && ((u32) M2C_FIELD(temp_r3, u32 *, 0) != 0U)) {
            if ((s32) (u32) (u64) temp_ret != 4) {

            }
            if ((u32) *temp_r11 <= 0xDU) {
                return temp_r3;
            }
            goto block_33;
        }
    }
block_33:
    return (void *)-2U;
}

// ============================================================================
// Test 12: 
// ============================================================================

M2C_UNK func_822A7180(void *, void *, M2C_UNK, M2C_UNK); /* extern */
u32 func_822CD240(M2C_UNK, M2C_UNK);                /* extern */
void *func_822CD3A0(M2C_UNK, void *, M2C_UNK);      /* extern */
void *func_82487284();                              /* extern */
M2C_UNK func_82487ED0(s32 *, M2C_UNK, s32);         /* extern */

void test_12(s32 arg_sp50) {
    M2C_UNK var_r6;                                 /* artifact */
    s32 *var_r9;                                    /* artifact */
    s32 var_r10;                                    /* artifact */
    u32 temp_r30;                                   /* artifact */
    void *temp_r11;                                 /* artifact */
    void *temp_r31;                                 /* artifact */
    void *temp_ret;                                 /* artifact */
    void *var_r3;                                   /* artifact */

    temp_ret = func_82487284();
    temp_r30 = M2C_ERROR(/* Read from unset register $r5 */);
    temp_r31 = temp_ret;
    if (temp_r30 > 0x10U) {
        M2C_FIELD(temp_r31, s32 *, 0x44) = 1;
    }
    if ((s32) M2C_FIELD(temp_r31, s32 *, 0x44) == 0) {
        func_82487ED0(&(&arg_sp50)[temp_r30], 0, (0x10 - temp_r30) * 4);
        var_r10 = temp_r30 - 1;
        if (var_r10 >= 0) {
            var_r9 = &(&arg_sp50)[var_r10];
loop_5:
            temp_r11 = M2C_FIELD(temp_r31, void **, 0x5C);
            if (temp_r11 != NULL) {
                var_r10 -= 1;
                M2C_FIELD(temp_r31, void **, 0x5C) = (void *) M2C_FIELD(temp_r11, void **, 0xC);
                *var_r9 = M2C_FIELD(temp_r11, s32 *, 8);
                var_r9 -= 4;
                M2C_FIELD(temp_r11, s32 *, 8) = 0;
                M2C_FIELD(temp_r11, void **, 0xC) = (void *) M2C_FIELD(temp_r31, void **, 0x60);
                M2C_FIELD(temp_r31, void **, 0x60) = temp_r11;
                if (var_r10 < 0) {
                    goto block_7;
                }
                goto loop_5;
            }
            var_r6 = 0x8202C0F4;
            goto block_10;
        }
block_7:
        if ((u32) (u64) temp_ret <= 0x2EU) {
            return;
        }
        if ((s32) M2C_FIELD(temp_r31, s32 *, 0x44) == 0) {
            var_r3 = M2C_FIELD(temp_r31, void **, 0x60);
            if (var_r3 != NULL) {
                M2C_FIELD(temp_r31, void **, 0x60) = (void *) M2C_FIELD(var_r3, void **, 0xC);
                M2C_FIELD(var_r3, s32 *, 8) = 0;
                M2C_FIELD(var_r3, void **, 0xC) = (void *) M2C_FIELD(temp_r31, void **, 0x5C);
                goto block_70;
            }
            if (func_822CD240(0x14, 0x10) != 0U) {
                var_r3 = func_822CD3A0(0, M2C_FIELD(temp_r31, void **, 0x5C), 0x8202C0C0);
            } else {
                var_r3 = NULL;
            }
            if (var_r3 == NULL) {
                var_r6 = 0x8202C0A0;
block_10:
                func_822A7180(temp_r31 + 0x18, temp_r31 + 0x278, 0, var_r6);
                M2C_FIELD(temp_r31, s32 *, 0x44) = 1;
            } else {
block_70:
                M2C_FIELD(temp_r31, void **, 0x5C) = var_r3;
            }
        }
    }
}

// ============================================================================
// Test 13: 
// ============================================================================

M2C_UNK func_822A7180(s32, void *, M2C_UNK, M2C_UNK); /* extern */
u32 func_822CD240(M2C_UNK, M2C_UNK);                /* extern */
void *func_822CD3A0(M2C_UNK, void *, M2C_UNK);      /* extern */
void *func_82487288();                              /* extern */
M2C_UNK func_824872D8();                            /* extern */

void test_13(s32 arg_sp60) {
    s32 *var_r10;                                   /* artifact */
    s32 var_ctr;                                    /* artifact */
    void *temp_r11;                                 /* artifact */
    void *temp_r3;                                  /* artifact */
    void *temp_ret;                                 /* artifact */
    void *var_r3;                                   /* artifact */

    temp_ret = func_82487288();
    temp_r3 = temp_ret;
    if ((s32) M2C_FIELD(temp_r3, s32 *, 0x50) == 0) {
        var_ctr = M2C_ERROR(/* Read from unset register $r5 */);
        if ((u32) M2C_ERROR(/* Read from unset register $r5 */) != 0U) {
            var_r10 = &(&arg_sp60)[M2C_ERROR(/* Read from unset register $r5 */)];
loop_3:
            temp_r11 = M2C_FIELD(temp_r3, void **, 0x34);
            var_r10 -= 4;
            if (temp_r11 != NULL) {
                M2C_FIELD(temp_r3, void **, 0x34) = (void *) M2C_FIELD(temp_r11, void **, 0xC);
                *var_r10 = M2C_FIELD(temp_r11, s32 *, 8);
                M2C_FIELD(temp_r11, s32 *, 8) = 0;
                M2C_FIELD(temp_r11, void **, 0xC) = NULL;
                var_ctr -= 1;
                if (var_ctr == 0) {
                    goto block_5;
                }
                goto loop_3;
            }
            func_822A7180(M2C_FIELD(temp_r3, s32 *, 0), temp_r3 + 0x10, 0, 0x8202C0F4);
            M2C_FIELD(temp_r3, s32 *, 0x4C) = 1;
            /* Duplicate return node #108. Try simplifying control flow for better match */
            func_824872D8();
            return;
        }
block_5:
        if ((u32) (u64) temp_ret <= 0x3FU) {
            return;
        }
        if ((s32) M2C_FIELD(temp_r3, s32 *, 0x50) == 0) {
            if (func_822CD240(0x14, 0x10) != 0U) {
                var_r3 = func_822CD3A0(0, M2C_FIELD(temp_r3, void **, 0x34), 0x8202C0C0);
            } else {
                var_r3 = NULL;
            }
            if (var_r3 == NULL) {
                func_822A7180(M2C_FIELD(temp_r3, s32 *, 0), temp_r3 + 0x10, 0, 0x8202C0A0);
                M2C_FIELD(temp_r3, s32 *, 0x50) = 1;
                M2C_FIELD(temp_r3, s32 *, 0x4C) = 1;
            } else {
                M2C_FIELD(temp_r3, void **, 0x34) = var_r3;
            }
        }
        /* Duplicate return node #108. Try simplifying control flow for better match */
        func_824872D8();
        return;
    }
    func_824872D8();
}

// ============================================================================
// Test 14: 
// ============================================================================

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

s32 test_14(M2C_UNK arg_sp50, M2C_UNK arg_sp54, M2C_UNK arg_spA8, u32 arg_spAC, M2C_UNK arg_spC0, M2C_UNK arg_sp130, u32 arg_sp134) {
    f32 temp_f31;                                   /* artifact */
    s32 temp_r31;                                   /* artifact */
    s32 temp_r3;                                    /* artifact */
    s32 var_r3;                                     /* artifact */
    u32 temp_r11;                                   /* artifact */
    u32 temp_r27;                                   /* artifact */

    temp_r27 = (u32) func_831A8160();
    temp_r31 = func_83154600();
    func_82DF3A08(&arg_sp54, *(s32 *)0x83267658);
    temp_f31 = *(f32 *)0x820008A4;
    func_82BB2CB8(&arg_spA8, func_823053E8(temp_r31), &arg_sp54, temp_f31);
    if (arg_spAC != 0U) {
        func_822C0890();
    }
    func_82DF3428(&arg_sp54);
    func_82DF3A08(&arg_sp54, *(s32 *)0x83267C74);
    func_82BB2CB8(&arg_sp130, func_823053E8(temp_r31), &arg_sp54, temp_f31);
    if (arg_sp134 != 0U) {
        func_822C0890();
    }
    func_82DF3428(&arg_sp54);
    temp_r11 = *func_8250F4C8(&arg_spC0, func_82A13598(temp_r31));
    var_r3 = temp_r11 - 4;
    if (temp_r11 == 0U) {
        var_r3 = 0;
    }
    func_82E3FF08(&arg_sp50, *func_82508528(var_r3));
    temp_r3 = func_82DF1C90(&arg_spC0);
    if ((u32) M2C_FIELD(temp_r27, u32 *, 0x18) <= 7U) {
        return temp_r3;
    }
    return 1;
}

// ============================================================================
// Test 15: 
// ============================================================================

M2C_UNK func_825A1588(u32, M2C_UNK *, M2C_UNK);     /* extern */
M2C_UNK func_82DF3428(M2C_UNK *);                   /* extern */
M2C_UNK func_82DF3A08(M2C_UNK *, M2C_UNK);          /* extern */
u64 func_831A8144();                                /* extern */
M2C_UNK func_831A8194();                            /* extern */

void test_15(M2C_UNK arg_sp50) {
    u32 temp_r31;                                   /* artifact */
    u64 temp_r22;                                   /* artifact */
    u64 temp_ret;                                   /* artifact */

    temp_ret = func_831A8144();
    temp_r22 = temp_ret;
    temp_r31 = (u32) temp_ret;
    func_82DF3A08(&arg_sp50, 0x82024A98);
    func_825A1588(temp_r31, &arg_sp50, 0);
    func_82DF3428(&arg_sp50);
    func_82DF3A08(&arg_sp50, 0x8204132C);
    func_825A1588(temp_r31, &arg_sp50, 0);
    func_82DF3428(&arg_sp50);
    func_82DF3A08(&arg_sp50, 0x82041310);
    func_825A1588(temp_r31, &arg_sp50, 0);
    func_82DF3428(&arg_sp50);
    func_82DF3A08(&arg_sp50, 0x8203FD08);
    func_825A1588(temp_r31, &arg_sp50, 0);
    func_82DF3428(&arg_sp50);
    func_82DF3A08(&arg_sp50, 0x82044370);
    func_825A1588(temp_r31, &arg_sp50, 0);
    func_82DF3428(&arg_sp50);
    func_82DF3A08(&arg_sp50, 0x8204D2D0);
    func_825A1588(temp_r31, &arg_sp50, 0);
    func_82DF3428(&arg_sp50);
    func_82DF3A08(&arg_sp50, 0x82051160);
    func_825A1588(temp_r31, &arg_sp50, 0);
    func_82DF3428(&arg_sp50);
    func_82DF3A08(&arg_sp50, 0x82051154);
    func_825A1588(temp_r31, &arg_sp50, 0);
    func_82DF3428(&arg_sp50);
    func_82DF3A08(&arg_sp50, 0x8204D2E8);
    func_825A1588(temp_r31, &arg_sp50, 0);
    func_82DF3428(&arg_sp50);
    func_82DF3A08(&arg_sp50, 0x8205114C);
    func_825A1588(temp_r31, &arg_sp50, 0);
    func_82DF3428(&arg_sp50);
    func_82DF3A08(&arg_sp50, 0x8205113C);
    func_825A1588(temp_r31, &arg_sp50, 0);
    func_82DF3428(&arg_sp50);
    func_82DF3A08(&arg_sp50, 0x82024A98);
    func_825A1588(temp_r31, &arg_sp50, 1);
    func_82DF3428(&arg_sp50);
    if ((u32) (M2C_FIELD(temp_r22, s32 *, 0x64) - 1) <= 9U) {
        return;
    }
    func_831A8194();
}

// ============================================================================
// Test 16: test_16
// ============================================================================

s32 func_82696F38();                                /* extern */
M2C_UNK func_82696F88(M2C_UNK);                     /* extern */
M2C_UNK func_82960C04(M2C_UNK);                     /* extern */
M2C_UNK func_82960C14(M2C_UNK);                     /* extern */

void test_16(void) {
    M2C_UNK var_r31;                                /* artifact */
    s32 temp_r31;                                   /* artifact */
    s32 temp_ret;                                   /* artifact */
    s32 var_r11;                                    /* artifact */
    u32 *temp_r29;                                  /* artifact */
    u32 temp_r11;                                   /* artifact */
    u32 temp_r30;                                   /* artifact */

    temp_ret = func_82696F38();
    temp_r31 = temp_ret;
    temp_r30 = (u32) (u64) temp_ret;
    temp_r29 = M2C_ERROR(/* Read from unset register $r5 */);
    func_82960C04(0x8297D2D4);
    if (temp_r31 <= 0x1000) {
        if (temp_r31 != 0x1000) {
            if ((u32) (temp_r31 - 1) <= 0x1BU) {
                return;
            }
            var_r31 = 0x807A1009;
            /* Duplicate return node #88. Try simplifying control flow for better match */
            func_82960C14(0x8297D2D4);
            func_82696F88(var_r31);
            return;
        }
        if ((u32) *temp_r29 >= 4U) {
            var_r11 = M2C_FIELD((void *)0x8297D248, s32 *, 0x60);
            goto block_6;
        }
        goto block_7;
        goto block_8;
    }
    temp_r11 = temp_r31 - 0x1003;
    switch (temp_r11) {                             /* irregular */
    case 0:
        if ((u32) *temp_r29 >= 4U) {
            var_r11 = M2C_FIELD((void *)0x8297D248, s32 *, 0x30);
block_6:
            var_r31 = 0;
            *temp_r30 = var_r11;
        } else {
block_7:
            var_r31 = 0x807A1001;
        }
block_8:
        *temp_r29 = 4U;
        break;
    case 1:
        if ((u32) *temp_r29 >= 4U) {
            var_r11 = (s32) M2C_FIELD((void *)0x8297D248, u16 *, 0x38);
            goto block_6;
        }
        goto block_7;
        goto block_8;
    case 2:
        if ((u32) *temp_r29 >= 4U) {
            var_r11 = (s32) M2C_FIELD((void *)0x8297D248, u16 *, 0x3A);
            goto block_6;
        }
        goto block_7;
        goto block_8;
    case 3:
        if ((u32) *temp_r29 >= 4U) {
            var_r11 = (s32) M2C_FIELD((void *)0x8297D248, u16 *, 0x3C);
            goto block_6;
        }
        goto block_7;
        goto block_8;
    case 4:
        if ((u32) *temp_r29 >= 4U) {
            var_r11 = M2C_FIELD((void *)0x8297D248, s32 *, 0x64);
            goto block_6;
        }
        goto block_7;
        goto block_8;
    case 5:
        if ((u32) *temp_r29 >= 4U) {
            var_r11 = M2C_FIELD((void *)0x8297D248, s32 *, 0x80);
            goto block_6;
        }
        goto block_7;
        goto block_8;
    case 6:
        if ((u32) *temp_r29 >= 4U) {
            var_r11 = M2C_FIELD((void *)0x8297D248, s32 *, 0x44);
            goto block_6;
        }
        goto block_7;
        goto block_8;
    default:
        if ((u32) *temp_r29 >= 4U) {
            var_r11 = M2C_FIELD((void *)0x8297D248, s32 *, 0x48);
            goto block_6;
        }
        goto block_7;
        goto block_8;
    }
    func_82960C14(0x8297D2D4);
    func_82696F88(var_r31);
}

// ============================================================================
// Test 17: test_17
// ============================================================================

u32 test_17(u32 arg0) {
    if (arg0 <= 0x1DU) {
        return arg0;
    }
    return 0U;
}

// ============================================================================
// Test 18: 
// ============================================================================

void *func_8258DFB8();                              /* extern */
M2C_UNK func_825F06E8(void *, u32, M2C_UNK);        /* extern */

void test_18(void) {
    s32 temp_r11;                                   /* artifact */
    s32 temp_r29;                                   /* artifact */
    u32 temp_r26;                                   /* artifact */
    u32 temp_r4;                                    /* artifact */
    void *temp_r3;                                  /* artifact */
    void *temp_ret;                                 /* artifact */

    temp_ret = func_8258DFB8();
    temp_r3 = temp_ret;
    temp_r4 = (u32) (u64) temp_ret;
    temp_r26 = M2C_FIELD(temp_r3, u32 *, 0x34);
    temp_r29 = M2C_FIELD(temp_r4, s32 *, 0);
    if (temp_r26 < (u32) M2C_FIELD(temp_r3, u32 *, 0x30)) {

    }
    if ((u32) M2C_FIELD(temp_r3, u32 *, 0) <= 9U) {
        return;
    }
    M2C_FIELD(temp_r3, s32 *, 0x20) = (s32) M2C_FIELD(temp_r3, s32 *, 0x20);
    M2C_FIELD(temp_r3, s32 *, 0x1C) = (s32) M2C_FIELD(temp_r3, s32 *, 0x1C);
    M2C_FIELD(temp_r4, s32 *, 4) = (s32) M2C_FIELD(temp_r4, s32 *, 4);
    temp_r11 = temp_r29 - M2C_FIELD(temp_r4, s32 *, 0);
    M2C_FIELD(temp_r4, s32 *, 0) = temp_r29;
    M2C_FIELD(temp_r4, s32 *, 8) = (s32) (temp_r11 + M2C_FIELD(temp_r4, s32 *, 8));
    M2C_FIELD(temp_r3, u32 *, 0x34) = temp_r26;
    func_825F06E8(temp_r3, temp_r4, -2);
}

// ============================================================================
// Test 19: 
// ============================================================================

M2C_UNK func_8214BC60(s32, s32, s32);               /* extern */

void test_19(s32 arg0, s32 arg1, s32 arg2, s32 arg_sp14, s32 arg_sp1C, s32 arg_sp24) {
    arg_sp14 = arg0;
    arg_sp1C = arg1;
    arg_sp24 = arg2;
    func_8214BC60(arg_sp14, arg_sp1C, arg_sp24);
    *(arg_sp14 + 0x40 + arg_sp1C)(arg_sp14, arg_sp24);
}

