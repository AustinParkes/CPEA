# CS_ARCH_ARM, CS_MODE_THUMB, None
// 0xe2,0xee,0xa1,0x0b = vfma.f64 d16, d18, d17
0xa2,0xee,0x00,0x1a = vfma.f32 s2, s4, s0
0x42,0xef,0xb1,0x0c = vfma.f32 d16, d18, d17
0x08,0xef,0x50,0x4c = vfma.f32 q2, q4, q0
// 0xd2,0xee,0xe1,0x0b = vfnma.f64 d16, d18, d17
0x92,0xee,0x40,0x1a = vfnma.f32 s2, s4, s0
// 0xe2,0xee,0xe1,0x0b = vfms.f64 d16, d18, d17
0xa2,0xee,0x40,0x1a = vfms.f32 s2, s4, s0
0x62,0xef,0xb1,0x0c = vfms.f32 d16, d18, d17
0x28,0xef,0x50,0x4c = vfms.f32 q2, q4, q0
// 0xd2,0xee,0xa1,0x0b = vfnms.f64 d16, d18, d17
0x92,0xee,0x00,0x1a = vfnms.f32 s2, s4, s0
