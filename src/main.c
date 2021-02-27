#include "types.h"
#include "os.h"
#include "execution_buffer.h"
#include <stdio.h>
#ifdef RED_OS_WINDOWS
#error
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#ifdef RED_OS_WINDOWS
#define MSVC_x86_64
#else
#if defined(RED_OS_LINUX)
#define SYSTEM_V_x86_64
#endif
#endif

#define TEST_MODE 0

typedef s64 square_fn(s64);
typedef s64 mul_fn(s64, s64);
typedef s64 make_increment_s64(s64);

typedef enum OperandSize
{
    OperandSize_Any = 0,
    OperandSize_8 = 1,
    OperandSize_16 = 2,
    OperandSize_32 = 4,
    OperandSize_64 = 8,
} OperandSize;

typedef enum OperandType
{
    OperandType_None,
    OperandType_Register,
    OperandType_Immediate,
    OperandType_MemoryIndirect,
    OperandType_RIP_Relative,
} OperandType;

typedef enum SIBScale
{
    SIBScale_1 = 0b00,
    SIBScale_2 = 0b01,
    SIBScale_4 = 0b10,
    SIBScale_8 = 0b11,
} SIBScale;

typedef enum Mod
{
    Mod_Displacement_0 = 0b00,
    Mod_Displacement_8 = 0b01,
    Mod_Displacement_32 = 0b10,
    Mod_Register = 0b11,
} Mod;

enum
{
    OperandSizeOverride = 0x66,
};

typedef enum REX
{
    Rex  = 0x40,
    RexB = 0x41,
    RexX = 0x42,
    RexR = 0x44,
    RexW = 0x48,
} REX;

typedef enum Register
{
    Register_A = 0,
    Register_C = 1,
    Register_D = 2,
    Register_B = 3,
    Register_SP = 4,
    Register_BP = 5,
    Register_SI = 6,
    Register_DI = 7,
    Register_AH = Register_SP,
    Register_CH = Register_BP,
    Register_DH = Register_SI,
    Register_BH = Register_DI,

    Register_8 =  8,
    Register_9 =  9,
    Register_10 = 10,
    Register_11 = 11,
    Register_12 = 12,
    Register_13 = 13,
    Register_14 = 14,
    Register_15 = 15,
} Register;

const char* register_to_string(Register r)
{
    switch (r)
    {
        CASE_TO_STR(Register_A);
        CASE_TO_STR(Register_C);
        CASE_TO_STR(Register_D);
        CASE_TO_STR(Register_B);
        CASE_TO_STR(Register_SP);
        CASE_TO_STR(Register_BP);
        CASE_TO_STR(Register_SI);
        CASE_TO_STR(Register_DI);
        CASE_TO_STR(Register_8);
        CASE_TO_STR(Register_9);
        CASE_TO_STR(Register_10);
        CASE_TO_STR(Register_11);
        CASE_TO_STR(Register_12);
        CASE_TO_STR(Register_13);
        CASE_TO_STR(Register_14);
        CASE_TO_STR(Register_15);
    default:
        return NULL;
    }
}

typedef struct OperandMemoryIndirect
{
    s32 displacement;
    Register reg;
} OperandMemoryIndirect;

typedef struct OperandMemoryDirect
{
    u64 memory;
} OperandMemoryDirect;

typedef union OperandImmediate
{
    u8  _8;
    u16 _16;
    u32 _32;
    u64 _64;
} OperandImmediate;

typedef struct Operand
{
    OperandType type;
    OperandSize size;
    union
    {
        Register reg;
        OperandImmediate imm;
        OperandMemoryIndirect mem_indirect;
        OperandMemoryDirect memory;
    };
} Operand;

#define reg_init(reg_index, reg_size) { .type = OperandType_Register, .size = reg_size, .reg = reg_index, }
#define define_register(reg_name, reg_index, reg_size)\
    const Operand reg_name = reg_init(reg_index, reg_size)

/* 64-bit registers */
define_register(rax,    Register_A, 8);
define_register(rcx,    Register_C, 8);
define_register(rdx,    Register_D, 8);
define_register(rbx,    Register_B, 8);
define_register(rsp,    Register_SP, 8);
define_register(rbp,    Register_BP, 8);
define_register(rsi,    Register_SI, 8);
define_register(rdi,    Register_DI, 8);
define_register(r8,     Register_8, 8);
define_register(r9,     Register_9, 8);
define_register(r10,    Register_10, 8);
define_register(r11,    Register_11, 8);
define_register(r12,    Register_12, 8);
define_register(r13,    Register_13, 8);
define_register(r14,    Register_14, 8);
define_register(r15,    Register_15, 8);

/* 32-bit registers */
define_register(eax,    Register_A, 4);
define_register(ecx,    Register_C, 4);
define_register(edx,    Register_D, 4);
define_register(ebx,    Register_B, 4);
define_register(esp,    Register_SP, 4);
define_register(ebp,    Register_BP, 4);
define_register(esi,    Register_SI, 4);
define_register(edi,    Register_DI, 4);
define_register(r8d,    Register_8,  4);
define_register(r9d,    Register_9,  4);
define_register(r10d,   Register_10, 4);
define_register(r11d,   Register_11, 4);
define_register(r12d,   Register_12, 4);
define_register(r13d,   Register_13, 4);
define_register(r14d,   Register_14, 4);
define_register(r15d,   Register_15, 4);

/* 16-bit registers */
define_register(ax,     Register_A,  2);
define_register(cx,     Register_C,  2);
define_register(dx,     Register_D,  2);
define_register(bx,     Register_B,  2);
define_register(sp,     Register_SP, 2);
define_register(bp,     Register_BP, 2);
define_register(si,     Register_SI, 2);
define_register(di,     Register_DI, 2);
define_register(r8w,    Register_8,  2);
define_register(r9w,    Register_9,  2);
define_register(r10w,   Register_10, 2);
define_register(r11w,   Register_11, 2);
define_register(r12w,   Register_12, 2);
define_register(r13w,   Register_13, 2);
define_register(r14w,   Register_14, 2);
define_register(r15w,   Register_15, 2);

/* 8-bit registers */
define_register(al,     Register_A,  1);
define_register(cl,     Register_C,  1);
define_register(dl,     Register_D,  1);
define_register(bl,     Register_B,  1);
define_register(ah,     Register_AH, 1);
define_register(ch,     Register_CH, 1);
define_register(dh,     Register_DH, 1);
define_register(bh,     Register_BH, 1);
define_register(r8b,    Register_8,  1);
define_register(r9b,    Register_9,  1);
define_register(r10b,   Register_10, 1);
define_register(r11b,   Register_11, 1);
define_register(r12b,   Register_12, 1);
define_register(r13b,   Register_13, 1);
define_register(r14b,   Register_14, 1);
define_register(r15b,   Register_15, 1);

#ifdef MSVC_x86_64
const Register parameter_registers[] =
{
    Register_C,
    Register_D,
    Register_8,
    Register_9,
};
const Register return_registers[] =
{
    Register_A,
};
const Register scratch_registers[] =
{
    Register_A,
    Register_C,
    Register_D,
    Register_8,
    Register_9,
    Register_10,
    Register_11,
};
const Register preserved_registers[] =
{
    Register_B,
    Register_DI,
    Register_SI,
    Register_SP,
    Register_BP,
    Register_12,
    Register_13,
    Register_14,
    Register_15,
};
#elif defined(SYSTEM_V_x86_64)
const Register parameter_registers[] =
{
    Register_DI,
    Register_SI,
    Register_D,
    Register_C,
    Register_8,
    Register_9,
};
const Register return_registers[] =
{
    Register_A,
    Register_D,
};
const Register scratch_registers[] =
{
    Register_A,
    Register_DI,
    Register_SI,
    Register_D,
    Register_C,
    Register_8,
    Register_9,
    Register_10,
    Register_11,
};
const Register preserved_registers[] =
{
    Register_B,
    Register_SP,
    Register_BP,
    Register_12,
    Register_13,
    Register_14,
    Register_15,
};
#endif

#define _imm(n, v) { .type = OperandType_Immediate, .imm._ ## n = v, .size = OperandSize_ ## n, }
static inline Operand imm8(u8 value)
{
    return (const Operand)_imm(8, value);
}

static inline Operand imm16(u16 value)
{
    return (const Operand)_imm(16, value);
}

static inline Operand imm32(u32 value)
{
    return (const Operand)_imm(32, value);
}

static inline Operand imm64(u64 value)
{
    return (const Operand)_imm(64, value);
}
#undef _imm

#if defined (MSVC_x86_64)
static inline Operand stack(s32 offset)
{
    return (const Operand)
    {
        .type = OperandType_MemoryIndirect,
        .size = OperandSize_64,
        .mem_indirect =
        {
            .reg = rsp.reg,
            .displacement = offset,
        },
    };
}
#else
static inline Operand stack(s32 offset, s32 size)
{
    return (const Operand)
    {
        .type = OperandType_MemoryIndirect,
        .mem_indirect =
        {
            .reg = rbp.reg,
            .displacement = offset,
        },
        .size = size,
    };
}
#endif

typedef enum InstructionExtensionType
{
    IET_None,
    IET_Register,
    IET_OpCode,
    IET_Plus_Register,
} InstructionExtensionType;

typedef enum OperandEncodingType
{
    OET_None = 0,
    OET_Register,
    OET_Register_A,
    OET_Register_Or_Memory,
    OET_Memory,
    OET_Immediate,
} OperandEncodingType;


typedef struct OperandEncoding
{
    OperandEncodingType type;
    OperandSize size;
} OperandEncoding;
typedef struct OperandCombination
{
    u8 rex_byte;
    OperandEncoding operands[4];
} OperandCombination;

typedef enum InstructionOptionType
{
    None = 0,
    Digit,
    Reg,
    OpCodePlusReg,
} InstructionOptionType;

typedef struct InstructionOptions
{
    InstructionOptionType type;
    u8 digit;
} InstructionOptions;
typedef struct InstructionEncoding
{
    u8 op_code;
    InstructionOptions options;
    OperandCombination operand_combinations[4];
} InstructionEncoding;

typedef struct Mnemonic
{
    const InstructionEncoding* encodings;
    u32 encoding_count;
} Mnemonic;

typedef struct Instruction
{
    Mnemonic mnemonic;
    Operand operands[4];
} Instruction;

#define OP(_type, _size) { .type = _type,  .size = OperandSize_ ## _size, }
#define OPTS(...) __VA_ARGS__
#define NO_OPTS .rex_byte = 0
#define OPS(...) .operands = { __VA_ARGS__ }
#define OP_COMB(_ops, _opts) { _ops, _opts }
#define ENC_OPTS(...) .options = { __VA_ARGS__ }
#define ENCODING(_op_code, options, ...) { .op_code = _op_code, options, .operand_combinations = { __VA_ARGS__ }, }

const InstructionEncoding adc_encoding[] =
{
    ENCODING(0x14,ENC_OPTS(0),
        OP_COMB(OPTS(0),      OPS(OP(OET_Register_A, 8), OP(OET_Immediate, 8)))
        ),
    ENCODING(0x15, ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_A, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(NO_OPTS),		OPS(OP(OET_Register_A, 32), OP(OET_Immediate, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_A, 64), OP(OET_Immediate, 32))),
        ),
    ENCODING(0x80, ENC_OPTS(.type = Digit, .digit = 2),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Immediate, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Immediate, 8))),
        ),
    ENCODING(0x81, ENC_OPTS(.type = Digit, .digit = 2),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 32))),
        ),
    ENCODING(0x83, ENC_OPTS(.type = Digit, .digit = 2),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 8))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 8))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 8))),
        ),
    ENCODING(0x10, ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
        ),
    ENCODING(0x11,ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Register, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Register, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Register, 64))),
        ),
    ENCODING(0x12,ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
        ),
    ENCODING(0x13,ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register, 16), OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register, 32), OP(OET_Register_Or_Memory, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register, 64), OP(OET_Register_Or_Memory, 64))),
        ),
};


// @TODO:
const InstructionEncoding adcx_encoding[] = {0};
const InstructionEncoding add_encoding[] =
{
    ENCODING(0x04,ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_A, 8), OP(OET_Immediate, 8))),
    ),
    ENCODING(0x05,ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_A, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_A, 32), OP(OET_Immediate, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_A, 64), OP(OET_Immediate, 32))),
    ),
    ENCODING(0x80,ENC_OPTS(.type = Digit, .digit = 0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory,8), OP(OET_Immediate, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register_Or_Memory,8), OP(OET_Immediate, 8))),
        ),
    ENCODING(0x81,ENC_OPTS(.type = Digit, .digit = 0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 32))),
    ),
    ENCODING(0x83,ENC_OPTS(.type = Digit, .digit = 0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 8))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 8))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 8))),
    ),
    ENCODING(0x00,ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
    ),
    ENCODING(0x01,ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Register, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Register, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Register, 64))),
    ),
    ENCODING(0x02,ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
    ),
    ENCODING(0x03,ENC_OPTS(.type = Reg),
    	OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register, 16), OP(OET_Register_Or_Memory, 16))),
    	OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register, 32), OP(OET_Register_Or_Memory, 32))),
    	OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register, 64), OP(OET_Register_Or_Memory, 64))),
    ),
};

const InstructionEncoding adox_encoding[] = { 0 };
const InstructionEncoding and_encoding[] = { 0 };
const InstructionEncoding andn_encoding[] = { 0 };
const InstructionEncoding bextr_encoding[] = { 0 };
const InstructionEncoding blsi_encoding[] = { 0 };
const InstructionEncoding blsmsk_encoding[] = { 0 };
const InstructionEncoding blsr_encoding[] = { 0 };
const InstructionEncoding bndcl_encoding[] = { 0 };
const InstructionEncoding bndcu_encoding[] = { 0 };
const InstructionEncoding bndcn_encoding[] = { 0 };
const InstructionEncoding bndldx_encoding[] = { 0 };
const InstructionEncoding bndmk_encoding[] = { 0 };
const InstructionEncoding bndmov_encoding[] = { 0 };
const InstructionEncoding bndstx_encoding[] = { 0 };
const InstructionEncoding bsf_encoding[] = { 0 };
const InstructionEncoding bsr_encoding[] = { 0 };
const InstructionEncoding bswap_encoding[] = { 0 };
const InstructionEncoding bt_encoding[] = { 0 };
const InstructionEncoding btc_encoding[] = { 0 };
const InstructionEncoding btr_encoding[] = { 0 };
const InstructionEncoding bts_encoding[] = { 0 };
const InstructionEncoding bzhi_encoding[] = { 0 };
const InstructionEncoding call_encoding[] =
{
    ENCODING(0xFF, ENC_OPTS(.type = Digit, .digit = 2),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register_Or_Memory, 64))),
    ),
};
const InstructionEncoding cbw_encoding[] = { 0 };
const InstructionEncoding cwde_encoding[] = { 0 };
const InstructionEncoding cdqe_encoding[] = { 0 };
const InstructionEncoding clac_encoding[] = { 0 };
const InstructionEncoding clc_encoding[] = { 0 };
const InstructionEncoding cld_encoding[] = { 0 };
const InstructionEncoding cldemote_encoding[] = { 0 };
const InstructionEncoding clflush_encoding[] = { 0 };
const InstructionEncoding clflushopt_encoding[] = { 0 };
const InstructionEncoding cli_encoding[] = { 0 };
const InstructionEncoding clrssbsy_encoding[] = { 0 };
const InstructionEncoding clts_encoding[] = { 0 };
const InstructionEncoding clwb_encoding[] = { 0 };
const InstructionEncoding cmc_encoding[] = { 0 };
const InstructionEncoding cmov_encoding[] = { 0 };
const InstructionEncoding cmp_encoding[] = { 0 };
const InstructionEncoding cmpxchg_encoding[] = { 0 };
const InstructionEncoding cmpxchg8b_encoding[] = { 0 };
const InstructionEncoding cmpxchg16b_encoding[] = { 0 };
const InstructionEncoding cpuid_encoding[] = { 0 };
const InstructionEncoding crc32_encoding[] = { 0 };
const InstructionEncoding cwd_encoding[] = { 0 };
const InstructionEncoding cdq_encoding[] = { 0 };
const InstructionEncoding cqo_encoding[] = { 0 };
const InstructionEncoding dec_encoding[] = { 0 };
const InstructionEncoding div_encoding[] = { 0 };
const InstructionEncoding endbr32_encoding[] = { 0 };
const InstructionEncoding endbr64_encoding[] = { 0 };
const InstructionEncoding enter_encoding[] = { 0 };
// Tons of float instructions here
const InstructionEncoding hlt_encoding[] = { 0 };
const InstructionEncoding idiv_encoding[] = { 0 };
const InstructionEncoding imul_encoding[] = { 0 };
const InstructionEncoding in_encoding[] = { 0 };
const InstructionEncoding inc_encoding[] = { 0 };
const InstructionEncoding incssp_encoding[] = { 0 };
const InstructionEncoding ins_encoding[] = { 0 };
const InstructionEncoding int_encoding[] = { 0 };
const InstructionEncoding invd_encoding[] = { 0 };
const InstructionEncoding invlpg_encoding[] = { 0 };
const InstructionEncoding invpcid_encoding[] = { 0 };
const InstructionEncoding iret_encoding[] = { 0 };
const InstructionEncoding jcc_encoding[] = { 0 };
const InstructionEncoding jmp_encoding[] = { 0 };
const InstructionEncoding lar_encoding[] = { 0 };
const InstructionEncoding lds_encoding[] = { 0 };
const InstructionEncoding lss_encoding[] = { 0 };
const InstructionEncoding les_encoding[] = { 0 };
const InstructionEncoding lfs_encoding[] = { 0 };
const InstructionEncoding lgs_encoding[] = { 0 };
const InstructionEncoding lea_encoding[] = { 0 };
const InstructionEncoding leave_encoding[] = { 0 };
const InstructionEncoding lfence_encoding[] = { 0 };
const InstructionEncoding lgdt_encoding[] = { 0 };
const InstructionEncoding lidt_encoding[] = { 0 };
const InstructionEncoding lldt_encoding[] = { 0 };
const InstructionEncoding lmsw_encoding[] = { 0 };
const InstructionEncoding lock_encoding[] = { 0 };
const InstructionEncoding lods_encoding[] = { 0 };
const InstructionEncoding lodsb_encoding[] = { 0 };
const InstructionEncoding lodsw_encoding[] = { 0 };
const InstructionEncoding lodsd_encoding[] = { 0 };
const InstructionEncoding lodsq_encoding[] = { 0 };
const InstructionEncoding loop_encoding[] = { 0 };
const InstructionEncoding loope_encoding[] = { 0 };
const InstructionEncoding loopne_encoding[] = { 0 };
const InstructionEncoding lsl_encoding[] = { 0 };
const InstructionEncoding ltr_encoding[] = { 0 };
const InstructionEncoding lzcnt_encoding[] = { 0 };
const InstructionEncoding mfence_encoding[] = { 0 };

const InstructionEncoding mov_encoding[] =
{
    ENCODING(0x88, ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
    ),
    ENCODING(0x89, ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Register, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Register, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Register, 64))),
    ),
    ENCODING(0x8A, ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
    ),
    ENCODING(0x8B, ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 16), OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 32), OP(OET_Register_Or_Memory, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register, 64), OP(OET_Register_Or_Memory, 64))),
    ),
    /*  @TODO: NOT CODED SEGMENT AND OFFSET INSTRUCTIONS */
    ENCODING(0xB0, ENC_OPTS(.type = OpCodePlusReg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 8), OP(OET_Immediate, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register, 8), OP(OET_Immediate, 8))),
    ),
    ENCODING(0xB8, ENC_OPTS(.type = OpCodePlusReg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 32), OP(OET_Immediate, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register, 64), OP(OET_Immediate, 64))),
    ),
    ENCODING(0xC6, ENC_OPTS(.type = Digit, .digit = 0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Immediate, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Immediate, 8))),
    ),
    ENCODING(0xC7, ENC_OPTS(.type = Digit, .digit = 0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 32))),
    ),
};

const InstructionEncoding movcr_encoding[] = { 0 };
const InstructionEncoding movdbg_encoding[] = { 0 };
const InstructionEncoding movbe_encoding[] = { 0 };
const InstructionEncoding movdq_encoding[] = { 0 };
const InstructionEncoding movdiri_encoding[] = { 0 };
const InstructionEncoding movdir64b_encoding[] = { 0 };
const InstructionEncoding movq_encoding[] = { 0 };
const InstructionEncoding movs_encoding[] = { 0 };
const InstructionEncoding movsx_encoding[] = { 0 };
const InstructionEncoding movzx_encoding[] = { 0 };
const InstructionEncoding mul_encoding[] = { 0 };
const InstructionEncoding mulx_encoding[] = { 0 };
const InstructionEncoding mwait_encoding[] = { 0 };
const InstructionEncoding neg_encoding[] = { 0 };
const InstructionEncoding nop_encoding[] = { 0 };
const InstructionEncoding not_encoding[] = { 0 };
const InstructionEncoding or_encoding[] = { 0 };
const InstructionEncoding out_encoding[] = { 0 };
const InstructionEncoding outs_encoding[] = { 0 };
const InstructionEncoding pause_encoding[] = { 0 };
const InstructionEncoding pdep_encoding[] = { 0 };
const InstructionEncoding pext_encoding[] = { 0 };
const InstructionEncoding pop_encoding[] =
{
    ENCODING(0x58, ENC_OPTS(.type = OpCodePlusReg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 64))),
    ),
    ENCODING(0x8f, ENC_OPTS(.type = Digit, .digit = 0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 64))),
    ),
    ENCODING(0x6A, ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Immediate, 8))),
    ),
    // @TODO: these need two-byte opcode
    //// Pop FS
    //ENCODING(0x0f 0xa1,
    //    OP_COMB(OPTS(0), OPS(0)),
    //),
    //// Pop GS
    //ENCODING(0x0f 0xa9,
    //    OP_COMB(OPTS(0), OPS(0)),
    //),

};
const InstructionEncoding popcnt_encoding[] = { 0 };
const InstructionEncoding popf_encoding[] = { 0 };
const InstructionEncoding por_encoding[] = { 0 };
const InstructionEncoding prefetch_encoding[] = { 0 };
const InstructionEncoding prefetchw_encoding[] = { 0 };
const InstructionEncoding ptwrite_encoding[] = { 0 };
const InstructionEncoding push_encoding[] =
{
    ENCODING(0x50, ENC_OPTS(.type = OpCodePlusReg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 64))),
    ),
    ENCODING(0xff, ENC_OPTS(.type = Digit, .digit = 6),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 64))),
    ),
    ENCODING(0x6A, ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Immediate, 8))),
    ),
    ENCODING(0x68, ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Immediate, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Immediate, 32))),
    ),
    // @TODO: these need two-byte opcode
    //// Push FS
    //ENCODING(0x0f 0xa0,
    //    OP_COMB(OPTS(0), OPS(0)),
    //),
    //// Push GS
    //ENCODING(0x0f 0xa8,
    //    OP_COMB(OPTS(0), OPS(0)),
    //),
};
const InstructionEncoding pushf_encoding[] = { 0 };
const InstructionEncoding rotate_encoding[] = { 0 };
const InstructionEncoding rdfsbase_encoding[] = { 0 };
const InstructionEncoding rdgsbase_encoding[] = { 0 };
const InstructionEncoding rdmsr_encoding[] = { 0 };
const InstructionEncoding rdpid_encoding[] = { 0 };
const InstructionEncoding rdpmc_encoding[] = { 0 };
const InstructionEncoding rdrand_encoding[] = { 0 };
const InstructionEncoding rdseed_encoding[] = { 0 };
const InstructionEncoding rdssp_encoding[] = { 0 };
const InstructionEncoding rdtsc_encoding[] = { 0 };
const InstructionEncoding rdtscp_encoding[] = { 0 };
const InstructionEncoding rep_encoding[] = { 0 };
const InstructionEncoding ret_encoding[] =
{
    ENCODING(0xC3, ENC_OPTS(0)),
    ENCODING(0xCB, ENC_OPTS(0)),
    ENCODING(0xC2, ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Immediate, 16))),
    ),
    ENCODING(0xCA, ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Immediate, 16))),
    ),
};

const InstructionEncoding rsm_encoding[] = { 0 };
const InstructionEncoding rstorssp_encoding[] = { 0 };
const InstructionEncoding sahf_encoding[] = { 0 };
const InstructionEncoding sal_encoding[] = { 0 };
const InstructionEncoding sar_encoding[] = { 0 };
const InstructionEncoding shl_encoding[] = { 0 };
const InstructionEncoding shr_encoding[] = { 0 };
const InstructionEncoding sarx_encoding[] = { 0 };
const InstructionEncoding shlx_encoding[] = { 0 };
const InstructionEncoding shrx_encoding[] = { 0 };
const InstructionEncoding saveprevssp_encoding[] = { 0 };
const InstructionEncoding sbb_encoding[] = { 0 };
const InstructionEncoding scas_encoding[] = { 0 };
const InstructionEncoding setcc_encoding[] = { 0 };
const InstructionEncoding setssbsy_encoding[] = { 0 };
const InstructionEncoding sfence_encoding[] = { 0 };
const InstructionEncoding sgdt_encoding[] = { 0 };
const InstructionEncoding shld_encoding[] = { 0 };
const InstructionEncoding shrd_encoding[] = { 0 };
const InstructionEncoding sidt_encoding[] = { 0 };
const InstructionEncoding sldt_encoding[] = { 0 };
const InstructionEncoding smsw_encoding[] = { 0 };
const InstructionEncoding stac_encoding[] = { 0 };
const InstructionEncoding stc_encoding[] = { 0 };
const InstructionEncoding std_encoding[] = { 0 };
const InstructionEncoding sti_encoding[] = { 0 };
const InstructionEncoding stos_encoding[] = { 0 };
const InstructionEncoding str_encoding[] = { 0 };
const InstructionEncoding sub_encoding[] = { 0 };
const InstructionEncoding swapgs_encoding[] = { 0 };
const InstructionEncoding syscall_encoding[] = { 0 };
const InstructionEncoding sysenter_encoding[] = { 0 };
const InstructionEncoding sysexit_encoding[] = { 0 };
const InstructionEncoding sysret_encoding[] = { 0 };
const InstructionEncoding test_encoding[] = { 0 };
const InstructionEncoding tpause_encoding[] = { 0 };
const InstructionEncoding tzcnt_encoding[] = { 0 };
const InstructionEncoding ud_encoding[] = { 0 };
const InstructionEncoding umonitor_encoding[] = { 0 };
const InstructionEncoding umwait_encoding[] = { 0 };
const InstructionEncoding wait_encoding[] = { 0 };
const InstructionEncoding wbinvd_encoding[] = { 0 };
const InstructionEncoding wbnoinvd_encoding[] = { 0 };
const InstructionEncoding wrfsbase_encoding[] = { 0 };
const InstructionEncoding wrgsbase_encoding[] = { 0 };
const InstructionEncoding wrmsr_encoding[] = { 0 };
const InstructionEncoding wrss_encoding[] = { 0 };
const InstructionEncoding wruss_encoding[] = { 0 };
const InstructionEncoding xacquire_encoding[] = { 0 };
const InstructionEncoding xrelease_encoding[] = { 0 };
const InstructionEncoding xabort_encoding[] = { 0 };
const InstructionEncoding xadd_encoding[] = { 0 };
const InstructionEncoding xbegin_encoding[] = { 0 };
const InstructionEncoding xchg_encoding[] = { 0 };
const InstructionEncoding xend_encoding[] = { 0 };
const InstructionEncoding xgetbv_encoding[] = { 0 };
const InstructionEncoding xlat_encoding[] = { 0 };
const InstructionEncoding xor_encoding[] = { 0 };
const InstructionEncoding xrstor_encoding[] = { 0 };
const InstructionEncoding xrstors_encoding[] = { 0 };
const InstructionEncoding xsave_encoding[] = { 0 };
const InstructionEncoding xsavec_encoding[] = { 0 };
const InstructionEncoding xsaveopt_encoding[] = { 0 };
const InstructionEncoding xsaves_encoding[] = { 0 };
const InstructionEncoding xsetbv_encoding[] = { 0 };
const InstructionEncoding xtest_encoding[] = { 0 };


#define define_mnemonic(instruction)\
    const Mnemonic instruction = { .encodings = (const InstructionEncoding*) instruction ## _encoding, .encoding_count = array_length(instruction ## _encoding), }

define_mnemonic(adc);
define_mnemonic(add);
define_mnemonic(call);
define_mnemonic(mov);
define_mnemonic(pop);
define_mnemonic(push);
define_mnemonic(ret);

bool find_encoding(Instruction instruction, u32* encoding_index, u32* combination_index)
{
    u32 encoding_count = instruction.mnemonic.encoding_count;
    const InstructionEncoding* encodings = instruction.mnemonic.encodings;

    for (u32 encoding_i = 0; encoding_i < encoding_count; encoding_i++)
    {
        InstructionEncoding encoding = encodings[encoding_i];
        u32 combination_count = array_length(encoding.operand_combinations);

        for (u32 combination_i = 0; combination_i < combination_count; combination_i++)
        {
            OperandCombination combination = encoding.operand_combinations[combination_i];
            const u32 operand_count = array_length(combination.operands);
            bool matched = true;

            for (u32 operand_i = 0; operand_i < operand_count; operand_i++)
            {
                Operand operand = instruction.operands[operand_i];
                OperandEncoding operand_encoding = combination.operands[operand_i];

                switch (operand.type)
                {
                    case OperandType_None:
                        if (operand_encoding.type == OET_None)
                        {
                            continue;
                        }
                        break;
                    case OperandType_Register:
                        if (operand_encoding.type == OET_Register && operand_encoding.size == operand.size)
                        {
                            continue;
                        }
                        if (operand_encoding.type == OET_Register_A && operand.reg == Register_A && operand_encoding.size == operand.size)
                        {
                            continue;
                        }
                        if (operand_encoding.type == OET_Register_Or_Memory && operand_encoding.size == operand.size)
                        {
                            continue;
                        }
                        break;
                    case OperandType_Immediate:
                        if (operand_encoding.type == OET_Immediate && operand_encoding.size == operand.size)
                        {
                            continue;
                        }
                        break;
                    case OperandType_MemoryIndirect:
                        if (operand_encoding.type == OET_Register_Or_Memory)
                        {
                            continue;
                        }
                        break;
                    case OperandType_RIP_Relative:
                        RED_NOT_IMPLEMENTED;
                        break;
                }

                matched = false;
                break;
            }

            if (matched)
            {
                *encoding_index = encoding_i;
                *combination_index = combination_i;
                return true;
            }
        }
    }
    return false;
}

static inline Mod find_mod_displacement(s32 displacement)
{
    if (displacement == 0)
    {
        return Mod_Displacement_0;
    }

    if (displacement <= INT8_MAX && displacement >= INT8_MIN)
    {
        return Mod_Displacement_8;
    }

    return Mod_Displacement_32;
}

void encode(ExecutionBuffer* eb, Instruction instruction)
{
    u32 encoding_index;
    u32 combination_index;
    if (!find_encoding(instruction, &encoding_index, &combination_index))
    {
        redassert(false);
        return;
    }

    InstructionEncoding encoding = instruction.mnemonic.encodings[encoding_index];
    OperandCombination combination = encoding.operand_combinations[combination_index];
    u32 operand_count = array_length(combination.operands);
    redassert(instruction.operands[2].type == OperandType_None && instruction.operands[3].type == OperandType_None);

    if (combination.rex_byte)
    {
        u8_append(eb, combination.rex_byte);
    }
    else if ((instruction.operands[0].type == OperandType_Register && instruction.operands[0].size == OperandSize_16) || (instruction.operands[1].type == OperandType_Register && instruction.operands[1].size == OperandSize_16))
    {
        u8_append(eb, OperandSizeOverride);
    }


    u8 op_code = encoding.op_code;
    bool d = op_code & 0b10;
    bool s = op_code & 0b1;
    u8 reg_code;
    if (encoding.options.type == OpCodePlusReg)
    {
        reg_code = instruction.operands[0].reg;
        op_code = (op_code & 0b11111000) | (reg_code & 0b111);
    }

    u8_append(eb, op_code);

    // MOD RM
    bool need_sib = false;
    u8 sib_byte = 0;
    bool is_digit = encoding.options.type == Digit;
    bool is_reg = encoding.options.type == Reg;
    bool need_mod_rm = is_digit || is_reg;

    u8 register_or_digit;
    u8 r_m = 0;
    u8 mod = 0;
    if (need_mod_rm)
    {
        for (u32 oi = 0; oi < operand_count; oi++)
        {
            Operand operand = instruction.operands[oi];
            switch (operand.type)
            {
                case OperandType_Register:
                    switch (oi)
                    {
                        case 0:
                            mod = Mod_Register;
                            r_m = operand.reg;
                            reg_code = operand.reg;
                            if (is_reg)
                            {
                                register_or_digit = operand.reg;
                            }
                            break;
                        case 1:
                            if (is_reg)
                            {
                                register_or_digit = operand.reg;
                            }
                            break;
                        default:
                            break;
                    }
                    break;
                case OperandType_MemoryIndirect:
                    mod = find_mod_displacement(operand.mem_indirect.displacement);
                    r_m = operand.mem_indirect.reg;
                    need_sib = operand.mem_indirect.reg == rsp.reg;
                    if (need_sib)
                    {
                        sib_byte = (
                            (SIBScale_1 << 6) |
                            (r_m << 3) |
                            (r_m)
                            );
                    }
                    break;
                default:
                    break;
            }
        }

        if (is_digit)
        {
            register_or_digit = encoding.options.digit;
        }

        u8 mod_r_m = (
            (mod << 6) |
            (register_or_digit << 3) |
            (r_m)
            );

        u8_append(eb, mod_r_m);
    }

    // SIB
    if (need_sib)
    {
        u8_append(eb, sib_byte);
    }

    // DISPLACEMENT
    if (need_mod_rm && mod != Mod_Register)
    {
        for (u32 oi = 0; oi < operand_count; oi++)
        {
            Operand op = instruction.operands[oi];
            if (op.type == OperandType_MemoryIndirect)
            {
                switch (mod)
                {
                    case Mod_Displacement_8:
                        s8_append(eb, (s8)op.mem_indirect.displacement);
                        break;
                    case Mod_Displacement_32:
                        s32_append(eb, op.mem_indirect.displacement);
                        break;
                    default:
                        break;
                }
            }
        }
    }

    // IMMEDIATE
    for (u32 operand_i = 0; operand_i < operand_count; operand_i++)
    {
        Operand operand = instruction.operands[operand_i];
        if (operand.type == OperandType_Immediate)
        {
            switch (operand.size)
            {
                case OperandSize_8:
                    u8_append(eb, operand.imm._8);
                    break;
                case OperandSize_16:
                    u16_append(eb, operand.imm._16);
                    break;
                case OperandSize_32:
                    u32_append(eb, operand.imm._32);
                    break;
                case OperandSize_64:
                    u64_append(eb, operand.imm._64);
                    break;
                default:
                    break;
            }
        }
    }
}

static void test_adc_al_imm8(void* s)
{
    u8 n = 0x1;
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) {adc, {al, imm8(n)}});

    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0x14);
    u8_append(&expected, n);

    test_buffer(&eb, expected.ptr, expected.len, __func__);
}
static void test_adc_ax_imm16(void* s)
{
    u16 n = 0x1234;
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) {adc, {ax, imm16(n)}});

    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0x15);
    u16_append(&expected, n);

    test_buffer(&eb, expected.ptr, expected.len, __func__);
}

static void test_adc_eax_imm32(void* s)
{
    u32 n = 0x123456;
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) {adc, {eax, imm32(n)}});

    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0x15);
    u32_append(&expected, n);

    test_buffer(&eb, expected.ptr, expected.len, __func__);
}
static void test_adc_rax_imm32(void* s)
{
    u32 n = 0x123456;
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) {adc, {rax, imm32(n)}});

    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0x48);
    u8_append(&expected, 0x15);
    u32_append(&expected, n);

    test_buffer(&eb, expected.ptr, expected.len, __func__);
}

static void test_adc_r64_m64(void* s)
{
    u32 n = 0xfffffff;
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) {adc, {rbx, stack(n, sizeof(n))}});

    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0x48);
    u8_append(&expected, 0x13);
    u8_append(&expected, 0x04);
    u8_append(&expected, 0x25);
    u32_append(&expected, n);

    test_buffer(&eb, expected.ptr, expected.len, __func__);
}
#define INSTR(...) (Instruction) { __VA_ARGS__ }
#define EXPECTED(...) __VA_ARGS__
static bool test_instruction(const char* test_name, Instruction instruction, u8* expected_bytes, u8 expected_byte_count)
{
    const u32 buffer_size = 64;
    ExecutionBuffer eb = give_me(buffer_size);
    encode(&eb, instruction);

    ExecutionBuffer expected = give_me(buffer_size);
    for (u32 i = 0; i < expected_byte_count; i++)
    {
        u8_append(&expected, expected_bytes[i]);
    }
    return test_buffer(&eb, expected.ptr, expected.len, test_name);
}

#define TEST(test_name, _instr, _test_bytes)\
    u8 expected_bytes_ ## test_name [] = { _test_bytes };\
    test_instruction(#test_name, _instr, expected_bytes_ ## test_name, array_length(expected_bytes_ ## test_name )

void test_main(s32 argc, char* argv[])
{
    TEST(add_ax_imm16, INSTR(add, { ax, imm16(0xffff) }), EXPECTED(0x66, 0x05, 0xff, 0xff)));
    TEST(add_al_imm8, INSTR(add, { al, imm8(0xff) }), EXPECTED(0x04, UINT8_MAX)));
    TEST(add_eax_imm32, INSTR(add, { eax, imm32(0xffffffff) }), EXPECTED(0x05, 0xff, 0xff, 0xff, 0xff)));
    TEST(add_rax_imm32, INSTR(add, { rax, imm32(0xffffffff) }), EXPECTED(0x48, 0x05, 0xff, 0xff, 0xff, 0xff)));
    TEST(add_rm8_imm8, INSTR(add, { bl, imm8(0xff) }), EXPECTED(0x80, 0xc3, 0xff)));
    TEST(add_rm16_imm16, INSTR(add, { bx, imm16(0xffff) }), EXPECTED(0x66, 0x81, 0xc3, 0xff, 0xff)));
    TEST(add_rm32_imm32, INSTR(add, { ebx, imm32(0xffffffff) }), EXPECTED(0x81, 0xc3, 0xff, 0xff, 0xff, 0xff)));
    TEST(add_rm64_imm32, INSTR(add, { rbx, imm32(0xffffffff) }), EXPECTED(0x48, 0x81, 0xc3, 0xff, 0xff, 0xff, 0xff)));
    TEST(call_r64, INSTR(call, { rax }), EXPECTED(0xff, 0xd0)));
    TEST(mov_bl_cl, INSTR(mov, { bl, cl }), EXPECTED(0x88, 0xcb)));
    TEST(mov_bx_cx, INSTR(mov, { bx, cx }), EXPECTED(0x66, 0x89, 0xcb)));
    TEST(mov_ebx_ecx, INSTR(mov, { ebx, ecx }), EXPECTED(0x89, 0xcb)));
    TEST(mov_rbx_rcx, INSTR(mov, { rbx, rcx }), EXPECTED(0x48, 0x89, 0xcb)));
    TEST(mov_al_imm8, INSTR(mov, { al, imm8(0xff) }), EXPECTED(0xb0, UINT8_MAX)));
    TEST(mov_ax_imm16, INSTR(mov, { ax, imm16(0xffff) }), EXPECTED(0x66, 0xb8, 0xff, 0xff)));
    TEST(mov_eax_imm32, INSTR(mov, { eax, imm32(0xffffffff) }), EXPECTED(0xb8, 0xff, 0xff)));
    TEST(mov_rax_imm32, INSTR(mov, { rax, imm32(0xffffffff) }), EXPECTED(0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff)));
    TEST(mov_rax_imm64, INSTR(mov, { rax, imm64(0xffffffffffffffff) }), EXPECTED(0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)));
    TEST(mov_r8_imm8,   INSTR(mov, { bl, imm8(0xff) }), EXPECTED(0xb3, 0xff)));
    TEST(mov_r16_imm16, INSTR(mov, { bx, imm16(0xffff) }), EXPECTED(0x66, 0xbb, 0xff, 0xff)));
    TEST(mov_r32_imm32, INSTR(mov, { ebx, imm32(0xffffffff) }), EXPECTED(0xbb, 0xff, 0xff, 0xff, 0xff)));
    TEST(mov_r64_imm64, INSTR(mov, { rbx, imm64(0xffffffffffffffff) }), EXPECTED(0x48, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)));
    TEST(mov_rm64_imm32, INSTR(mov, { rbx, imm32(0xffffffff) }), EXPECTED(0x48, 0xc7, 0xc3, 0xff, 0xff, 0xff, 0xff)));
    TEST(mov_qword_ptr_r64_offset_r64, INSTR(mov, { stack(-8, 8), rdi }), EXPECTED(0x48, 0x89, 0x7d, 0xf8)));
    TEST(mov_rax_qword_ptr_r64_offset_r64, INSTR(mov, { rax, stack(-8, 8)}), EXPECTED(0x48, 0x8b, 0x45, 0xf8)));
    TEST(pop_r64, INSTR(pop, { rbp }), EXPECTED(0x5d)));
    TEST(push_r64, INSTR(push, { rbp }), EXPECTED(0x55)));
}

typedef struct Function
{
    ExecutionBuffer eb;
    s32 stack_offset;
    u32 arg_count;
} Function;

Operand declare_variable(Function* fn, s32 size)
{
    fn->stack_offset -= size;

    return stack(fn->stack_offset, size);
}

void assign(Function* fn, Operand a, Operand b)
{
    encode(&fn->eb, (Instruction) { mov, {a, b} });
}

Operand do_add(Function* fn, Operand a, Operand b)
{
    encode(&fn->eb, (Instruction) { add, { a, b } });
    return a;
}

Function fn_begin(void)
{
    Function fn = {.eb = give_me(1024) };
    encode(&fn.eb, (Instruction) { push, { rbp } });
    encode(&fn.eb, (Instruction) { mov, { rbp, rsp } });

    return fn;
}

void fn_return(Function* fn, Operand to_return)
{
    Operand ret_reg;

    switch (to_return.size)
    {
        case OperandSize_8:
            ret_reg = al;
            break;
        case OperandSize_16:
            ret_reg = ax;
            break;
        case OperandSize_32:
            ret_reg = eax;
            break;
        case OperandSize_64:
            ret_reg = rax;
            break;
        default:
            RED_UNREACHABLE;
            break;
    }

    if (memcmp(&ret_reg, &to_return, sizeof(to_return)) != 0)
    {
        encode(&fn->eb, (Instruction) { mov, { ret_reg, to_return }});
    }

    encode(&fn->eb, (Instruction) { pop, { rbp } });
    encode(&fn->eb, (Instruction) { ret });
}

void test_abstract_fn()
{
    Function fn = fn_begin();
    Operand var = declare_variable(&fn, 4);
    assign(&fn, var, edi);
    assign(&fn, eax, var);
    Operand add_result = do_add(&fn, eax, var);
    fn_return(&fn, add_result);

    u8 expected[] = { 0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xfc, 0x8b, 0x45, 0xfc, 0x03, 0x45, 0xfc, 0x5d, 0xc3 };
    test_buffer(&fn.eb, expected, array_length(expected), __func__);

    typedef int SumFn(int);
    SumFn* sum = (SumFn*) fn.eb.ptr;
    int n = 5;
    int result = sum(n);
    print("Result %d\n", result);
    print("Expected %d\n", n + n);
}



typedef s32 RetS32(void);

RetS32* make_ret_s32(void)
{
    Function fn = fn_begin();
    Operand var = declare_variable(&fn, 4);
    assign(&fn, var, imm32(18293));
    fn_return(&fn, var);

    return (RetS32*)fn.eb.ptr;
}

typedef s32 ProxyFn(RetS32);

void wna_main(s32 argc, char* argv[])
{
    Function fn = fn_begin();
    encode(&fn.eb, (Instruction) {call, {rdi}});
    fn_return(&fn, rax);

    RetS32* ret_s32 = make_ret_s32();
    ProxyFn* proxy_fn = (ProxyFn*)fn.eb.ptr;
    s32 result = proxy_fn(ret_s32);
    print("Result: %d\n", result);
}

s32 main(s32 argc, char* argv[])
{
#if TEST_MODE
    test_main(argc, argv);
#else
    wna_main(argc, argv);
#endif
}
