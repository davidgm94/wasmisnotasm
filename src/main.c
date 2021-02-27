#include "types.h"
#include "os.h"
#include "execution_buffer.h"
#include <stdio.h>
#include <stdlib.h>
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
    OperandSize_48 = 6,
    OperandSize_64 = 8,
    OperandSize_80 = 10,
} OperandSize;

typedef enum OperandType
{
    OperandType_None,
    OperandType_Register,
    OperandType_Immediate,
    OperandType_MemoryIndirect,
    OperandType_Relative,
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

enum 
{
    Register_N_Flag = 0b1000,
};

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

typedef union OperandRelative
{
    u8  _8;
    u16 _16;
    u32 _32;
    struct
    {
        u32 first;
        u16 second;
    } _48;
    u64 _64;
    struct
    {
        u64 first;
        u16 second;
    } _80;
} OperandRelative;

typedef struct Operand
{
    OperandType type;
    OperandSize size;
    union
    {
        Register reg;
        OperandImmediate imm;
        OperandMemoryIndirect mem_indirect;
        OperandRelative rel;
    };
} Operand;

typedef enum DescriptorType
{
    Integer,
    Pointer,
    FixedSizeArray,
    Function,
} DescriptorType;

typedef struct Value Value;
typedef struct DescriptorFunction
{
    Value* arg_list;
    s64 arg_count;
    Value* return_value;
} DescriptorFunction;

typedef struct DescriptorFixedSizeArray
{
    struct Descriptor* data;
    s64 len;
} DescriptorFixedSizeArray;

struct Descriptor;
typedef struct Descriptor
{
    DescriptorType type;
    union
    {
        DescriptorFunction function;
        struct Descriptor* pointer_to;
        DescriptorFixedSizeArray fixed_size_array;
    };
} Descriptor;

typedef struct Value
{
    Descriptor descriptor;
    Operand operand;
} Value;

#define reg_init(reg_index, reg_size) { .type = OperandType_Register, .size = reg_size, .reg = reg_index, }
#define define_register(reg_name, reg_index, reg_size)\
    .reg_name = reg_init(reg_index, reg_size)

u8 register_size_jump_table[] =
{
    [OperandSize_64] = 0,
    [OperandSize_32] = 1,
    [OperandSize_16] = 2,
    [OperandSize_8]  = 1,
};

#define register_count_per_size 16
union
{
    Operand arr[array_length(register_size_jump_table)][register_count_per_size];
    struct
    {
        /* 64-bit registers */
        Operand rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15;
        /* 32-bit registers */
        Operand eax, ecx, edx, ebx, esp, ebp, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d;
        /* 16-bit registers */
        Operand ax, cx, dx, bx, sp, bp, si, di, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w;
        /* 8-bit registers */
        Operand al, cl, dl, bl, ah, ch, dh, bh, r8b, r9b, r10b, r11b, r12b, r13b, r14b, r15b;
    };
} reg =
{
    /* 64-bit registers */
    define_register(rax,    Register_A,  8),
    define_register(rcx,    Register_C,  8),
    define_register(rdx,    Register_D,  8),
    define_register(rbx,    Register_B,  8),
    define_register(rsp,    Register_SP, 8),
    define_register(rbp,    Register_BP, 8),
    define_register(rsi,    Register_SI, 8),
    define_register(rdi,    Register_DI, 8),
    define_register(r8,     Register_8,  8),
    define_register(r9,     Register_9,  8),
    define_register(r10,    Register_10, 8),
    define_register(r11,    Register_11, 8),
    define_register(r12,    Register_12, 8),
    define_register(r13,    Register_13, 8),
    define_register(r14,    Register_14, 8),
    define_register(r15,    Register_15, 8),

    /* 32-bit registers */
    define_register(eax,    Register_A,  4),
    define_register(ecx,    Register_C,  4),
    define_register(edx,    Register_D,  4),
    define_register(ebx,    Register_B,  4),
    define_register(esp,    Register_SP, 4),
    define_register(ebp,    Register_BP, 4),
    define_register(esi,    Register_SI, 4),
    define_register(edi,    Register_DI, 4),
    define_register(r8d,    Register_8,  4),
    define_register(r9d,    Register_9,  4),
    define_register(r10d,   Register_10, 4),
    define_register(r11d,   Register_11, 4),
    define_register(r12d,   Register_12, 4),
    define_register(r13d,   Register_13, 4),
    define_register(r14d,   Register_14, 4),
    define_register(r15d,   Register_15, 4),

    /* 16-bit registers */
    define_register(ax,     Register_A,  2),
    define_register(cx,     Register_C,  2),
    define_register(dx,     Register_D,  2),
    define_register(bx,     Register_B,  2),
    define_register(sp,     Register_SP, 2),
    define_register(bp,     Register_BP, 2),
    define_register(si,     Register_SI, 2),
    define_register(di,     Register_DI, 2),
    define_register(r8w,    Register_8,  2),
    define_register(r9w,    Register_9,  2),
    define_register(r10w,   Register_10, 2),
    define_register(r11w,   Register_11, 2),
    define_register(r12w,   Register_12, 2),
    define_register(r13w,   Register_13, 2),
    define_register(r14w,   Register_14, 2),
    define_register(r15w,   Register_15, 2),

    /* 8-bit registers */
    define_register(al,     Register_A,  1),
    define_register(cl,     Register_C,  1),
    define_register(dl,     Register_D,  1),
    define_register(bl,     Register_B,  1),
    define_register(ah,     Register_AH, 1),
    define_register(ch,     Register_CH, 1),
    define_register(dh,     Register_DH, 1),
    define_register(bh,     Register_BH, 1),
    define_register(r8b,    Register_8,  1),
    define_register(r9b,    Register_9,  1),
    define_register(r10b,   Register_10, 1),
    define_register(r11b,   Register_11, 1),
    define_register(r12b,   Register_12, 1),
    define_register(r13b,   Register_13, 1),
    define_register(r14b,   Register_14, 1),
    define_register(r15b,   Register_15, 1),
};

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

#define _rel(n, v) { .type = OperandType_Relative, .rel._ ## n = v, .size = OperandSize_ ## n, }
static inline Operand rel8(u8 value)
{
    return (const Operand)_rel(8, value);
}

static inline Operand rel16(u16 value)
{
    return (const Operand)_rel(16, value);
}

static inline Operand rel32(u32 value)
{
    return (const Operand)_rel(32, value);
}

static inline Operand rel48(u64 value)
{
    return (const Operand)_rel(48, value);
}

static inline Operand rel64(u64 value)
{
    return (const Operand)_rel(64, value);
}

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
            .reg = reg.rbp.reg,
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
    OET_Relative,
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
    u8 op_code[4];
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
#define OP_CODE(...) { __VA_ARGS__ }
#define OPTS(...) __VA_ARGS__
#define NO_OPTS .rex_byte = 0
#define OPS(...) .operands = { __VA_ARGS__ }
#define OP_COMB(_ops, _opts) { _ops, _opts }
#define ENC_OPTS(...) .options = { __VA_ARGS__ }
#define ENCODING(_op_code, options, ...) { .op_code = _op_code, options, .operand_combinations = { __VA_ARGS__ }, }

const InstructionEncoding adc_encoding[] =
{
    ENCODING(OP_CODE(0x14),ENC_OPTS(0),
        OP_COMB(OPTS(0),      OPS(OP(OET_Register_A, 8), OP(OET_Immediate, 8)))
        ),
    ENCODING(OP_CODE(0x15), ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_A, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(NO_OPTS),		OPS(OP(OET_Register_A, 32), OP(OET_Immediate, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_A, 64), OP(OET_Immediate, 32))),
        ),
    ENCODING(OP_CODE(0x80), ENC_OPTS(.type = Digit, .digit = 2),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Immediate, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Immediate, 8))),
        ),
    ENCODING(OP_CODE(0x81), ENC_OPTS(.type = Digit, .digit = 2),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 32))),
        ),
    ENCODING(OP_CODE(0x83), ENC_OPTS(.type = Digit, .digit = 2),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 8))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 8))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 8))),
        ),
    ENCODING(OP_CODE(0x10), ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
        ),
    ENCODING(OP_CODE(0x11),ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Register, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Register, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Register, 64))),
        ),
    ENCODING(OP_CODE(0x12),ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
        ),
    ENCODING(OP_CODE(0x13),ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register, 16), OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register, 32), OP(OET_Register_Or_Memory, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register, 64), OP(OET_Register_Or_Memory, 64))),
        ),
};


// @TODO:
const InstructionEncoding adcx_encoding[] = {0};
const InstructionEncoding add_encoding[] =
{
    ENCODING(OP_CODE(0x04),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_A, 8), OP(OET_Immediate, 8))),
    ),
    ENCODING(OP_CODE(0x05),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_A, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_A, 32), OP(OET_Immediate, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_A, 64), OP(OET_Immediate, 32))),
    ),
    ENCODING(OP_CODE(0x80),ENC_OPTS(.type = Digit, .digit = 0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory,8), OP(OET_Immediate, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register_Or_Memory,8), OP(OET_Immediate, 8))),
        ),
    ENCODING(OP_CODE(0x81),ENC_OPTS(.type = Digit, .digit = 0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 32))),
    ),
    ENCODING(OP_CODE(0x83),ENC_OPTS(.type = Digit, .digit = 0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 8))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 8))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 8))),
    ),
    ENCODING(OP_CODE(0x00),ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
    ),
    ENCODING(OP_CODE(0x01),ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Register, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Register, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Register, 64))),
    ),
    ENCODING(OP_CODE(0x02),ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
    ),
    ENCODING(OP_CODE(0x03),ENC_OPTS(.type = Reg),
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
    ENCODING(OP_CODE(0xFF), ENC_OPTS(.type = Digit, .digit = 2),
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
const InstructionEncoding cmp_encoding[] =
{
    ENCODING(OP_CODE(0x3C), ENC_OPTS(0),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register_A, 8), OP(OET_Immediate, 8))),
    ),
    ENCODING(OP_CODE(0x3D), ENC_OPTS(0),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register_A, 16), OP(OET_Immediate, 16))),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register_A, 32), OP(OET_Immediate, 32))),
    	OP_COMB(OPTS(.rex_byte = RexW), OPS(OP(OET_Register_A, 64), OP(OET_Immediate, 32))),
    ),
    ENCODING(OP_CODE(0x80), ENC_OPTS(.type = Digit, .digit = 7),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Immediate, 8))),
    	OP_COMB(OPTS(.rex_byte = Rex), OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Immediate, 8))),
        ),
    ENCODING(OP_CODE(0x81), ENC_OPTS(.type = Digit, .digit = 7),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 16))),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 32))),
    	OP_COMB(OPTS(.rex_byte = RexW), OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 32))),
        ),
    ENCODING(OP_CODE(0x83), ENC_OPTS(.type = Digit, .digit = 7),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 8))),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 8))),
    	OP_COMB(OPTS(.rex_byte = RexW), OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 8))),
        ),
    ENCODING(OP_CODE(0x38), ENC_OPTS(.type = Reg),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
    	OP_COMB(OPTS(.rex_byte = Rex), OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
        ),
    ENCODING(OP_CODE(0x39), ENC_OPTS(.type = Reg),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Register, 16))),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Register, 32))),
    	OP_COMB(OPTS(.rex_byte = RexW), OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Register, 64))),
        ),
    ENCODING(OP_CODE(0x3A), ENC_OPTS(.type = Reg),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
    	OP_COMB(OPTS(.rex_byte = Rex), OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
        ),
    ENCODING(OP_CODE(0x3B), ENC_OPTS(.type = Reg),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register, 16), OP(OET_Register_Or_Memory, 16))),
    	OP_COMB(OPTS(0), OPS(OP(OET_Register, 32), OP(OET_Register_Or_Memory, 32))),
    	OP_COMB(OPTS(.rex_byte = RexW), OPS(OP(OET_Register, 64), OP(OET_Register_Or_Memory, 64))),
        ),
};

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

const InstructionEncoding ja_encoding[] =
{
    ENCODING(OP_CODE(0x77), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x87), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jae_encoding[] =
{
    ENCODING(OP_CODE(0x73), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x83), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jb_encoding[] =
{
    ENCODING(OP_CODE(0x72), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x82), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jbe_encoding[] =
{
    ENCODING(OP_CODE(0x76), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x86), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jc_encoding[] =
{
    ENCODING(OP_CODE(0x72), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x82), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jecxz_encoding[] =
{
    ENCODING(OP_CODE(0xE3), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
};
const InstructionEncoding jrcxz_encoding[] =
{
    ENCODING(OP_CODE(0xE3), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
};
const InstructionEncoding je_encoding[] =
{
    ENCODING(OP_CODE(0x74), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x84), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jg_encoding[] =
{
    ENCODING(OP_CODE(0x7F), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x8F), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jge_encoding[] =
{
    ENCODING(OP_CODE(0x7D), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x8D), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jl_encoding[] =
{
    ENCODING(OP_CODE(0x7C), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x8C), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jle_encoding[] =
{
    ENCODING(OP_CODE(0x7E), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x8E), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jna_encoding[] =
{
    ENCODING(OP_CODE(0x76), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x86), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jnae_encoding[] =
{
    ENCODING(OP_CODE(0x72), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x82), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jnb_encoding[] =
{
    ENCODING(OP_CODE(0x73), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x83), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jnbe_encoding[] =
{
    ENCODING(OP_CODE(0x77), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x87), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jnc_encoding[] =
{
    ENCODING(OP_CODE(0x73), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x83), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jne_encoding[] =
{
    ENCODING(OP_CODE(0x75), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x85), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jng_encoding[] =
{
    ENCODING(OP_CODE(0x7E), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x8E), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jnge_encoding[] =
{
    ENCODING(OP_CODE(0x7C), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x8C), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jnl__encoding[] =
{
    ENCODING(OP_CODE(0x7D), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x8D), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jnle_encoding[] =
{
    ENCODING(OP_CODE(0x7F), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x8F), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jno_encoding[] =
{
    ENCODING(OP_CODE(0x71), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x81), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jnp_encoding[] =
{
    ENCODING(OP_CODE(0x7B), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x8B), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jns_encoding[] =
{
    ENCODING(OP_CODE(0x79), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x89), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jnz_encoding[] =
{
    ENCODING(OP_CODE(0x75), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x85), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jo_encoding[] =
{
    ENCODING(OP_CODE(0x70), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x80), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jp_encoding[] =
{
    ENCODING(OP_CODE(0x7A), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x8A), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jpe_encoding[] =
{
    ENCODING(OP_CODE(0x7A), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x8A), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jpo_encoding[] =
{
    ENCODING(OP_CODE(0x7B), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x8B), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding js_encoding[] =
{
    ENCODING(OP_CODE(0x78), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x88), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};
const InstructionEncoding jz_encoding[] =
{
    ENCODING(OP_CODE(0x74), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0x0F, 0x84), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
};

const InstructionEncoding jmp_encoding[] =
{
    0
};

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
    ENCODING(OP_CODE(0x88), ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
    ),
    ENCODING(OP_CODE(0x89), ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Register, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Register, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Register, 64))),
    ),
    ENCODING(OP_CODE(0x8A), ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
    ),
    ENCODING(OP_CODE(0x8B), ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 16), OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 32), OP(OET_Register_Or_Memory, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register, 64), OP(OET_Register_Or_Memory, 64))),
    ),
    /*  @TODO: NOT CODED SEGMENT AND OFFSET INSTRUCTIONS */
    ENCODING(OP_CODE(0xB0), ENC_OPTS(.type = OpCodePlusReg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 8), OP(OET_Immediate, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register, 8), OP(OET_Immediate, 8))),
    ),
    ENCODING(OP_CODE(0xB8), ENC_OPTS(.type = OpCodePlusReg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 32), OP(OET_Immediate, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register, 64), OP(OET_Immediate, 64))),
    ),
    ENCODING(OP_CODE(0xC6), ENC_OPTS(.type = Digit, .digit = 0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Immediate, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Immediate, 8))),
    ),
    ENCODING(OP_CODE(0xC7), ENC_OPTS(.type = Digit, .digit = 0),
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
    ENCODING(OP_CODE(0x58), ENC_OPTS(.type = OpCodePlusReg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 64))),
    ),
    ENCODING(OP_CODE(0x8f), ENC_OPTS(.type = Digit, .digit = 0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 64))),
    ),
    ENCODING(OP_CODE(0x6A), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Immediate, 8))),
    ),
    // @TODO: these need two-byte opcode
    //// Pop FS
    //ENCODING(OP_CODE(0x0f 0xa1,
    //    OP_COMB(OPTS(0), OPS(0)),
    //),
    //// Pop GS
    //ENCODING(OP_CODE(0x0f 0xa9,
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
    ENCODING(OP_CODE(0x50), ENC_OPTS(.type = OpCodePlusReg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 64))),
    ),
    ENCODING(OP_CODE(0xff), ENC_OPTS(.type = Digit, .digit = 6),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 64))),
    ),
    ENCODING(OP_CODE(0x6A), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Immediate, 8))),
    ),
    ENCODING(OP_CODE(0x68), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Immediate, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Immediate, 32))),
    ),
    // @TODO: these need two-byte opcode
    //// Push FS
    //ENCODING(OP_CODE(0x0f 0xa0,
    //    OP_COMB(OPTS(0), OPS(0)),
    //),
    //// Push GS
    //ENCODING(OP_CODE(0x0f 0xa8,
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
    ENCODING(OP_CODE(0xC3), ENC_OPTS(0)),
    ENCODING(OP_CODE(0xCB), ENC_OPTS(0)),
    ENCODING(OP_CODE(0xC2), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Immediate, 16))),
    ),
    ENCODING(OP_CODE(0xCA), ENC_OPTS(0),
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
define_mnemonic(cmp);

define_mnemonic(ja);
define_mnemonic(jae);
define_mnemonic(jb);
define_mnemonic(jbe);
define_mnemonic(jc);
define_mnemonic(jecxz);
define_mnemonic(jrcxz);
define_mnemonic(je);
define_mnemonic(jg);
define_mnemonic(jge);
define_mnemonic(jl);
define_mnemonic(jle);
define_mnemonic(jna);
define_mnemonic(jnae);
define_mnemonic(jnb);
define_mnemonic(jnbe);
define_mnemonic(jnc);
define_mnemonic(jne);
define_mnemonic(jng);
define_mnemonic(jnge);
define_mnemonic(jnl_);
define_mnemonic(jnle);
define_mnemonic(jno);
define_mnemonic(jnp);
define_mnemonic(jns);
define_mnemonic(jnz);
define_mnemonic(jo);
define_mnemonic(jp);
define_mnemonic(jpe);
define_mnemonic(jpo);
define_mnemonic(js);
define_mnemonic(jz);

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
                    case OperandType_Relative:
                        if (operand_encoding.type == OET_Relative && operand_encoding.size == operand.size)
                        {
                            continue;
                        }
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

    u8 rex_byte = combination.rex_byte;

    for (u32 i = 0; i < array_length(instruction.operands); i++)
    {
        Operand op = instruction.operands[i];
        if (op.type == OperandType_Register && op.reg & Register_N_Flag)
        {
            if (encoding.options.type == Digit)
            {
                rex_byte |= RexR;
            }
            else if (encoding.options.type == OpCodePlusReg)
            {
                rex_byte |= RexB;
            }
        }
    }

    u8 reg_code;
    u8 op_code[4] = { encoding.op_code[0], encoding.op_code[1], encoding.op_code[2], encoding.op_code[3] };

    if (encoding.options.type == OpCodePlusReg)
    {
        u8 plus_reg_op_code = op_code[0];
        for (u32 i = 1; i < array_length(op_code); i++)
        {
            redassert(op_code[i] == 0);
        }
        reg_code = instruction.operands[0].reg;
        bool d = plus_reg_op_code & 0b10;
        bool s = plus_reg_op_code & 0b1;
        plus_reg_op_code = (plus_reg_op_code & 0b11111000) | (reg_code & 0b111);
        op_code[0] = plus_reg_op_code;

    }

    // MOD RM
    bool need_sib = false;
    u8 sib_byte = 0;
    bool is_digit = encoding.options.type == Digit;
    bool is_reg = encoding.options.type == Reg;
    bool need_mod_rm = is_digit || is_reg;

    u8 register_or_digit;
    u8 r_m = 0;
    u8 mod = 0;
    u8 mod_r_m = 0;

    if (need_mod_rm)
    {
        for (u32 oi = 0; oi < operand_count; oi++)
        {
            Operand operand = instruction.operands[oi];
            switch (operand.type)
            {
                case OperandType_Register:
                    if (operand.reg & Register_N_Flag)
                    {
                        rex_byte |= RexB;
                    }
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
                    need_sib = operand.mem_indirect.reg == reg.rsp.reg;
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

        mod_r_m = (
            (mod << 6) |
            (register_or_digit << 3) |
            (r_m)
            );

    }

    if (rex_byte)
    {
        u8_append(eb, rex_byte);
    }
    else if ((instruction.operands[0].type == OperandType_Register && instruction.operands[0].size == OperandSize_16) || (instruction.operands[1].type == OperandType_Register && instruction.operands[1].size == OperandSize_16))
    {
        u8_append(eb, OperandSizeOverride);
    }

    for (u32 i = 0; i < array_length(op_code); i++)
    {
        u8 op_code_byte = op_code[i];
        if (op_code_byte)
        {
            u8_append(eb, op_code_byte);
        }
    }

    if (need_mod_rm)
    {
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
                    RED_NOT_IMPLEMENTED;
                    break;
            }
        }
        else if (operand.type == OperandType_Relative)
        {
            switch (operand.size)
            {
                case OperandSize_8:
                    u8_append(eb, operand.rel._8);
                    break;
                case OperandSize_16:
                    u16_append(eb, operand.rel._16);
                    break;
                case OperandSize_32:
                    u32_append(eb, operand.rel._32);
                    break;
                case OperandSize_64:
                    u64_append(eb, operand.rel._64);
                    break;
                default:
                    RED_NOT_IMPLEMENTED;
                    break;
            }
        }
    }
}

static void test_adc_al_imm8(void* s)
{
    u8 n = 0x1;
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) {adc, {reg.al, imm8(n)}});

    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0x14);
    u8_append(&expected, n);

    test_buffer(&eb, expected.ptr, expected.len, __func__);
}
static void test_adc_ax_imm16(void* s)
{
    u16 n = 0x1234;
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) {adc, {reg.ax, imm16(n)}});

    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0x15);
    u16_append(&expected, n);

    test_buffer(&eb, expected.ptr, expected.len, __func__);
}

static void test_adc_eax_imm32(void* s)
{
    u32 n = 0x123456;
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) {adc, {reg.eax, imm32(n)}});

    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0x15);
    u32_append(&expected, n);

    test_buffer(&eb, expected.ptr, expected.len, __func__);
}
static void test_adc_rax_imm32(void* s)
{
    u32 n = 0x123456;
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) {adc, {reg.rax, imm32(n)}});

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
    encode(&eb, (Instruction) {adc, {reg.rbx, stack(n, sizeof(n))}});

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
    TEST(add_ax_imm16, INSTR(add, { reg.ax, imm16(0xffff) }), EXPECTED(0x66, 0x05, 0xff, 0xff)));
    TEST(add_al_imm8, INSTR(add, { reg.al, imm8(0xff) }), EXPECTED(0x04, UINT8_MAX)));
    TEST(add_eax_imm32, INSTR(add, { reg.eax, imm32(0xffffffff) }), EXPECTED(0x05, 0xff, 0xff, 0xff, 0xff)));
    TEST(add_rax_imm32, INSTR(add, { reg.rax, imm32(0xffffffff) }), EXPECTED(0x48, 0x05, 0xff, 0xff, 0xff, 0xff)));
    TEST(add_rm8_imm8, INSTR(add, { reg.bl, imm8(0xff) }), EXPECTED(0x80, 0xc3, 0xff)));
    TEST(add_rm16_imm16, INSTR(add, { reg.bx, imm16(0xffff) }), EXPECTED(0x66, 0x81, 0xc3, 0xff, 0xff)));
    TEST(add_rm32_imm32, INSTR(add, { reg.ebx, imm32(0xffffffff) }), EXPECTED(0x81, 0xc3, 0xff, 0xff, 0xff, 0xff)));
    TEST(add_rm64_imm32, INSTR(add, { reg.rbx, imm32(0xffffffff) }), EXPECTED(0x48, 0x81, 0xc3, 0xff, 0xff, 0xff, 0xff)));
    TEST(call_r64, INSTR(call, { reg.rax }), EXPECTED(0xff, 0xd0)));
    TEST(mov_bl_cl, INSTR(mov, { reg.bl, reg.cl }), EXPECTED(0x88, 0xcb)));
    TEST(mov_bx_cx, INSTR(mov, { reg.bx, reg.cx }), EXPECTED(0x66, 0x89, 0xcb)));
    TEST(mov_ebx_ecx, INSTR(mov, { reg.ebx, reg.ecx }), EXPECTED(0x89, 0xcb)));
    TEST(mov_rbx_rcx, INSTR(mov, { reg.rbx, reg.rcx }), EXPECTED(0x48, 0x89, 0xcb)));
    TEST(mov_al_imm8, INSTR(mov, { reg.al, imm8(0xff) }), EXPECTED(0xb0, UINT8_MAX)));
    TEST(mov_ax_imm16, INSTR(mov, { reg.ax, imm16(0xffff) }), EXPECTED(0x66, 0xb8, 0xff, 0xff)));
    TEST(mov_eax_imm32, INSTR(mov, { reg.eax, imm32(0xffffffff) }), EXPECTED(0xb8, 0xff, 0xff)));
    TEST(mov_rax_imm32, INSTR(mov, { reg.rax, imm32(0xffffffff) }), EXPECTED(0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff)));
    TEST(mov_rax_imm64, INSTR(mov, { reg.rax, imm64(0xffffffffffffffff) }), EXPECTED(0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)));
    TEST(mov_r8_imm8,   INSTR(mov, { reg.bl, imm8(0xff) }), EXPECTED(0xb3, 0xff)));
    TEST(mov_r16_imm16, INSTR(mov, { reg.bx, imm16(0xffff) }), EXPECTED(0x66, 0xbb, 0xff, 0xff)));
    TEST(mov_r32_imm32, INSTR(mov, { reg.ebx, imm32(0xffffffff) }), EXPECTED(0xbb, 0xff, 0xff, 0xff, 0xff)));
    TEST(mov_r64_imm64, INSTR(mov, { reg.rbx, imm64(0xffffffffffffffff) }), EXPECTED(0x48, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)));
    TEST(mov_rm64_imm32, INSTR(mov, { reg.rbx, imm32(0xffffffff) }), EXPECTED(0x48, 0xc7, 0xc3, 0xff, 0xff, 0xff, 0xff)));
    TEST(mov_qword_ptr_r64_offset_r64, INSTR(mov, { stack(-8, 8), reg.rdi }), EXPECTED(0x48, 0x89, 0x7d, 0xf8)));
    TEST(mov_rax_qword_ptr_r64_offset_r64, INSTR(mov, { reg.rax, stack(-8, 8)}), EXPECTED(0x48, 0x8b, 0x45, 0xf8)));
    TEST(pop_r64, INSTR(pop, { reg.rbp }), EXPECTED(0x5d)));
    TEST(push_r64, INSTR(push, { reg.rbp }), EXPECTED(0x55)));
    TEST(push_r9, INSTR(push, { reg.r9 }), EXPECTED(0x41, 0x51)));
}

typedef struct FunctionBuilder
{
    DescriptorFunction descriptor;
    ExecutionBuffer eb;
    s32 stack_offset;
    u8 next_arg;
} FunctionBuilder;

Operand declare_variable(FunctionBuilder* fn_builder, s32 size)
{
    fn_builder->stack_offset -= size;

    return stack(fn_builder->stack_offset, size);
}

void assign(FunctionBuilder* fn_builder, Operand a, Operand b)
{
    encode(&fn_builder->eb, (Instruction) { mov, {a, b} });
}

Operand do_add(FunctionBuilder* fn_builder, Operand a, Operand b)
{
    encode(&fn_builder->eb, (Instruction) { add, { a, b } });
    return a;
}

FunctionBuilder fn_begin(void)
{
    FunctionBuilder fn_builder = {.eb = give_me(1024) };

    fn_builder.descriptor.arg_list = malloc(sizeof(Value) * array_length(parameter_registers));
    fn_builder.descriptor.return_value = malloc(sizeof(Value));
    encode(&fn_builder.eb, (Instruction) { push, { reg.rbp } });
    encode(&fn_builder.eb, (Instruction) { mov, { reg.rbp, reg.rsp } });

    return fn_builder;
}

Value fn_arg(FunctionBuilder* fn_builder, Descriptor arg_descriptor)
{
    redassert(fn_builder->next_arg < array_length(parameter_registers));
    // @TODO: hardcoded 64-bit register
    u32 size_index = register_size_jump_table[OperandSize_64];
    u32 register_index = parameter_registers[fn_builder->next_arg];
    Value arg = 
    {
        .descriptor = arg_descriptor,
        .operand = reg.arr[size_index][register_index],
    };

    fn_builder->next_arg++;
    return arg;
};

Value fn_end(FunctionBuilder* fn_builder)
{
    fn_builder->descriptor.arg_count = fn_builder->next_arg;
    return (const Value)
    {
        .descriptor = (const Descriptor) {.type = Function, .function = fn_builder->descriptor},
        .operand = imm64((u64)fn_builder->eb.ptr),
    };
}

void fn_return(FunctionBuilder* fn_builder, Value to_return)
{
    *fn_builder->descriptor.return_value = to_return;
    // @TODO: hardcoded 64-bit register
    u32 size_index = register_size_jump_table[OperandSize_64];
    u32 register_index = return_registers[0];
    Operand ret_reg = reg.arr[size_index][register_index];

    if (memcmp(&ret_reg, &to_return, sizeof(to_return)) != 0)
    {
        encode(&fn_builder->eb, (Instruction) { mov, { ret_reg, to_return.operand }});
    }

    encode(&fn_builder->eb, (Instruction) { pop, { reg.rbp } });
    encode(&fn_builder->eb, (Instruction) { ret });
}

void test_abstract_fn()
{
    FunctionBuilder fn_builder = fn_begin();
    Operand var = declare_variable(&fn_builder, 4);
    assign(&fn_builder, var, reg.edi);
    assign(&fn_builder, reg.eax, var);
    Operand add_result = do_add(&fn_builder, reg.eax, var);
    fn_return(&fn_builder, (const Value) { .descriptor = { .type = Integer }, .operand = add_result });

    u8 expected[] = { 0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xfc, 0x8b, 0x45, 0xfc, 0x03, 0x45, 0xfc, 0x5d, 0xc3 };
    test_buffer(&fn_builder.eb, expected, array_length(expected), __func__);

    typedef int SumFn(int);
    SumFn* sum = (SumFn*) fn_builder.eb.ptr;
    int n = 5;
    int result = sum(n);
    print("Result %d\n", result);
    print("Expected %d\n", n + n);
}

typedef s32 RetS32(void);

RetS32* make_ret_s32(void)
{
    FunctionBuilder fn_builder = fn_begin();
    Operand var = declare_variable(&fn_builder, 4);
    assign(&fn_builder, var, imm32(18293));
    fn_return(&fn_builder, (const Value) {.descriptor = { .type = Integer}, .operand = var });

    return (RetS32*)fn_builder.eb.ptr;
}

typedef s32 ProxyFn(RetS32);

// This can implement simple lambdas
void test_proxy_fn(void)
{
    FunctionBuilder fn_builder = fn_begin();
    encode(&fn_builder.eb, (Instruction) {call, {reg.rdi}});
    fn_return(&fn_builder, (const Value) {.descriptor = {.type = Integer}, .operand = reg.rax });

    RetS32* ret_s32 = make_ret_s32();
    ProxyFn* proxy_fn = (ProxyFn*)fn_builder.eb.ptr;
    s32 result = proxy_fn(ret_s32);
    print("Result: %d\n", result);
}

typedef s32 s32_s32(s32);

typedef struct LabelPatch
{
    u8* address;
    s64 ip;
} LabelPatch;

LabelPatch make_jnz(FunctionBuilder* fn_builder)
{
    encode(&fn_builder->eb, (Instruction) { jnz, { rel8(0xcc) } });
    s64 ip = fn_builder->eb.len;
    u8* patch = &fn_builder->eb.ptr[ip - 1];

    return (LabelPatch) { patch, ip };
}

void make_jump_label(FunctionBuilder* fn_builder, LabelPatch patch)
{
    u8 diff = (fn_builder->eb.len - patch.ip);
    redassert(diff <= 0x80);
    *patch.address = diff;
}

Value fn_call(FunctionBuilder* fn_builder, Value* fn, Value* arg_list, s64 arg_count)
{
    redassert(fn->descriptor.type == Function);
    redassert(fn->descriptor.function.arg_list);
    redassert(fn->descriptor.function.arg_count == arg_count);
    // @TODO: type-check arguments
    u32 size_index = register_size_jump_table[OperandSize_64];
    for (s64 i = 0; i < arg_count; i++)
    {
        u32 register_index_param = parameter_registers[i];
        Operand param_reg = reg.arr[size_index][register_index_param];
        encode(&fn_builder->eb, (Instruction) {mov, {param_reg, arg_list[i].operand }});
    }

    encode(&fn_builder->eb, (Instruction) {mov, {reg.rax, fn->operand }});
    encode(&fn_builder->eb, (Instruction) {call, {reg.rax}});

    return *fn->descriptor.function.return_value;
}

void make_is_non_zero(void)
{
    FunctionBuilder fn_builder = fn_begin();
    Value n = fn_arg(&fn_builder, (const Descriptor) {.type = Integer, });
    encode(&fn_builder.eb, (Instruction) { cmp, { n.operand, imm32(0) } });
    LabelPatch patch = make_jnz(&fn_builder);
    fn_return(&fn_builder, (const Value) {.descriptor = {.type = Integer,}, .operand = imm32(0)} );
    make_jump_label(&fn_builder, patch);
    fn_return(&fn_builder, (const Value) {.descriptor = {.type = Integer,}, .operand = imm32(1)});

    s32_s32* function = (s32_s32*)fn_builder.eb.ptr;
    print("Should be 0: %d\n", function(0));
    print("Should be 1: %d\n", function(-128391));
}

Value make_partial_application_s64(Value* original_fn, s64 arg)
{
    FunctionBuilder fn_builder = fn_begin();
    Value applied_arg0 = 
    {
        .descriptor = {.type = Integer},
        .operand = imm64(arg),
    };

    Value result = fn_call(&fn_builder, original_fn, &applied_arg0, 1);
    fn_return(&fn_builder, result);

    return fn_end(&fn_builder);
}

Value make_identity_s64()
{
    FunctionBuilder fn_builder = fn_begin();
    Value arg0 = fn_arg(&fn_builder, (const Descriptor) { .type = Integer });
    fn_return(&fn_builder, arg0);
    return fn_end(&fn_builder);
}

typedef s64 (fn_type_void_to_s64)(void);
void make_simple_lambda(void)
{
    Value id_value = make_identity_s64();
    Value partial_fn_value = make_partial_application_s64(&id_value, 42);
    fn_type_void_to_s64* result_fn = (fn_type_void_to_s64*)partial_fn_value.operand.imm._64;
    s64 result = result_fn();
    redassert (result == 42);
}

u64 helper_value_as_function(Value * value)
{
    redassert(value->operand.type == OperandType_Immediate && value->operand.size == OperandSize_64);
    return value->operand.imm._64;
}

#define value_as_function(_value_, _type_) ((_type_*)helper_value_as_function(_value_))

typedef void VoidRetVoid(void);
void print_fn(void)
{
    const char* message = "Hello world!\n";
    Descriptor message_descriptor =
    {
        .type = FixedSizeArray,
        .fixed_size_array =
        {
            .data = &(Descriptor){.type = Integer,},
            .len = strlen(message) + 1,
        },
    };
    Value printf_arg =
    {
        .descriptor = { .type = Pointer, .pointer_to = &message_descriptor },
        .operand = reg.rcx,
    };
    Value dummy_return = 
    {
        .descriptor = {.type = Integer},
        .operand = imm32(0),
    };
    Value printf_value =
    {
        .descriptor = { .type = Function, .function = { .arg_list = &printf_arg, .arg_count = 1, .return_value = &dummy_return} },
        .operand = imm64((u64)printf),
    };

    FunctionBuilder fn_builder = fn_begin();
    Value message_value = 
    {
        .descriptor = {.type = Pointer},
        .operand = imm64((u64)message),
    };

    fn_call(&fn_builder, &printf_value, &message_value, 1);

    fn_return(&fn_builder, dummy_return);
    Value fn_value = fn_end(&fn_builder);

    value_as_function(&fn_value, VoidRetVoid)();
}

void wna_main(s32 argc, char* argv[])
{
    print_fn();
}

s32 main(s32 argc, char* argv[])
{
#if TEST_MODE
    test_main(argc, argv);
#else
    wna_main(argc, argv);
#endif
}
