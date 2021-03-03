#include "types.h"
#include "os.h"
#include "execution_buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#ifdef RED_OS_WINDOWS
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#ifdef RED_OS_WINDOWS
#define MSVC_x86_64 1
#define SYSTEM_V_x86_64 0
#else
#if defined(RED_OS_LINUX)
#define MSVC_x86_64 0
#define SYSTEM_V_x86_64 1
#else
#error
#endif
#endif

typedef enum CallingConvention
{
    MSVC,
    SYSTEMV,
} CallingConvention;
CallingConvention calling_convention =
#ifdef RED_OS_WINDOWS
MSVC;
#else
#ifdef RED_OS_LINUX
SYSTEMV;
#else
#error
#endif
#endif

static inline s64 align(s64 number, s64 alignment)
{
    return (s64)(ceil((double)number / alignment) * alignment);
}

typedef s64 square_fn(s64);
typedef s64 mul_fn(s64, s64);

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

struct Descriptor;
typedef enum DescriptorType
{
    DescriptorType_Void,
    DescriptorType_Integer,
    DescriptorType_Pointer,
    DescriptorType_FixedSizeArray,
    DescriptorType_Function,
    DescriptorType_Struct,
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
    const struct Descriptor* data;
    s64 len;
} DescriptorFixedSizeArray;

typedef struct DescriptorInteger
{
    u32 size;
} DescriptorInteger;

typedef struct DescriptorStructField
{
    const struct Descriptor* descriptor;
    s64 offset;
} DescriptorStructField;

typedef struct DescriptorStruct
{
    struct DescriptorStructField* field_list;
    s64 field_count;
} DescriptorStruct;

typedef struct Descriptor
{
    DescriptorType type;
    union
    {
        DescriptorInteger integer;
        DescriptorFunction function;
        struct Descriptor* pointer_to;
        DescriptorFixedSizeArray fixed_size_array;
        DescriptorStruct struct_;
    };
} Descriptor;

const u32 pointer_size = sizeof(usize);

s64 descriptor_size(const Descriptor* descriptor)
{
    DescriptorType type = descriptor->type;
    switch (type)
    {
        case DescriptorType_Void:
            return 0;
        case DescriptorType_Struct:
        {
            s64 field_count = descriptor->struct_.field_count;
            redassert(field_count);
            s64 alignment = 0;
            s64 raw_size = 0;

            for (s64 i = 0; i < field_count; i++)
            {
                DescriptorStructField* field = &descriptor->struct_.field_list[i];
                s64 field_size = descriptor_size(field->descriptor);
                alignment = MAX(alignment, field_size);
                bool is_last_field = i == field_count - 1;
                if (is_last_field)
                {
                    raw_size = field->offset + field_size;
                }
            }

            return align(raw_size, alignment);
        }
        case DescriptorType_Integer:
            return descriptor->integer.size;
        case DescriptorType_Pointer:
            return pointer_size;
        case DescriptorType_FixedSizeArray:
            return descriptor_size(descriptor->fixed_size_array.data) * descriptor->fixed_size_array.len;
        case DescriptorType_Function:
            return pointer_size;
        default:
            RED_NOT_IMPLEMENTED;
            return 0;
    }
}

#define define_descriptor(_type_)\
    const Descriptor descriptor_ ## _type_ =\
    {\
        .type = DescriptorType_Integer,\
        .integer = { .size = sizeof(_type_) },\
    }

define_descriptor(u8);
define_descriptor(u16);
define_descriptor(u32);
define_descriptor(u64);
define_descriptor(s8);
define_descriptor(s16);
define_descriptor(s32);
define_descriptor(s64);

typedef struct Value
{
    Descriptor descriptor;
    Operand operand;
} Value;

Value _void_value_v =
{
    .descriptor = { .type = DescriptorType_Void, },
    .operand = { .type = OperandType_None },
};
Value* void_value = &_void_value_v;

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
        const Operand rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15;
        /* 32-bit registers */
        const Operand eax, ecx, edx, ebx, esp, ebp, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d;
        /* 16-bit registers */
        const Operand ax, cx, dx, bx, sp, bp, si, di, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w;
        /* 8-bit registers */
        const Operand al, cl, dl, bl, ah, ch, dh, bh, r8b, r9b, r10b, r11b, r12b, r13b, r14b, r15b;
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

static inline Operand rel64(u64 value)
{
    return (const Operand)_rel(64, value);
}

static inline Register get_stack_register(void)
{
    switch (calling_convention)
    {
        case MSVC:
            return reg.rsp.reg;
        case SYSTEMV:
            return reg.rbp.reg;
            break;
        default:
            RED_NOT_IMPLEMENTED;
            return 0;
    }
}

static inline Operand stack(s32 offset, s32 size)
{
    return (const Operand)
    {
        .type = OperandType_MemoryIndirect,
        .mem_indirect =
        {
            .reg = get_stack_register(),
            .displacement = offset,
        },
        .size = size,
    };
}

static inline Operand get_reg(OperandSize reg_size, Register reg_index)
{
    return reg.arr[register_size_jump_table[reg_size]][reg_index];
}

static inline Value* reg_value(Register reg, const Descriptor* descriptor)
{
    s64 size = descriptor_size(descriptor);
    redassert(
        size == sizeof(s8) ||
        size == sizeof(s16) ||
        size == sizeof(s32) ||
        size == sizeof(s64)
    );

    Value* result = NEW(Value, 1);
    *result = (Value){
        .descriptor = *descriptor,
        .operand = get_reg(size, reg),
    };

    return result;
}

static inline Value* s32_value(s32 v)
{
    Value* result = NEW(Value, 1);
    *result = (const Value)
    {
        .descriptor = descriptor_s32,
        .operand = imm32(v),
    };
    return result;
}
static inline Value* s64_value(s64 v)
{
    Value* result = NEW(Value, 1);
    *result = (const Value)
    {
        .descriptor = descriptor_s64,
        .operand = imm64(v),
    };
    return result;
}

Descriptor* descriptor_pointer_to(Descriptor* descriptor)
{
    Descriptor* result = NEW(Descriptor, 1);
    *result = (const Descriptor){
        .type = DescriptorType_Pointer,
        .pointer_to = descriptor,
    };
    return result;
}
#if 0
static inline Value* pointer_value(u64 address)
{
    Value* result = NEW(Value, 1);
    *result = (const Value)
    {
        .descriptor = { .type = DescriptorType_Pointer, },
        .operand = imm64(address),
    };
    return result;
}
#else
static inline Value* pointer_value(u64 address)
{
    Value* result = NEW(Value, 1);
    *result = (const Value)
    {
        .descriptor = { .type = DescriptorType_Pointer, },
        .operand = imm64(address),
    };
    return result;
}
#endif

#if MSVC_x86_64
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

#elif (SYSTEM_V_x86_64)

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


Value* C_function_value(const char* proto, u64 address)
{
    Value* result = NEW(Value, 1);
    *result = (const Value)
    {
        .descriptor = { .type = DescriptorType_Function, },
        .operand = imm64(address),
    };

    if (strstr(proto, "void") == proto)
    {
        result->descriptor.function.return_value = void_value;
    }
    else if (strstr(proto, "int") == proto)
    {
        result->descriptor.function.return_value = NEW(Value, 1);
        *result->descriptor.function.return_value = (const Value)
        {
            .descriptor = descriptor_s32,
            .operand = get_reg(OperandSize_32, return_registers[0]),
        };
    }
    else
    {
        redassert(!"Unknown return type");
    }

    char* it = strchr(proto, '(');
    redassert(it);
    it++;

    char* start = it;

    Value* arg = NEW(Value, 1);
    *arg = (const Value)
    {
        .operand = get_reg(OperandSize_8, parameter_registers[0]),
    };

    for(; *it; it++)
    {
        if (*it == ',')
        {
            redassert(!"Multiple arguments are not supported");
        }
        if (*it == ' ' || *it == ')' || *it == '*')
        {
            s64 length = it - start;

            if (start != it)
            {
                if (strncmp("char", start, length) == 0)
                {
                    arg->descriptor = descriptor_u8,
                    result->descriptor.function.arg_list = arg;
                    result->descriptor.function.arg_count = 1;
                }
                else if (strncmp("const", start, length) == 0)
                {
                    // @TODO
                }
                else
                {
                    redassert("Unsupported argument type");
                }
            }

            start = it + 1;

            if (*it == '*')
            {
                Descriptor* prev_desc = NEW(Descriptor, 1);
                *prev_desc = arg->descriptor;
                arg->descriptor = (const Descriptor)
                {
                    .type = DescriptorType_Pointer,
                        .pointer_to = prev_desc,
                };
            }
        }
    }

    return result;
}

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
    ExplicitByteSize,
} InstructionOptionType;

typedef struct InstructionOptions
{
    InstructionOptionType type;
    u8 digit;
    u8 explicit_byte_size;
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

const InstructionEncoding cwd_encoding[] =
{
    ENCODING(OP_CODE(0x99),ENC_OPTS(.explicit_byte_size = OperandSize_16),
        OP_COMB(OPTS(0), OPS(0))),
};
const InstructionEncoding cdq_encoding[] =
{
    ENCODING(OP_CODE(0x99),ENC_OPTS(.explicit_byte_size = OperandSize_32),
        OP_COMB(OPTS(0), OPS(0))),
};
const InstructionEncoding cqo_encoding[] =
{
    ENCODING(OP_CODE(0x99),ENC_OPTS(.explicit_byte_size = OperandSize_64),
        OP_COMB(OPTS(.rex_byte = RexW), OPS(0)),
    ),
};

const InstructionEncoding dec_encoding[] = { 0 };

// unsigned division
const InstructionEncoding div__encoding[] =
{
    ENCODING(OP_CODE(0xF6),ENC_OPTS(.type = Digit, .digit = 6),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
    ENCODING(OP_CODE(0xF7),ENC_OPTS(.type = Digit, .digit = 6),
        OP_COMB(OPTS(NO_OPTS),              OPS(OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(NO_OPTS),              OPS(OP(OET_Register_Or_Memory, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register_Or_Memory, 64))),
    ),
};

const InstructionEncoding endbr32_encoding[] = { 0 };
const InstructionEncoding endbr64_encoding[] = { 0 };
const InstructionEncoding enter_encoding[] = { 0 };
// Tons of float instructions here
const InstructionEncoding hlt_encoding[] = { 0 };

// signed division
const InstructionEncoding idiv_encoding[] =
{
    ENCODING(OP_CODE(0xF6),ENC_OPTS(.type = Digit, .digit = 7),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
    ENCODING(OP_CODE(0xF7),ENC_OPTS(.type = Digit, .digit = 7),
        OP_COMB(OPTS(NO_OPTS),              OPS(OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(NO_OPTS),              OPS(OP(OET_Register_Or_Memory, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register_Or_Memory, 64))),
    ),
};

// Signed multiply
const InstructionEncoding imul_encoding[] =
{
    ENCODING(OP_CODE(0xF6),ENC_OPTS(.type = Digit, .digit = 5),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
    ENCODING(OP_CODE(0xF7),ENC_OPTS(.type = Digit, .digit = 5),
        OP_COMB(OPTS(NO_OPTS),              OPS(OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(NO_OPTS),              OPS(OP(OET_Register_Or_Memory, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register_Or_Memory, 64))),
    ),
    ENCODING(OP_CODE(0x0F, 0xAF), ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),              OPS(OP(OET_Register, 16), OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(NO_OPTS),              OPS(OP(OET_Register, 32), OP(OET_Register_Or_Memory, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register, 64), OP(OET_Register_Or_Memory, 64))),
    ),
    ENCODING(OP_CODE(0x6B), ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),              OPS(OP(OET_Register, 16), OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 8))),
        OP_COMB(OPTS(NO_OPTS),              OPS(OP(OET_Register, 32), OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 8))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register, 64), OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 8))),
    ),
    ENCODING(OP_CODE(0x69), ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),              OPS(OP(OET_Register, 16), OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(NO_OPTS),              OPS(OP(OET_Register, 32), OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register, 64), OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 32))),
    ),
};

const InstructionEncoding in_encoding[] = { 0 };

const InstructionEncoding inc_encoding[] =
{
    ENCODING(OP_CODE(0xFE), ENC_OPTS(.type = Digit, .digit = 0),
        OP_COMB(OPTS(NO_OPTS),             OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),     OPS(OP(OET_Register_Or_Memory, 8))),
    ),
    ENCODING(OP_CODE(0xFF), ENC_OPTS(.type = Digit, .digit = 0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register_Or_Memory, 64))),
    ),
    ENCODING(OP_CODE(0x40), ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register, 32))),
    ),
};

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
    ENCODING(OP_CODE(0xEB), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 8))),
    ),
    ENCODING(OP_CODE(0xE9), ENC_OPTS(0),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Relative, 32))),
    ),
    ENCODING(OP_CODE(0xFF), ENC_OPTS(.type = Digit, .digit = 4),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 64))),
    ),
    // ... Jump far
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

// Unsigned multiply
const InstructionEncoding mul_encoding[] =
{
    ENCODING(OP_CODE(0xF6), ENC_OPTS(.type = Digit, .digit = 4),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),     OPS(OP(OET_Register_Or_Memory, 8))),
    ),
    ENCODING(OP_CODE(0xF7), ENC_OPTS(.type = Digit, .digit = 4),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 16))),
        OP_COMB(OPTS(0),                    OPS(OP(OET_Register_Or_Memory, 32))),
        OP_COMB(OPTS(.rex_byte = RexW),     OPS(OP(OET_Register_Or_Memory, 64))),
    ),
};

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
    ENCODING(OP_CODE(0xC3), ENC_OPTS(0), {0}),
    ENCODING(OP_CODE(0xCB), ENC_OPTS(0), {0}),
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

const InstructionEncoding seta_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x97),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setae_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x93),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setb_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x92),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setbe_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x96),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setc_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x92),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding sete_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x94),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setg_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x9F),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setge_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x9D),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setl_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x9C),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setle_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x9E),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setna_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x96),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setnae_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x92),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setnb_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x93),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setnbe_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x97),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setnc_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x97),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setne_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x95),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setng_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x9E),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setnge_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x9C),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setnl_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x9D),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setnle_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x9F),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setno_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x91),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setnp_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x9B),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setns_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x99),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setnz_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x95),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding seto_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x90),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setp_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x9A),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setpe_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x9A),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setpo_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x9B),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding sets_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x98),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

const InstructionEncoding setz_encoding[] =
{
    ENCODING(OP_CODE(0x0F, 0x94),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8))),
        OP_COMB(OPTS(.rex_byte = Rex),      OPS(OP(OET_Register_Or_Memory, 8))),
    ),
};

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

const InstructionEncoding sub_encoding[] =
{
    ENCODING(OP_CODE(0x2C),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_A, 8), OP(OET_Immediate, 8))),
    ),
    ENCODING(OP_CODE(0x2D),ENC_OPTS(0),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_A, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_A, 32), OP(OET_Immediate, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_A, 64), OP(OET_Immediate, 32))),
    ),
    ENCODING(OP_CODE(0x80),ENC_OPTS(.type = Digit, .digit = 5),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory,8), OP(OET_Immediate, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register_Or_Memory,8), OP(OET_Immediate, 8))),
        ),
    ENCODING(OP_CODE(0x81),ENC_OPTS(.type = Digit, .digit = 5),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 32))),
    ),
    ENCODING(OP_CODE(0x83),ENC_OPTS(.type = Digit, .digit = 5),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Immediate, 8))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Immediate, 8))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Immediate, 8))),
    ),
    ENCODING(OP_CODE(0x28),ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register_Or_Memory, 8), OP(OET_Register, 8))),
    ),
    ENCODING(OP_CODE(0x29),ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 16), OP(OET_Register, 16))),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register_Or_Memory, 32), OP(OET_Register, 32))),
        OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register_Or_Memory, 64), OP(OET_Register, 64))),
    ),
    ENCODING(OP_CODE(0x2A),ENC_OPTS(.type = Reg),
        OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
        OP_COMB(.rex_byte = Rex,    OPS(OP(OET_Register, 8), OP(OET_Register_Or_Memory, 8))),
    ),
    ENCODING(OP_CODE(0x2B),ENC_OPTS(.type = Reg),
    	OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register, 16), OP(OET_Register_Or_Memory, 16))),
    	OP_COMB(OPTS(NO_OPTS),      OPS(OP(OET_Register, 32), OP(OET_Register_Or_Memory, 32))),
    	OP_COMB(.rex_byte = RexW,   OPS(OP(OET_Register, 64), OP(OET_Register_Or_Memory, 64))),
    ),
};

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
define_mnemonic(cwd);
define_mnemonic(cdq);
define_mnemonic(cqo);
define_mnemonic(div_);
define_mnemonic(idiv);
define_mnemonic(imul);
define_mnemonic(inc);

define_mnemonic(jmp);

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

define_mnemonic(mul);
define_mnemonic(mov);
define_mnemonic(pop);
define_mnemonic(push);
define_mnemonic(ret);
define_mnemonic(sete);
define_mnemonic(setg);
define_mnemonic(setl);
define_mnemonic(setz);
define_mnemonic(sub);

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
}

typedef struct LabelPatch32
{
    s32* address;
    s64 ip;
} LabelPatch32;

typedef struct JumpPatchList
{
    LabelPatch32 patch;
    struct JumpPatchList* next;
} JumpPatchList;

typedef struct StackPatch
{
    s32* location;
    u32 size;
} StackPatch;

#define MAX_DISPLACEMENT_COUNT 128

typedef struct FunctionBuilder
{
    DescriptorFunction descriptor;
    ExecutionBuffer eb;
    StackPatch stack_displacements[MAX_DISPLACEMENT_COUNT];
    s64 stack_displacement_count;

    JumpPatchList* return_patch_list;
    s32 stack_offset;
    u32 max_call_parameter_stack_size;
    u8 next_arg;
} FunctionBuilder;

void encode(FunctionBuilder* fn_builder, Instruction instruction)
{
    u32 encoding_index;
    u32 combination_index;

    if (!find_encoding(instruction, &encoding_index, &combination_index))
    {
        redassert(!"Couldn't find encoding");
        return;
    }

    InstructionEncoding encoding = instruction.mnemonic.encodings[encoding_index];
    OperandCombination combination = encoding.operand_combinations[combination_index];
    u32 operand_count = array_length(combination.operands);

    u8 rex_byte = combination.rex_byte;

    bool r_m_encoding = false;
    for (u32 i = 0; i < array_length(instruction.operands); i++)
    {
        Operand op = instruction.operands[i];
        OperandEncoding op_encoding = combination.operands[i];
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
        else if (op_encoding.type == OET_Register_Or_Memory)
        {
            r_m_encoding = true;
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
    bool need_mod_rm = is_digit || is_reg || r_m_encoding;

    u64 offset_of_displacement = 0;
    u32 stack_size = 0;
    u8 register_or_digit = 0;
    u8 r_m = 0;
    u8 mod = 0;
    u8 mod_r_m = 0;
    bool encoding_stack_operand = false;

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
                        rex_byte |= RexR;
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
                {
                    mod = Mod_Displacement_32;
                    r_m = operand.mem_indirect.reg;
                    need_sib = operand.mem_indirect.reg == get_stack_register();

                    if (need_sib)
                    {
                        sib_byte = (SIBScale_1 << 6) | (r_m << 3) | (r_m);
                    }
                    break;
                }
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
            ((register_or_digit & 0b111) << 3) |
            ((r_m & 0b111))
            );

    }

    if (rex_byte)
    {
        u8_append(&fn_builder->eb, rex_byte);
    }
    else if ((instruction.operands[0].type == OperandType_Register && instruction.operands[0].size == OperandSize_16) || (instruction.operands[1].type == OperandType_Register && instruction.operands[1].size == OperandSize_16) || encoding.options.explicit_byte_size == OperandSize_16)
    {
        u8_append(&fn_builder->eb, OperandSizeOverride);
    }

    for (u32 i = 0; i < array_length(op_code); i++)
    {
        u8 op_code_byte = op_code[i];
        if (op_code_byte)
        {
            u8_append(&fn_builder->eb, op_code_byte);
        }
    }

    if (need_mod_rm)
    {
        u8_append(&fn_builder->eb, mod_r_m);
    }
    // SIB
    if (need_sib)
    {
        u8_append(&fn_builder->eb, sib_byte);
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
                        s8_append(&fn_builder->eb, (s8)op.mem_indirect.displacement);
                        break;
                    case Mod_Displacement_32:
                        if (need_sib)
                        {
                            offset_of_displacement = fn_builder->eb.len;
                            stack_size = op.size;
                            redassert(fn_builder->stack_displacement_count < MAX_DISPLACEMENT_COUNT);
                            s32* location = (s32*)(fn_builder->eb.ptr + offset_of_displacement);
                            fn_builder->stack_displacements[fn_builder->stack_displacement_count] = (const StackPatch){
                                .location = location,
                                .size = stack_size,
                            };
                            fn_builder->stack_displacement_count++;
                        }
                        s32_append(&fn_builder->eb, op.mem_indirect.displacement);
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
                    u8_append(&fn_builder->eb, operand.imm._8);
                    break;
                case OperandSize_16:
                    u16_append(&fn_builder->eb, operand.imm._16);
                    break;
                case OperandSize_32:
                    u32_append(&fn_builder->eb, operand.imm._32);
                    break;
                case OperandSize_64:
                    u64_append(&fn_builder->eb, operand.imm._64);
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
                    u8_append(&fn_builder->eb, operand.rel._8);
                    break;
                case OperandSize_16:
                    u16_append(&fn_builder->eb, operand.rel._16);
                    break;
                case OperandSize_32:
                    u32_append(&fn_builder->eb, operand.rel._32);
                    break;
                case OperandSize_64:
                    u64_append(&fn_builder->eb, operand.rel._64);
                    break;
                default:
                    RED_NOT_IMPLEMENTED;
                    break;
            }
        }
    }
}

#define Function(_name_)\
Value* _name_ = NULL;\
for (FunctionBuilder fn_builder = fn_begin(); !(_name_); _name_ = fn_end(&fn_builder))

#define Return(_value_)\
fn_return(&fn_builder, _value_)

#define Arg(_id_, _descriptor_)\
Value* _id_ = fn_arg(&fn_builder, (_descriptor_))

#define Arg_s8(_id_)  Arg(_id_, &descriptor_s8)
#define Arg_s16(_id_) Arg(_id_, &descriptor_s16)
#define Arg_s32(_id_) Arg(_id_, &descriptor_s32)
#define Arg_s64(_id_) Arg(_id_, &descriptor_s64)
#define Arg_u8(_id_)  Arg(_id_, &descriptor_u8)
#define Arg_u16(_id_) Arg(_id_, &descriptor_u16)
#define Arg_u32(_id_) Arg(_id_, &descriptor_u32)
#define Arg_u64(_id_) Arg(_id_, &descriptor_u64)

#define Stack(_id_, _descriptor_, _value_)\
Value* _id_ = stack_reserve(&fn_builder, (_descriptor_));\
move_value(&fn_builder, (_id_), (_value_))

#define Stack_s8(_id_ , _value_) Stack((_id_), &descriptor_s8 , (_value_))
#define Stack_s16(_id_, _value_) Stack((_id_), &descriptor_s16, (_value_))
#define Stack_s32(_id_, _value_) Stack((_id_), &descriptor_s32, (_value_))
#define Stack_s64(_id_, _value_) Stack((_id_), &descriptor_s64, (_value_))
#define Stack_u8(_id_ , _value_) Stack((_id_), &descriptor_u8 , (_value_))
#define Stack_u16(_id_, _value_) Stack((_id_), &descriptor_u16, (_value_))
#define Stack_u32(_id_, _value_) Stack((_id_), &descriptor_u32, (_value_))
#define Stack_u64(_id_, _value_) Stack((_id_), &descriptor_u64, (_value_))

#define Add(_a_, _b_)  rns_add(&fn_builder, _a_, _b_)
#define Sub(_a_, _b_)  rns_sub(&fn_builder, _a_, _b_)
#define MulS(_a_, _b_) rns_signed_mul_immediate(&fn_builder, _a_, _b_)
#define DivS(_a_, _b_) rns_signed_div(&fn_builder, _a_, _b_)


#define TEST_MODE 0
#define INSTR(...) (Instruction) { __VA_ARGS__ }
#define EXPECTED(...) __VA_ARGS__
static bool test_instruction(const char* test_name, Instruction instruction, u8* expected_bytes, u8 expected_byte_count)
{
    const u32 buffer_size = 64;
    FunctionBuilder fn_builder = { 0 };
    fn_builder.eb = give_me(buffer_size);
    encode(&fn_builder, instruction);

    ExecutionBuffer expected = give_me(buffer_size);
    for (u32 i = 0; i < expected_byte_count; i++)
    {
        u8_append(&expected, expected_bytes[i]);
    }
    return test_buffer(&fn_builder.eb, expected.ptr, expected.len, test_name);
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

Value* stack_reserve(FunctionBuilder* fn_builder, const Descriptor* descriptor)
{
    s32 size = (s32)descriptor_size(descriptor);
    Operand reserved;

    switch (calling_convention)
    {
        // @TODO: we need to test this in SystemV
        case SYSTEMV:
        case MSVC:
            fn_builder->stack_offset += size;
            reserved = stack(-fn_builder->stack_offset, size);
            break;
        default:
            RED_NOT_IMPLEMENTED;
            break;
    }

    Value* result = NEW(Value, 1);
    *result = (const Value) {
        .descriptor = *descriptor,
        .operand = reserved,
    }; 

    return result;
}

void move_value(FunctionBuilder* fn_builder, Value* a, Value* b)
{
    encode(fn_builder, (Instruction) { mov, {a->operand, b->operand} });
}

LabelPatch32 make_jnz(FunctionBuilder* fn_builder)
{
    encode(fn_builder, (Instruction) { jnz, { rel32(0xcccccccc) } });
    s64 ip = fn_builder->eb.len;
    s32* patch = (s32*)fn_builder->eb.ptr[ip - sizeof(u32)];

    return (LabelPatch32) { patch, ip };
}

LabelPatch32 make_jz(FunctionBuilder* fn_builder)
{
    encode(fn_builder, (Instruction) { jz, { rel32(0xcccccccc) } });
    s64 ip = fn_builder->eb.len;
    s32* patch = (s32*)&fn_builder->eb.ptr[ip - sizeof(u32)];

    return (LabelPatch32) { patch, ip };
}

LabelPatch32 make_jmp(FunctionBuilder* fn_builder)
{
    encode(fn_builder, (Instruction) { jmp, { rel32(0xcccccccc) } });
    s64 ip = fn_builder->eb.len;
    s32* patch = (s32*)&fn_builder->eb.ptr[ip - sizeof(u32)];

    return (LabelPatch32) { patch, ip };
}

void make_jump_label(FunctionBuilder* fn_builder, LabelPatch32 patch)
{
    *patch.address = (s32)(fn_builder->eb.len - patch.ip);;
}

void make_jump_ip(LabelPatch32 patch, u64 current_ip)
{
    *patch.address = (s32)(current_ip - patch.ip);
}

JumpPatchList* make_jump_patch(FunctionBuilder* fn_builder, JumpPatchList* next)
{
    JumpPatchList* patch = NEW(JumpPatchList, 1);
    *patch = (const JumpPatchList){
        .patch = make_jmp(fn_builder),
        .next = next,
    };
    return patch;
}

void resolve_jump_patch_list(FunctionBuilder* fn_builder, JumpPatchList* list)
{
    for (JumpPatchList* patch = list; patch; patch = patch->next)
    {
        make_jump_label(fn_builder, patch->patch);
    }
}

FunctionBuilder fn_begin(void)
{
    FunctionBuilder fn_builder =
    {
        .eb = give_me(1024)
    };

    // @Volatile @ArgCount
    fn_builder.descriptor.arg_list = NEW(Value, 16);
    fn_builder.descriptor.return_value = NEW(Value, 1);

    switch (calling_convention)
    {
        case MSVC:
            encode(&fn_builder, (Instruction) { sub, { reg.rsp, imm32(0xcccccccc)} });
            break;
        case SYSTEMV:
            encode(&fn_builder, (Instruction) { push, { reg.rbp } });
            encode(&fn_builder, (Instruction) { mov, { reg.rbp, reg.rsp } });
            break;
        default:
            RED_NOT_IMPLEMENTED;
            break;
    }

    return fn_builder;
}

Value* fn_end(FunctionBuilder* fn_builder)
{
    switch (calling_convention)
    {
        case MSVC:
        {
            s8 alignment = 0x8;
            fn_builder->stack_offset += fn_builder->max_call_parameter_stack_size;
            s32 stack_size = (s32)align(fn_builder->stack_offset, 16) + alignment;
            s64 current_function_code_size = fn_builder->eb.len;
            fn_builder->eb.len = 0;

            encode(fn_builder, (Instruction) { sub, { reg.rsp, imm32(stack_size) } });
            fn_builder->eb.len = current_function_code_size;

            for (s64 i = 0; i < fn_builder->stack_displacement_count; i++)
            {
                StackPatch* patch = &fn_builder->stack_displacements[i];
                s32 displacement = *patch->location;
                if (displacement < 0)
                {
                    *patch->location = stack_size + displacement;
                }
                else if (displacement >= (s32)fn_builder->max_call_parameter_stack_size)
                {
                    s8 return_address_size = 8;
                    *patch->location = stack_size + displacement + return_address_size;
                }
            }

            resolve_jump_patch_list(fn_builder, fn_builder->return_patch_list);

            encode(fn_builder, (Instruction) { add, { reg.rsp, imm32(stack_size) } });
            encode(fn_builder, (Instruction) { ret });
            break;
        }
        case SYSTEMV:
            // @TODO: maybe resolve max call parameter stack size
            resolve_jump_patch_list(fn_builder, fn_builder->return_patch_list);
            encode(fn_builder, (Instruction) { pop, { reg.rbp } });
            encode(fn_builder, (Instruction) { ret });
            break;
        default:
            RED_NOT_IMPLEMENTED;
            break;
    }

    fn_builder->descriptor.arg_count = fn_builder->next_arg;
    Value* result = NEW(Value, 1);
    *result = (const Value)
    {
        .descriptor = {
            .type = DescriptorType_Function,
            .function = fn_builder->descriptor,
        },
        .operand = imm64((u64)fn_builder->eb.ptr),
    };

    return result;
}

Value* fn_arg(FunctionBuilder* fn_builder, const Descriptor* arg_descriptor)
{
    s64 arg_index = fn_builder->next_arg++;
    if (arg_index < array_length(parameter_registers))
    {
        u32 register_index = parameter_registers[arg_index];
        fn_builder->descriptor.arg_list[arg_index] = *reg_value(register_index, arg_descriptor);
    }
    else
    {
        switch (calling_convention)
        {
            case MSVC:
            {
                s32 return_address_size = 8;
                s64 arg_size = descriptor_size(arg_descriptor);
                s64 offset = arg_index * 8;

                fn_builder->descriptor.arg_list[arg_index] = (const Value){
                    .descriptor = *arg_descriptor,
                    .operand = stack((s32)offset, (s32)arg_size),
                };
                break;
            }
            default:
                RED_NOT_IMPLEMENTED;
                break;
        }
    }

    return &fn_builder->descriptor.arg_list[arg_index];
};

Value* fn_return(FunctionBuilder* fn_builder, const Value* to_return)
{
    if (to_return->descriptor.type != DescriptorType_Void)
    {
        s64 size = descriptor_size(&to_return->descriptor);
        redassert(size <= OperandSize_64);
        Value* ret_reg = reg_value(return_registers[0], &to_return->descriptor);

        if (memcmp(&ret_reg->operand, &to_return->operand, sizeof(Operand)) != 0)
        {
            encode(fn_builder, (Instruction) { mov, { ret_reg->operand, to_return->operand }});
        }
        *fn_builder->descriptor.return_value = *ret_reg;
    }
    else
    {
        *fn_builder->descriptor.return_value = *void_value;
    }

    fn_builder->return_patch_list = make_jump_patch(fn_builder, fn_builder->return_patch_list);

    return (Value*)to_return;
}

typedef s32 s32_s32(s32);
typedef s64 (fn_type_void_to_s64)(void);
u64 helper_value_as_function(Value* value)
{
    redassert(value->operand.type == OperandType_Immediate && value->operand.size == OperandSize_64);
    return value->operand.imm._64;
}

#define value_as_function(_value_, _type_) ((_type_*)helper_value_as_function(_value_))

Value* call_fn_value(FunctionBuilder* fn_builder, Value* fn, Value* arg_list, s64 arg_count)
{
    DescriptorFunction* descriptor = &fn->descriptor.function;
    redassert(fn->descriptor.type == DescriptorType_Function);
    redassert(descriptor->arg_count == arg_count);
    // @TODO: type-check arguments

    for (s64 i = 0; i < arg_count; i++)
    {
        redassert(descriptor->arg_list[i].descriptor.type == arg_list[i].descriptor.type);
        encode(fn_builder, (Instruction) {mov, {descriptor->arg_list[i].operand, arg_list[i].operand }});
    }

    u32 parameter_stack_size = (u32)MAX(4, arg_count) * 8;
    fn_builder->max_call_parameter_stack_size = MAX(fn_builder->max_call_parameter_stack_size, parameter_stack_size);

    encode(fn_builder, (Instruction) {mov, {reg.rax, fn->operand }});
    encode(fn_builder, (Instruction) {call, {reg.rax}});

    return fn->descriptor.function.return_value;
}

LabelPatch32 make_if(FunctionBuilder* fn_builder, Value* conditional)
{
    Operand imm;
    switch (conditional->operand.size)
    {
        case OperandSize_8:
            imm = imm8(0);
            break;
        case OperandSize_16:
            imm = imm16(0);
            break;
        case OperandSize_32:
            imm = imm32(0);
            break;
        case OperandSize_64:
            imm = imm64(0);
            break;
        default:
            redassert(false);
            imm = (const Operand){0};
            break;
    }
    encode(fn_builder, (Instruction) { cmp, { conditional->operand, imm8(0)}});

    return make_jz(fn_builder);
}

#define IF(_value_) for (LabelPatch32 patch = make_if(&fn_builder, _value_), *__dummy_index___ = 0; !(__dummy_index___++); make_jump_label(&fn_builder, patch))

typedef struct LoopBuilder
{
    JumpPatchList* jump_patch_list;
    u64 start_ip;
    bool done;
} LoopBuilder;

void make_loop_end(FunctionBuilder* fn_builder, LoopBuilder* loop_builder)
{
    make_jump_ip(make_jmp(fn_builder), loop_builder->start_ip);
    resolve_jump_patch_list(fn_builder, loop_builder->jump_patch_list);
    loop_builder->done = true;
}

#define LOOP\
    for (\
        LoopBuilder loop_builder = { .start_ip = fn_builder.eb.len, .jump_patch_list = NULL };\
        !loop_builder.done;\
        make_loop_end(&fn_builder, &loop_builder)\
        )

#define CONTINUE make_jump_ip(make_jmp(&fn_builder), loop_builder.start_ip)
#define BREAK loop_builder.jump_patch_list = make_jump_patch(&fn_builder, loop_builder.jump_patch_list)

typedef struct StructBuilderField
{
    DescriptorStructField descriptor;
    struct StructBuilderField* next;
} StructBuilderField;

typedef struct StructBuilder
{
    s64 offset;
    s64 field_count;
    StructBuilderField* field_list;
} StructBuilder;

StructBuilder struct_begin(void)
{
    return (const StructBuilder) { 0 };
}

DescriptorStructField* struct_add_field(StructBuilder* struct_builder, const Descriptor* descriptor)
{
    StructBuilderField* field = NEW(StructBuilderField, 1);

    u32 size = (u32)descriptor_size(descriptor);
    struct_builder->offset = align(struct_builder->offset, size);

    field->descriptor.descriptor = descriptor;
    field->descriptor.offset = struct_builder->offset;


    field->next = struct_builder->field_list;
    struct_builder->field_list = field;

    struct_builder->offset += size;
    struct_builder->field_count++;

    return &field->descriptor;
}

Descriptor* struct_end(StructBuilder* struct_builder)
{
    redassert(struct_builder->field_count);

    Descriptor* result = NEW(Descriptor, 1);

    DescriptorStructField* field_list = NEW(DescriptorStructField, struct_builder->field_count);

    u64 index = struct_builder->field_count - 1;
    for (StructBuilderField* field = struct_builder->field_list; field; field = field->next, index--)
    {
        field_list[index] = field->descriptor;
    }

    result->type = DescriptorType_Struct;
    result->struct_ = (const DescriptorStruct){
        .field_list = field_list,
        .field_count = struct_builder->field_count,
    };

    return result;
}

typedef enum CompareOp
{
    Cmp_Equal,
    Cmp_Less,
    Cmp_Greater,
} CompareOp;

Value* compare(FunctionBuilder* fn_builder, CompareOp compare_op, Value* a, Value* b)
{
    encode(fn_builder, (Instruction) { cmp, { a->operand, b->operand } });
    encode(fn_builder, (Instruction) { mov, { reg.rax, imm64(0) }});

    switch (compare_op)
    {
        case Cmp_Equal:
            encode(fn_builder, (Instruction) { setz, { reg.al }});
            break;
        case Cmp_Less:
            encode(fn_builder, (Instruction) { setl, { reg.al }});
            break;
        case Cmp_Greater:
            encode(fn_builder, (Instruction) { setg, { reg.al } });
            break;
        default:
            RED_NOT_IMPLEMENTED;
            break;
    }

    Value* result = stack_reserve(fn_builder, (Descriptor*)&descriptor_s64);
    encode(fn_builder, (Instruction) { mov, { result->operand, reg.rax }});

    return result;
}

void make_is_non_zero(void)
{
    FunctionBuilder fn_builder = fn_begin();
    Value* arg0 = fn_arg(&fn_builder, &descriptor_s64);

    {
        LabelPatch32 return_patch;

        
        IF (compare(&fn_builder, Cmp_Equal, arg0, s32_value(0)))
        {
            fn_return(&fn_builder, s64_value(0));
            return_patch = make_jmp(&fn_builder);
        }

        fn_return(&fn_builder, s64_value(1));
        make_jump_label(&fn_builder, return_patch);
    }

    LabelPatch32 patch = make_jnz(&fn_builder);
    fn_return(&fn_builder, &(const Value) {.descriptor = descriptor_s32, .operand = imm32(0)} );
    LabelPatch32 return_patch = make_jmp(&fn_builder);
    make_jump_label(&fn_builder, patch);
    fn_return(&fn_builder, &(const Value) {.descriptor = descriptor_s32, .operand = imm32(1)});
    make_jump_label(&fn_builder, return_patch);
    Value* fn = fn_end(&fn_builder);
    s32_s32* function = value_as_function(fn, s32_s32);

    print("Should be 0: %d\n", function(0));
    print("Should be 1: %d\n", function(-128391));
}

Value* make_partial_application_s64(Value* original_fn, s64 arg)
{
    FunctionBuilder fn_builder = fn_begin();
    Value* applied_arg0 = s64_value(arg);

    Value* result = call_fn_value(&fn_builder, original_fn, applied_arg0, 1);
    fn_return(&fn_builder, result);

    return fn_end(&fn_builder);
}

void make_simple_lambda(void)
{
    s64 n = 42;
    Function(identity_s64)
    {
        Arg_s64(replicate);
        Return(replicate);
    };
    Value* partial_fn_value = make_partial_application_s64(identity_s64, n);
    s64 result = value_as_function(partial_fn_value, fn_type_void_to_s64)();
    redassert (result == n);
}

typedef void VoidRetVoid(void);
void print_fn(void)
{
    const char* message = "Hello world!\n";
    Descriptor message_descriptor =
    {
        .type = DescriptorType_FixedSizeArray,
        .fixed_size_array =
        {
            .data = (Descriptor*)&descriptor_u8,
            .len = strlen(message) + 1,
        },
    };

    Value* puts_value = C_function_value("int(char*)", (u64)&puts);
    FunctionBuilder fn_builder = fn_begin();
    Value* message_value = pointer_value((u64)message);

    call_fn_value(&fn_builder, puts_value, message_value, 1);

    fn_return(&fn_builder, void_value);
    Value* fn_value = fn_end(&fn_builder);

    value_as_function(fn_value, VoidRetVoid)();
}

void assert_not_a_register(Value* value)
{
    redassert(value);
    if (value->operand.type == OperandType_Register)
    {
        redassert(value->operand.reg != Register_A);
    }
}

Value* rns_arithmetic(FunctionBuilder* fn_builder, Mnemonic mnemonic, Value* a, Value* b)
{
    assert_not_a_register(a);
    assert_not_a_register(b);

    u32 max_size = MAX(a->operand.size, b->operand.size);
    Operand reg1 = get_reg(max_size, Register_A);
    Operand reg2 = get_reg(max_size, Register_B);

    encode(fn_builder, (Instruction) { mov, {reg1, a->operand }} );
    encode(fn_builder, (Instruction) { mov, {reg2, b->operand }} );
    encode(fn_builder, (Instruction) { mnemonic, {reg1, reg2 }} );

    Value* temporary_value = stack_reserve(fn_builder, &a->descriptor);
    encode(fn_builder, (Instruction) { mov, { temporary_value->operand, reg1 }} );

    return temporary_value;
}

static inline Value* rns_add(FunctionBuilder* fn_builder, Value* a, Value* b)
{
    return rns_arithmetic(fn_builder, add, a, b);
}

static inline Value* rns_sub(FunctionBuilder* fn_builder, Value* a, Value* b)
{
    return rns_arithmetic(fn_builder, sub, a, b);
}

Value* rns_signed_mul_immediate(FunctionBuilder* fn_builder, Value* a, Value* b)
{
    assert_not_a_register(a);
    assert_not_a_register(b);
    redassert(b->operand.type == OperandType_Immediate && b->operand.size <= OperandSize_32);

    u32 max_size = MAX(a->operand.size, b->operand.size);
    Operand reg1 = get_reg(max_size, Register_A);

    encode(fn_builder, (Instruction) { mov, {reg1, a->operand }} );
    encode(fn_builder, (Instruction) { imul, {reg1, reg1, b->operand }} );

    Value* temporary_value = stack_reserve(fn_builder, &a->descriptor);
    encode(fn_builder, (Instruction) { mov, { temporary_value->operand, reg1 }} );

    return temporary_value;
}

Value* rns_signed_div(FunctionBuilder* fn_builder, Value* a, Value* b)
{
    assert_not_a_register(a);
    assert_not_a_register(b);

    u32 max_size = MAX(a->operand.size, b->operand.size);
    Operand reg1 = get_reg(max_size, Register_A);

    // Signed division stores the remainder in the D register
    Value* rdx_temp = stack_reserve(fn_builder, &descriptor_s64);
    encode(fn_builder, (Instruction) { mov, {rdx_temp->operand, reg.rdx }} );

    encode(fn_builder, (Instruction) { mov, {reg1, a->operand }} );

    Operand b_operand = get_reg(b->operand.size, Register_B);
    encode(fn_builder, (Instruction) { mov, {b_operand, b->operand }});
    switch (descriptor_size(&a->descriptor))
    {
        case OperandSize_16:
            encode(fn_builder, (Instruction) { cwd, {0}});
            break;
        case OperandSize_32:
            encode(fn_builder, (Instruction) { cdq, {0}});
            break;
        case OperandSize_64:
            encode(fn_builder, (Instruction) { cqo, {0}});
            break;
        default:
            RED_NOT_IMPLEMENTED;
    }

    encode(fn_builder, (Instruction) { idiv, {b_operand}});

    Value* temporary_value = stack_reserve(fn_builder, &a->descriptor);
    encode(fn_builder, (Instruction) { mov, { temporary_value->operand, reg1 }} );

    // Restore RDX
    encode(fn_builder, (Instruction) { mov, {reg.rdx, rdx_temp->operand}});

    return temporary_value;
}

typedef s64 RetS64_ParamS64_S64(s64, s64);

void test_rns_add_sub(void)
{
    s64 value_a = 5;
    s64 value_b = 6;
    s64 sub_value = 4;
    FunctionBuilder fn_builder = fn_begin();
    Value* a = s64_value(value_a);
    Value* b = s64_value(value_b);
    Value* sub_v = s64_value(sub_value);
    Value* sub_result = rns_sub(&fn_builder, a, sub_v);
    Value* add_result = rns_add(&fn_builder, sub_result, b);
    fn_return(&fn_builder, add_result);
    Value* fn = fn_end(&fn_builder);
    s64 result = value_as_function(fn, RetS64_ParamS64_S64)(value_a, value_b);

    print("Result: %ld\n", result);
    print("Expected: %ld\n", value_a - sub_value + value_b);
}

void test_multiply(void)
{
    s64 value_a = -5;
    s32 value_b = 6;
    FunctionBuilder fn_builder = fn_begin();
    Value* a = s64_value(value_a);
    Value* b = s32_value(value_b);
    fn_return(&fn_builder, rns_signed_mul_immediate(&fn_builder, a, b));
    Value* fn = fn_end(&fn_builder);
    s64 result = value_as_function(fn, RetS64_ParamS64_S64)(value_a, value_b);
    printf("Result: %I64d\n", result);
    printf("Expected: %I64d\n", value_a * value_b);
}

typedef s32 RetS32_ParamS32_S32(s32, s32);
void test_divide(void)
{
    s32 value_a = 40;
    s32 value_b = 5;
    FunctionBuilder fn_builder = fn_begin();
    Value* a = s32_value(value_a);
    Value* b = s32_value(value_b);
    fn_return(&fn_builder, rns_signed_div(&fn_builder, a, b));
    Value* fn = fn_end(&fn_builder);
    s32 result = value_as_function(fn, RetS32_ParamS32_S32)(value_a, value_b);
    printf("Result: %d\n", result);
    printf("Expected: %d\n", value_a / value_b);
}

typedef void RetVoid_Param_P_S32(s32*);
void test_array_loop(void)
{
    s32 arr[] = {1, 2, 3};
    u32 len = array_length(arr);

    Descriptor array_descriptor = 
    {
        .type = DescriptorType_FixedSizeArray,
        .fixed_size_array =
        {
            .data = &descriptor_s32,
            .len = len,
        },
    };

    Descriptor array_pointer_descriptor =
    {
        .type = DescriptorType_Pointer,
        .pointer_to = &array_descriptor,
    };

    Function(array_increment)
    {
        Arg(arr, &array_pointer_descriptor);
        Stack_s32(index, s32_value(0));
        Stack(temp, &arr->descriptor, arr);

        u32 array_elem_size = (u32)descriptor_size(array_pointer_descriptor.pointer_to->fixed_size_array.data);

        LOOP
        {
            s32 length = (s32)array_pointer_descriptor.pointer_to->fixed_size_array.len;
            IF (compare(&fn_builder, Cmp_Equal, index, s32_value(length)))
            {
                BREAK;
            }

            encode(&fn_builder, (Instruction) { mov, { reg.rax, temp->operand } });

            Operand pointer =
            {
                .type = OperandType_MemoryIndirect,
                .size = array_elem_size,
                .mem_indirect = {
                    .reg = reg.rax.reg,
                    .displacement = 0,
                },
            };

            encode(&fn_builder, (Instruction) { inc, { pointer } });
            encode(&fn_builder, (Instruction) { add, { temp->operand, imm32((u32)array_elem_size) } });
            encode(&fn_builder, (Instruction) { inc, { index->operand } });
        }
    }
    value_as_function(array_increment, RetVoid_Param_P_S32)(arr);

    redassert(arr[0] == 2);
    redassert(arr[1] == 3);
    redassert(arr[2] == 4);
}

typedef s32 RetS32_Param_VoidP(void*);
void test_structs(void)
{
    StructBuilder struct_builder = struct_begin();

    DescriptorStructField* width_field = struct_add_field(&struct_builder, &descriptor_s32);
    DescriptorStructField* height_field = struct_add_field(&struct_builder, &descriptor_s64);
    DescriptorStructField* dummy_field = struct_add_field(&struct_builder, &descriptor_s32);

    Descriptor* size_struct_descriptor = struct_end(&struct_builder);
    Descriptor* size_struct_pointer_desc = descriptor_pointer_to(size_struct_descriptor);

    FunctionBuilder fn_builder = fn_begin();

    Value* arg0 = fn_arg(&fn_builder, size_struct_pointer_desc);
    encode(&fn_builder, (Instruction) { mov, { reg.rax, arg0->operand } });
    Value* height_value = NEW(Value, 1);
    *height_value = (const Value) {
        .descriptor = *height_field->descriptor,
        .operand = {
            .type = OperandType_MemoryIndirect,
            .size = (u32)descriptor_size(height_field->descriptor),
            .mem_indirect = {
                .displacement = (s32)height_field->offset,
                .reg = reg.rax.reg,
            },
        },
    };

    fn_return(&fn_builder, height_value);

    typedef struct { s32 width; s64 height; s32 dummy; } size_struct;
    size_struct a = { .width = 10, .height = 42 };
    Value* fn = fn_end(&fn_builder);
    s32 height = value_as_function(fn, RetS32_Param_VoidP)(&a);
    //redassert(height == a.height);
    s64 struct_size = descriptor_size(size_struct_descriptor);
    redassert(sizeof(a) == struct_size);
}

void tests_()
{
    Function(test_args)
    {
        Arg_s64(arg0);
        Arg_s64(arg1);
        Arg_s64(arg2);
        Arg_s64(arg3);
        Arg_s64(arg4);
        Arg_s64(arg5);
        Arg_s64(arg6);
        Arg_s64(arg7);
        Return(arg5);
    }
#define def_num(a) s64 v ## a = a
    def_num(0);
    def_num(1);
    def_num(2);
    def_num(3);
    def_num(4);
    def_num(5);
    def_num(6);
    def_num(7);
#undef def_num
    typedef s64 foo(s64, s64, s64, s64, s64, s64, s64, s64);
    s64 result = value_as_function(test_args, foo)(v0, v1, v2, v3, v4, v5, v6, v7);
    redassert(result == v5);
}

void wna_main(s32 argc, char* argv[])
{
#if 1
    tests_();
#else
    TEST(mov_rax_r9, INSTR(mov, { reg.rax, reg.r9 }), EXPECTED(0x4c, 0x89, 0xc8)));
#endif
}

s32 main(s32 argc, char* argv[])
{
#if TEST_MODE
    test_main(argc, argv);
#else
    wna_main(argc, argv);
#endif
}
