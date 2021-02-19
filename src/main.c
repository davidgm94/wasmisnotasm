#include "types.h"
#include "os.h"
#include "execution_buffer.h"
#include <stdio.h>
#ifdef RED_OS_WINDOWS
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#ifdef RED_OS_WINDOWS
#define MSVC_x86_64
#else
#define SYSTEM_V_x86_64
#endif

typedef s64 square_fn(s64);
typedef s64 mul_fn(s64, s64);
typedef s64 make_increment_s64(s64);

/*** X86_64 ***/

static const u8 IMUL_RAX_RDI[] = { 0x48, 0x0f, 0xaf, 0xc7 };
static const u8 IMUL_RAX_RSI[] = { 0x48, 0x0f, 0xaf, 0xc6 };
static const u8 MOV_RBP_RSP[] = { 0x48, 0x89, 0xe5 };

typedef enum
{
    RAX_0x48 = 0x45,
    RBX_0x48 = 0x5d,
    RCX_0x48 = 0x4d,
    RDX_0x48 = 0x55,
    RSI_0x48 = 0x75,
    RDI_0x48 = 0x7d,
    RBP_0x48 = 0x6d,
    RSP_0x48 = 0x65,
} Register0x48;

typedef enum OperandType
{
    OperandType_None,
    OperandType_Register,
    OperandType_Immediate8,
    OperandType_Immediate16,
    OperandType_Immediate32,
    OperandType_Immediate64,
    OperandType_MemoryIndirect,
    OperandType_RIP_Relative,
    OperandType_Label32,
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
    Mod_Displacement_s8 = 0b01,
    Mod_Displacement_s32 = 0b10,
    Mod_Register = 0b11,
} Mod;

typedef enum REX
{
    Rex  = 0x40,
    RexW = 0x48,
    RexR = 0x44,
    RexX = 0x42,
    RexB = 0x41,
} REX;

typedef enum Register
{
    Register_rax = 0,
    Register_rcx = 1,
    Register_rdx = 2,
    Register_rbx = 3,
    Register_rsp = 4,
    Register_rbp = 5,
    Register_rsi = 6,
    Register_rdi = 7,

    Register_r8 =  8,
    Register_r9 =  9,
    Register_r10 = 10,
    Register_r11 = 11,
    Register_r12 = 12,
    Register_r13 = 13,
    Register_r14 = 14,
    Register_r15 = 15,
} Register;


const char* register_to_string(Register r)
{
    switch (r)
    {
        CASE_TO_STR(Register_rax);
        CASE_TO_STR(Register_rcx);
        CASE_TO_STR(Register_rdx);
        CASE_TO_STR(Register_rbx);
        CASE_TO_STR(Register_rsp);
        CASE_TO_STR(Register_rbp);
        CASE_TO_STR(Register_rsi);
        CASE_TO_STR(Register_rdi);
        CASE_TO_STR(Register_r8);
        CASE_TO_STR(Register_r9);
        CASE_TO_STR(Register_r10);
        CASE_TO_STR(Register_r11);
        CASE_TO_STR(Register_r12);
        CASE_TO_STR(Register_r13);
        CASE_TO_STR(Register_r14);
        CASE_TO_STR(Register_r15);
    default:
        return NULL;
    }
}

typedef struct OperandMemoryIndirect
{
    s64 displacement;
    Register reg;
} OperandMemoryIndirect;

typedef struct Operand
{
    OperandType type;
    union
    {
        Register reg;
        u8 imm8;
        u16 imm16;
        u32 imm32;
        u64 imm64;
        OperandMemoryIndirect mem_indirect;
    };
} Operand;

Operand no_operand = {0};

#define reg_init(reg_name) { .type = OperandType_Register, .reg = Register_ ## reg_name, }
#define define_register(reg_name)\
    const Operand reg_name = reg_init(reg_name)

define_register(rax);
define_register(rcx);
define_register(rdx);
define_register(rbx);
define_register(rsp);
define_register(rbp);
define_register(rsi);
define_register(rdi);

define_register(r8);
define_register(r9);
define_register(r10);
define_register(r11);
define_register(r12);
define_register(r13);
define_register(r14);
define_register(r15);

#ifdef MSVC_x86_64
const Operand parameter_registers[] =
{
    reg_init(rcx),
    reg_init(rdx),
    reg_init(r8),
    reg_init(r9),
};
const Operand return_registers[] =
{
    reg_init(rax),
};
const Operand scratch_registers[] =
{
    reg_init(rax),
    reg_init(rcx),
    reg_init(rdx),
    reg_init(rax),
    reg_init(r8),
    reg_init(r9),
    reg_init(r10),
    reg_init(r11),
};
const Operand preserved_registers[] =
{
    reg_init(rbx),
    reg_init(rdi),
    reg_init(rsi),
    reg_init(rsp),
    reg_init(rbp),
    reg_init(r12),
    reg_init(r13),
    reg_init(r14),
    reg_init(r15),
};
#elif defined(SYSTEM_V_x86_64)
const Operand parameter_registers[] =
{
    reg_init(rdi),
    reg_init(rsi),
    reg_init(rdx),
    reg_init(rcx),
    reg_init(r8),
    reg_init(r9),
};
const Operand return_registers[] =
{
    reg_init(rax),
    reg_init(rdx),
};
const Operand scratch_registers[] =
{
    reg_init(rax),
    reg_init(rdi),
    reg_init(rsi),
    reg_init(rdx),
    reg_init(rcx),
    reg_init(r8),
    reg_init(r9),
    reg_init(r10),
    reg_init(r11),
};
const Operand preserved_registers[] =
{
    reg_init(rbx),
    reg_init(rsp),
    reg_init(rbp),
    reg_init(r12),
    reg_init(r13),
    reg_init(r14),
    reg_init(r15),
};
#endif

static inline Operand imm8(u8 value)
{
    return (const Operand)
    {
        .type = OperandType_Immediate8,
        .imm8 = value,
    };
}

static inline Operand imm32(u32 value)
{
    return (const Operand)
    {
        .type = OperandType_Immediate32,
        .imm32 = value,
    };
}

static inline Operand imm64(u64 value)
{
    return (const Operand)
    {
        .type = OperandType_Immediate64,
        .imm64 = value,
    };
}

static inline Operand stack(s32 offset)
{
    return (const Operand)
    {
        .type = OperandType_MemoryIndirect,
        .mem_indirect =
        {
            .reg = rsp.reg,
            .displacement = offset,
        },
    };
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
    OET_Register_Or_Memory,
    OET_Memory,
    OET_Immediate,
} OperandEncodingType;

typedef enum OperandSize
{
    OperandSize_Any,
    OperandSize_8,
    OperandSize_16,
    OperandSize_32,
    OperandSize_64,
} OperandSize;

typedef struct OperandEncoding
{
    OperandEncodingType type;
    OperandSize size;
} OperandEncoding;

typedef struct InstructionEncoding
{
    u16 op_code;
    InstructionExtensionType    extension;
    u8 op_code_extension;
    union
    {
        OperandEncoding     types[3];
        struct
        {
            OperandEncoding type1;
            OperandEncoding type2;
            OperandEncoding type3;
        };
    };
} InstructionEncoding;

typedef struct Mnemonic
{
    const char* name;
    const InstructionEncoding* encodings;
    u32 encoding_count;
} Mnemonic;

typedef struct Instruction
{
    Mnemonic mnemonic;
    union
    {
        Operand operands[3];
        struct
        {
            Operand op1;
            Operand op2;
            Operand op3;
        };
    };
} Instruction;


const InstructionEncoding mov_encoding[] =
{
    // mov r/m64, r64
    {
        .op_code = 0x89,
        .extension = IET_Register,
        .types =
        {
            [0] = {.type = OET_Register_Or_Memory, .size = OperandSize_64, },
            [1] = {.type = OET_Register, .size = OperandSize_64,},
        },
    },
    //mov_rm64_imm32_encoding
    {
        .op_code = 0xc7,
        .extension = IET_Register,
        .types = 
        {
            [0] = {.type = OET_Register_Or_Memory, .size = OperandSize_64, },
            [1] = {.type = OET_Immediate, .size = OperandSize_32,},
        },
    },
    {
        .op_code = 0xb8,
        .extension = IET_Register,
        .types =
        {
            [0] = {.type = OET_Register, .size = OperandSize_64,},
            [1] = {.type = OET_Immediate, .size = OperandSize_64,},
        },
    },
};

const InstructionEncoding ret_encoding[] =
{
    {
        .op_code = 0xc3,
        .extension = IET_Register,
        .types =
        {
            [0] = OET_None,
            [1] = OET_None,
        },
    },
};

const InstructionEncoding add_encoding[] =
{
    {
        .op_code = 0x03,
        .extension = IET_Register,
        .types =
        {
            [0] = OET_Register,
            [1] = OET_Register_Or_Memory,
        },
    },
    {
        .op_code = 0x83,
        .extension = IET_OpCode,
        .op_code_extension = 0,
        .types =
        {
            [0] = OET_Register_Or_Memory,
            [1] = OET_Immediate,
        },
    },
    {
        .op_code = 0x05,
        .extension = IET_Register,
        .types = 
        {
            [0] = OET_Register,
            [1] = OET_Immediate,
        },
    },
};

const InstructionEncoding sub_encoding[] = 
{
    {
        .op_code = 0x83,
        .extension = IET_OpCode,
        .op_code_extension = 5,
        .types =
        {
            
            [0] = OET_Register_Or_Memory,
            [1] = OET_Immediate,
        },
    },
};

const InstructionEncoding push_encoding[] =
{
    {
        .op_code = 0x50,
        .extension = IET_Plus_Register,
        .type1 = {.type = OET_Register, .size = OperandSize_64},
    },
};
const InstructionEncoding pop_encoding[] =
{
    {
        .op_code = 0x58,
        .extension = IET_Plus_Register,
        .type1 = {.type = OET_Register, .size = OperandSize_64},
    },
};

#define define_mnemonic(instruction)\
    const Mnemonic instruction = { .encodings = (const InstructionEncoding*) instruction ## _encoding, .encoding_count = array_length(instruction ## _encoding), }

define_mnemonic(mov);
define_mnemonic(add);
define_mnemonic(sub);
define_mnemonic(push);
define_mnemonic(pop);

const Instruction ret = 
{
    .mnemonic = 
    {
        .encodings = (InstructionEncoding*) ret_encoding,
        .encoding_count = array_length(ret_encoding),
    },
    // No operands
};


static void encode(ExecutionBuffer* eb, Instruction instruction)
{
    for (u32 i = 0; i < instruction.mnemonic.encoding_count; i++)
    {
        InstructionEncoding encoding = instruction.mnemonic.encodings[i];
        bool match = true;
        for (u32 j = 0; j < array_length(instruction.operands); j++)
        {
            OperandEncodingType encoding_type = encoding.types[j].type;
            OperandSize encoding_size = encoding.types[j].size;
            OperandType operand_type = instruction.operands[j].type;

            if (operand_type == OperandType_None && encoding_type == OET_None)
            {
                continue;
            }
            if (operand_type == OperandType_Register && encoding_type == OET_Register)
            {
                continue;
            }
            if (operand_type == OperandType_Register && encoding_type == OET_Register_Or_Memory)
            {
                continue;
            }
            if (operand_type == OperandType_MemoryIndirect && encoding_type == OET_Register_Or_Memory)
            {
                continue;
            }
            if (operand_type == OperandType_Immediate64 && encoding_type == OET_Immediate && encoding_size == OperandSize_64)
            {
                continue;
            }
            if (operand_type == OperandType_Immediate32 && encoding_type == OET_Immediate && encoding_size == OperandSize_32)
            {
                continue;
            }
            if (operand_type == OperandType_Immediate8 && encoding_type == OET_Immediate && encoding_size == OperandSize_8)
            {
                continue;
            }

            match = false;
        }

        if (!match)
        {
            continue;
        }
        
        bool need_mod_rm = false;
        u8 register_or_op_code = 0;
        u8 rex_byte = 0;
        u8 r_m = 0;
        u8 mod = Mod_Register;
        bool needs_sib = false;
        u8 sib_byte = 0;

        for (u32 j = 0; j < 2; j++)
        {
            Operand operand = instruction.operands[j];
            OperandEncodingType encoding_type = encoding.types[j].type;

            if (operand.type == OperandType_Register && encoding.extension != IET_Plus_Register)
            {
                // TODO: add only if 64 bit
                rex_byte |= RexW;
                if (encoding_type == OET_Register)
                {
                    redassert(encoding.extension_type != IET_OpCode);
                    register_or_op_code = operand.reg;
                }
            }
            if (encoding_type == OET_Register_Or_Memory)
            {
                need_mod_rm = true;
                if (operand.type == OperandType_Register)
                {
                    r_m = operand.reg;
                    mod = Mod_Register;
                }
                else
                {
                    mod = Mod_Displacement_s32;
                    redassert(operand.type == OperandType_Register_Displacement);
                    r_m = operand.mem_indirect.reg;

                    if (r_m == rsp.reg)
                    {
                        needs_sib = true;
                        sib_byte = (
                                (SIBScale_1 << 6) |
                                (r_m << 3) |
                                (r_m)
                        );
                    }
                }
            }
        }

        u16 op_code = encoding.op_code;
        //print("Op code: 0x%02X\n", encoding.op_code_extension);
        if (encoding.extension == IET_OpCode)
        {
            register_or_op_code = encoding.op_code_extension;
            //print("Op code: 0x%02X\n", register_or_op_code);
        }
        else if (encoding.extension == IET_Plus_Register)
        {
            redassert(encoding.type1.type == OET_Register);
            redassert(instruction.op1.type = OperandType_Register);
            op_code |= instruction.op1.reg;
        }

        if (rex_byte)
        {
            print("Rex byte: 0x%02X\n", rex_byte);
            u8_append(eb, rex_byte);
        }

        /*// TODO: check that the encoding matches the instruction*/
        /*// TODO: add REX.W only if necessary*/
        /*// TODO: if op_code is 2 bytes, give a different append*/
        print("Opcode: 0x%02X\n", op_code);
        u8_append(eb, (u8)op_code);

        if (need_mod_rm)
        {
            u8 mod_rm = (
                (mod << 6) |
                (register_or_op_code << 3) | 
                (r_m)
            );
            // print("Mod register: 0x%02X, register_or_op_code: 0x%02X, r_m: 0x%02X. Appending: 0x%02X\n", Mod_Register, register_or_op_code, r_m, mod_rm);
            // print("Result: ");
            // print_binary(&mod_rm, 1);
            // u8 mod_rm_expected = 0x7D;
            // print("Expected: ");
            // print_binary(&mod_rm_expected, 1);
            // print("Expected: 0x%02X, result: 0x%02X\n", mod_rm_expected, mod_rm);
            
            // TODO: This hack was working before the crash
            //if (encoding.op_code == mov_rm64_r64_encoding[0].op_code)
            //{
                //mod_rm = 0x7D;
            //}
            u8_append(eb, mod_rm);
        }

        if (needs_sib)
        {
            print("Appending SIB byte 0x%02X\n", sib_byte);
            u8_append(eb, sib_byte);
        }

        for (u32 j = 0; j < 2; j++)
        {
            Operand operand = instruction.operands[j];
            switch (operand.type)
            {
                case (OperandType_MemoryIndirect):
                    s32_append(eb, (s32)operand.mem_indirect.displacement);
                    break;
                default:
                    break;
            }
        }

        for (u32 j = 0; j < 2; j++)
        {
            Operand operand = instruction.operands[j];
            switch (operand.type)
            {
                case (OperandType_Immediate64):
                    u64_append(eb, operand.imm64);
                    break;
                case (OperandType_Immediate32):
                    //print("Buffer len: %u\n", eb->len);
                    u32_append(eb, operand.imm32);
                    break;
                case (OperandType_Immediate8):
                    u8_append(eb, operand.imm8);
                    break;
                default:
                    break;
            }
        }
    }
}

typedef struct Function
{
    ExecutionBuffer eb;
    s8 stack_reserve;
} Function;

static inline Operand declare_variable(Function* fn)
{
    fn->stack_reserve += 0x10;
    return stack(0);
}

static inline void assign(Function* fn, Operand a, Operand b)
{
    encode(&fn->eb, (Instruction) { mov, a, b  });
}

static inline Operand mutating_plus(Function* fn, Operand a, Operand b)
{
    encode(&fn->eb, (Instruction) { add, a, b  });
    return a;
}

static inline Function fn_begin(void)
{
    Function fn =
    {
        .eb = give_me(1024),
        .stack_reserve = 8,
    };
    encode(&fn.eb, (Instruction) { sub, rsp, imm8(0xcc) });
    return fn;
}

static inline void fn_return(Function* fn, Operand to_return)
{
    // Override stack reservation
    u64 save_occupied = fn->eb.len;
    fn->eb.len = 0;
    encode(&fn->eb, (Instruction) { sub, rsp, imm8(fn->stack_reserve) });
    fn->eb.len = save_occupied;

    encode(&fn->eb, (Instruction) { mov, rax, to_return });
    encode(&fn->eb, (Instruction) { add, rsp, imm8(fn->stack_reserve) });
    encode(&fn->eb, ret);
}

Function foo(void)
{
    Function fn = fn_begin();
    Operand x = declare_variable(&fn);
    Operand temp = imm32(1);
    assign(&fn, x, temp);
    mutating_plus(&fn, rcx, x);
    fn_return(&fn, rcx);

    return fn;
}

static inline void push_rbp(ExecutionBuffer* eb)
{
    static const u8 PUSH_RBP = 0x55;
    u8_append(eb, PUSH_RBP);
}

static inline void pop_rbp(ExecutionBuffer* eb)
{
    static const u8 POP_RBP = 0x5d;
    u8_append(eb, POP_RBP);
}

static inline void mov_rbp8_rdi(ExecutionBuffer* eb)
{
    u8_append(eb, 0x48);
    u8_append(eb, 0x89);
    u8_append(eb, 0x7d);
    u8_append(eb, 0xf8);
}

static inline void mov_reg_0x48_rbp16(ExecutionBuffer* eb, Register0x48 reg)
{
    u8_append(eb, 0x48);
    u8_append(eb, 0x8B);
    u8_append(eb, reg);
    u8_append(eb, 0xf0);
}

static inline void add_reg_0x48_rbp8(ExecutionBuffer* eb, Register0x48 reg)
{
    u8_append(eb, 0x48);
    u8_append(eb, 0x03);
    u8_append(eb, reg);
    u8_append(eb, 0xf8);
}

static inline void mov_rbp16_imm32(ExecutionBuffer* eb, s32 value)
{
    u8_append(eb, 0x48);
    u8_append(eb, 0xc7);
    u8_append(eb, 0x45);
    u8_append(eb, 0xf0);
    s32_append(eb, value);
}

#define TEST_EQUAL_S64(result, expected)\
{\
    if (result == expected)\
    {\
        s32 chars = printf("[TEST] %s", __func__);\
        while (chars < 40)\
        {\
            putc(' ', stdout);\
            chars++;\
        }\
        printf("[OK]\n");\
    }\
    else\
    {\
        printf("TEST %s \t[FAILED] Unexpected result: %I64d. Expected result: %I64d\n", __func__, result, expected);\
        print_chunk_of_bytes_in_hex(eb.ptr, eb.len, "Buffer:\t");\
    }\
}

static void test_mul_s64(s64 a, s64 b)
{
    ExecutionBuffer eb = give_me(1024);
    encode(&eb, (Instruction) { mov, {rax, rdi}});

    array_append(&eb, IMUL_RAX_RSI);
    encode(&eb, ret);

    mul_fn* fn = (mul_fn*)eb.ptr;
    s64 result = fn(a, b);
    s64 expected = a * b;

    TEST_EQUAL_S64(result, expected);
}

static void test_square_s64(s64 n)
{
    ExecutionBuffer eb = give_me(1024);

    encode(&eb, (Instruction) { mov, {rax, rdi} });
    array_append(&eb, IMUL_RAX_RDI);
    encode(&eb, ret);

    square_fn* fn = (square_fn*)eb.ptr;
    s64 result = fn(n);
    s64 expected = n * n;

    TEST_EQUAL_S64(result, expected);
}
static inline ExecutionBuffer make_eb_increment(void)
{
    ExecutionBuffer eb = give_me(1024);

    encode(&eb, (Instruction) { mov, {rax, rdi} });
    encode(&eb, (Instruction) { add, rax, imm32(1)});
    encode(&eb, ret);

    print_chunk_of_bytes_in_hex(eb.ptr, eb.len, "Buffer:\t");
    return eb;
}

static void test_increment_s64(s64 n)
{
    ExecutionBuffer eb = make_eb_increment();
    //print_chunk_of_bytes_in_hex(eb.ptr, eb.len, "Buffer:\t");

    make_increment_s64* fn = (make_increment_s64*)eb.ptr;
    s64 result = fn(n);
    //print("We are about to call\n");
    s64 expected = n + 1;

    TEST_EQUAL_S64(result, expected);
}

static make_increment_s64* make_increment_s64_fn(void)
{
    ExecutionBuffer eb = make_eb_increment();

    make_increment_s64* fn = (make_increment_s64*)eb.ptr;
    return fn;
}

static void test_increment_s64_slow(s64 n)
{
    ExecutionBuffer eb = give_me(1024);

    push_rbp(&eb);
    array_append(&eb, MOV_RBP_RSP);
    encode(&eb, (Instruction) { mov, rax, rdi });
    mov_rbp8_rdi(&eb);
    mov_rbp16_imm32(&eb, 0x1);
    mov_reg_0x48_rbp16(&eb, RAX_0x48);
    add_reg_0x48_rbp8(&eb, RAX_0x48);
    pop_rbp(&eb);
    encode(&eb, ret);

    make_increment_s64* fn = (make_increment_s64*)eb.ptr;
    s64 result = fn(n);
    s64 expected = n + 1;

    TEST_EQUAL_S64(result, expected);
}

static void test_add_rax_imm32(s32 n)
{
    ExecutionBuffer eb = give_me(1024);
    encode(&eb, (Instruction) { add, rax, imm32(n)});

    ExecutionBuffer expected_eb = give_me(1024);
    u8_append(&expected_eb, 0x48);
    u8_append(&expected_eb, 0x05);
    s32_append(&expected_eb, n);

    test_buffer(&eb, expected_eb.ptr, expected_eb.len, __func__);
}

static void test_mov_rax_imm32(s32 n)
{
    ExecutionBuffer eb = give_me(1024);
    encode(&eb, (Instruction) { mov, rax, imm32(n) });

    ExecutionBuffer expected_eb = give_me(1024);
    u8_append(&expected_eb, 0x48);
    u8_append(&expected_eb, 0xc7);
    u8_append(&expected_eb, 0xc0);
    s32_append(&expected_eb, n);

    test_buffer(&eb, expected_eb.ptr, expected_eb.len, __func__);
}

// @not_pass: TODO: Something is wrong with this
static void test_mov_rax_rdi(void* s)
{
    ExecutionBuffer eb = give_me(1024);
    encode(&eb, (Instruction) {mov, rax, rdi});

    ExecutionBuffer expected_eb = give_me(1024);
    u8_append(&expected_eb, 0x48);
    u8_append(&expected_eb, 0x89);
    u8_append(&expected_eb, 0xf8);

    test_buffer(&eb, expected_eb.ptr, expected_eb.len, __func__);
}

static void test_mov_reg_imm64(void* s)
{
    u64 test_number = 12312541231;
    ExecutionBuffer eb = give_me(1024);
    encode(&eb, (Instruction) {
        mov, { rax, imm64(test_number) }
    });

    ExecutionBuffer expected_eb = give_me(1024);
    u8_append(&expected_eb, 0x48);
    u8_append(&expected_eb, 0xb8);
    u64_append(&expected_eb, test_number);
    
    test_buffer(&eb, expected_eb.ptr, expected_eb.len, __func__);
}

static void test_push_r64(void* s)
{
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) { push, { rbp } });
    
    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0x55);

    test_buffer(&eb, expected.ptr, expected.len, __func__);
}

static void test_pop_r64(void* s)
{
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) { pop, { rbp } });
    
    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0x5d);

    test_buffer(&eb, expected.ptr, expected.len, __func__);
}

typedef void TestFn(void*);
typedef struct Test
{
    TestFn* fn;
    void* args;
} Test;

Test tests[] =
{
    {test_push_r64},
    {test_pop_r64},
};

s32 main(s32 argc, char* argv[])
{
    for (u32 i = 0; i < array_length(tests); i++)
    {
        tests[i].fn(tests[i].args);
    }
}
