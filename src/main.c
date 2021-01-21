#include "types.h"
#include "os.h"
#include "execution_buffer.h"
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

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
    OperandType_None = 0,
    OperandType_Register,
    OperandType_Immediate8,
    OperandType_Immediate32,
    OperandType_Register_Displacement,
} OperandType;


typedef enum Mod
{
    Mod_Displacement_0 = 0b00,
    Mod_Displacement_s8 = 0b01,
    Mod_Displacement_s32 = 0b10,
    Mod_Register = 0b11,
} Mod;

typedef enum REX
{
    Rex   = 0b01000000,
    RexW = 0b01001000,
    RexR = 0b01000100,
    RexX = 0b01000010,
    RexB = 0b01000001,
} REX;

typedef enum OperandRegisterIndex
{
    OperandRegister_rax = 0,
    OperandRegister_rcx = 1,
    OperandRegister_rdx = 2,
    OperandRegister_rbx = 3,
    OperandRegister_rsp = 4,
    OperandRegister_rbp = 5,
    OperandRegister_rsi = 6,
    OperandRegister_rdi = 7,

    OperandRegister_r8 =  8,
    OperandRegister_r9 =  9,
    OperandRegister_r10 = 10,
    OperandRegister_r11 = 11,
    OperandRegister_r12 = 12,
    OperandRegister_r13 = 13,
    OperandRegister_r14 = 14,
    OperandRegister_r15 = 15,
} OperandRegisterIndex;

const char* register_to_string(OperandRegisterIndex r)
{
    switch (r)
    {
        CASE_TO_STR(OperandRegister_rax);
        CASE_TO_STR(OperandRegister_rcx);
        CASE_TO_STR(OperandRegister_rdx);
        CASE_TO_STR(OperandRegister_rbx);
        CASE_TO_STR(OperandRegister_rsp);
        CASE_TO_STR(OperandRegister_rbp);
        CASE_TO_STR(OperandRegister_rsi);
        CASE_TO_STR(OperandRegister_rdi);
        CASE_TO_STR(OperandRegister_r8);
        CASE_TO_STR(OperandRegister_r9);
        CASE_TO_STR(OperandRegister_r10);
        CASE_TO_STR(OperandRegister_r11);
        CASE_TO_STR(OperandRegister_r12);
        CASE_TO_STR(OperandRegister_r13);
        CASE_TO_STR(OperandRegister_r14);
        CASE_TO_STR(OperandRegister_r15);
    }
}

typedef u8 RegisterIndex;

typedef struct OperandRegisterDisplacement
{
    s64 offset;
    RegisterIndex reg;
} OperandRegisterDisplacement;

typedef struct Operand
{
    OperandType type;
    union
    {
        RegisterIndex reg_index;
        s8 imm8;
        s32 imm32;
    };
} Operand;

Operand no_operand = {0};

#define define_register(reg_name)\
    const Operand reg_name = { .type = OperandType_Register, .reg_index = OperandRegister_ ## reg_name, }

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

static inline Operand Operand_Imm8(s8 value)
{
    return (const Operand)
    {
        .type = OperandType_Immediate8,
        .imm8 = value,
    };
}

static inline Operand Operand_Imm32(s32 value)
{
    return (const Operand)
    {
        .type = OperandType_Immediate32,
        .imm32 = value,
    };
}

typedef enum InstructionExtensionType
{
    IET_Register,
    IET_OpCode,
    IET_Plus_Register,
} InstructionExtensionType;

typedef enum OperandEncodingType
{
    OET_None = 0,
    OET_Register,
    OET_Register_Or_Memory,
    OET_Immediate8,
    OET_Immediate32,
} OperandEncodingType;

typedef struct InstructionEncoding
{
    u16                         op_code;
    InstructionExtensionType    extension;
    u8 op_code_extension;
    union
    {
        OperandEncodingType     types[2];
        struct
        {
            OperandEncodingType type1;
            OperandEncodingType type2;
        };
    };
} InstructionEncoding;

typedef struct Mnemonic
{
    InstructionEncoding* encodings;
    u32 encoding_count;
} Mnemonic;

typedef struct Instruction
{
    Mnemonic mnemonic;
    union
    {
        Operand operands[2];
        struct
        {
            Operand op1;
            Operand op2;
        };
    };
} Instruction;

const InstructionEncoding mov_rm_register_encoding[] =
{
    {
        .op_code = 0x89,
        .extension = IET_Register,
        .types =
        {
            [0] = OET_Register_Or_Memory,
            [1] = OET_Register,
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

const InstructionEncoding add_register_imm32_encoding[] =
{
    {
        .op_code = 0x05,
        .extension = IET_Register,
        .types = 
        {
            [0] = OET_Register,
            [1] = OET_Immediate32,
        },
    },
};

const InstructionEncoding mov_register_imm32_encoding[] =
{
    {
        .op_code = 0xc7,
        .extension = IET_Register,
        .types = 
        {
            [0] = OET_Register_Or_Memory,
            [1] = OET_Immediate32,
        },
    },
};


#define define_mnemonic(instruction)\
    const Mnemonic instruction = { .encodings = (InstructionEncoding*) instruction ## _encoding, .encoding_count = array_length(instruction ## _encoding), }

define_mnemonic(mov_rm_register);
define_mnemonic(add_register_imm32);
define_mnemonic(mov_register_imm32);

const Instruction RET = 
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
        // TODO: remove hardcoded for-2 loop
        for (u32 j = 0; j < 2; j++)
        {
            OperandEncodingType encoding_type = encoding.types[j];
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
            if (operand_type == OperandType_Register_Displacement && encoding_type == OET_Register_Or_Memory)
            {
                continue;
            }
            if (operand_type == OperandType_Immediate32 && encoding_type == OET_Immediate32)
            {
                continue;
            }
            if (operand_type == OperandType_Immediate8 && encoding_type == OET_Immediate8)
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
        for (u32 j = 0; j < 2; j++)
        {
            Operand operand = instruction.operands[j];
            OperandEncodingType encoding_type = encoding.types[j];

            if (encoding_type == OET_Register)
            {
                redassert(encoding.extension != IET_OpCode);
                register_or_op_code = operand.reg_index;
            }
            if (operand.type == OperandType_Register && encoding_type == OET_Register_Or_Memory && instruction.operands[1].type != OperandType_Immediate32)
            {
                need_mod_rm = true;
                rex_byte |= RexW;
                if (encoding_type == OET_Register_Or_Memory)
                {
                    r_m = operand.reg_index;
                }
            }
            else if (operand.type == OperandType_Immediate32)
            {
                rex_byte |= RexW;
            }
            else if (instruction.op1.type == OperandType_Register && instruction.operands[1].type== OperandType_Immediate32)
            {
                need_mod_rm = true;
            }
        }

        //print("Op code: 0x%02X\n", encoding.op_code_extension);
        if (encoding.extension == IET_OpCode)
        {
            register_or_op_code = encoding.op_code_extension;
            //print("Op code: 0x%02X\n", register_or_op_code);
        }

        if (rex_byte)
        {
            //print("Rex byte: 0x%02X\n", rex_byte);
            u8_append(eb, rex_byte);
        }

        /*// TODO: check that the encoding matches the instruction*/
        /*// TODO: add REX.W only if necessary*/
        /*// TODO: if op_code is 2 bytes, give a different append*/
        print("Opcode: 0x%02X\n", encoding.op_code);
        u8_append(eb, (u8)encoding.op_code);

        // TODO: Fix workaround
        if (encoding.op_code == add_register_imm32_encoding->op_code && rex_byte)
        {
            need_mod_rm = false;
        }

        if (need_mod_rm)
        {
            print("Mod register: %d, register_or_op_code: %d\n", Mod_Register, register_or_op_code);
            u8 mod_rm = (
                (mod << 6) |
                (register_or_op_code << 3) | 
                (r_m)
            );
            u8_append(eb, mod_rm);
        }

        for (u32 j = 0; j < 2; j++)
        {
            Operand operand = instruction.operands[j];
            switch (operand.type)
            {
                case (OperandType_Immediate32):
                    //print("Buffer len: %u\n", eb->len);
                    s32_append(eb, operand.imm32);
                    break;
                case (OperandType_Immediate8):
                    s8_append(eb, operand.imm8);
                    break;
                default:
                    break;
            }
        }
    }
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

static inline void add_rax_imm_s8(ExecutionBuffer* eb, s8 value)
{
    const Operand imm8 = { .type = OperandType_Immediate8, .imm8 = value, };
    //array_append(eb, ADD_RAX_IMM_S32);
    s32_append(eb, value);
}

static inline void add_rax_imm_s32(ExecutionBuffer* eb, s32 value)
{

    //ExecutionBuffer test = give_me(1024);
    //encode(&test, 
    //(Instruction) { .mnemonic = add_rax_imm32, .op1 = rax, .op2 = { .type = OperandType_Immediate32, .imm32 = value, },
    //});

    //ExecutionBuffer expected_eb = give_me(1024);
    //u8_append(&expected_eb, 0x48);
    //u8_append(&expected_eb, 0x05);
    //s32_append(&expected_eb, value);

    //test_buffer(&test, expected_eb.ptr, expected_eb.len, __func__);
}

static inline void mov_rbp8_reg_0x48(ExecutionBuffer* eb, Register0x48 reg)
{
    u8_append(eb, 0x48);
    u8_append(eb, 0x89);
    u8_append(eb, reg);
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
        printf("TEST %s \t[FAILED] Unexpected result: %ld. Expected result: %ld\n", __func__, result, expected);\
        print_chunk_of_bytes_in_hex(eb.ptr, eb.len, "Buffer:\t");\
    }\
}

static void test_mul_s64(s64 a, s64 b)
{
    ExecutionBuffer eb = give_me(1024);
    encode(&eb, 
            (Instruction) { .mnemonic = mov_rm_register, .operands = { [0] = rax, [1] = rdi} });

    array_append(&eb, IMUL_RAX_RSI);
    encode(&eb, RET);

    mul_fn* fn = (mul_fn*)eb.ptr;
    s64 result = fn(a, b);
    s64 expected = a * b;

    TEST_EQUAL_S64(result, expected);
}

static void test_square_s64(s64 n)
{
    ExecutionBuffer eb = give_me(1024);

    encode(&eb, (Instruction) { mov_rm_register, {rax, rdi} });
    array_append(&eb, IMUL_RAX_RDI);
    encode(&eb, RET);

    square_fn* fn = (square_fn*)eb.ptr;
    s64 result = fn(n);
    s64 expected = n * n;

    TEST_EQUAL_S64(result, expected);
}

static void test_increment_s64(s64 n)
{
    ExecutionBuffer eb = give_me(1024);

    encode(&eb, (Instruction) { mov_rm_register, {rax, rdi} });
    encode(&eb, (Instruction) { .mnemonic = add_register_imm32, .op1 = rax, .op2 = Operand_Imm32(1), });
    encode(&eb, RET);
    print_chunk_of_bytes_in_hex(eb.ptr, eb.len, "Buffer:\t");

    square_fn* fn = (square_fn*)eb.ptr;
    s64 result = fn(n);
    print("We are about to call\n");
    s64 expected = n + 1;

    TEST_EQUAL_S64(result, expected);
}

static void test_increment_s64_slow(s64 n)
{
    ExecutionBuffer eb = give_me(1024);

    push_rbp(&eb);
    array_append(&eb, MOV_RBP_RSP);
    encode(&eb, (Instruction) { mov_rm_register, {rax, rdi} });
    mov_rbp8_reg_0x48(&eb, RDI_0x48);
    mov_rbp16_imm32(&eb, 0x1);
    mov_reg_0x48_rbp16(&eb, RAX_0x48);
    add_reg_0x48_rbp8(&eb, RAX_0x48);
    pop_rbp(&eb);
    encode(&eb, RET);

    square_fn* fn = (square_fn*)eb.ptr;
    s64 result = fn(n);
    s64 expected = n + 1;

    TEST_EQUAL_S64(result, expected);
}

static void test_add_rax_imm32(s32 n)
{
    ExecutionBuffer eb = give_me(1024);

    Instruction i =
    {
        .mnemonic = add_register_imm32,
        .op1 = rax,
        .op2 = Operand_Imm32(n),
    };
    encode(&eb, i);

    ExecutionBuffer expected_eb = give_me(1024);
    u8_append(&expected_eb, 0x48);
    u8_append(&expected_eb, 0x05);
    s32_append(&expected_eb, n);

    test_buffer(&eb, expected_eb.ptr, expected_eb.len, __func__);
}

static void test_mov_rax_imm32(s32 n)
{
    ExecutionBuffer eb = give_me(1024);

    Instruction i =
    {
        .mnemonic = mov_register_imm32,
        .op1 = rax,
        .op2 = Operand_Imm32(n),
    };
    encode(&eb, i);

    ExecutionBuffer expected_eb = give_me(1024);
    u8_append(&expected_eb, 0x48);
    u8_append(&expected_eb, 0xc7);
    u8_append(&expected_eb, 0xc0);
    s32_append(&expected_eb, n);

    test_buffer(&eb, expected_eb.ptr, expected_eb.len, __func__);
}

static void test_mov_rax_rdi(void)
{
    ExecutionBuffer eb = give_me(1024);

    Instruction i =
    {
        .mnemonic = mov_rm_register,
        .op1 = rax,
        .op2 = rdi,
    };
    encode(&eb, i);

    ExecutionBuffer expected_eb = give_me(1024);
    u8_append(&expected_eb, 0x48);
    u8_append(&expected_eb, 0x89);
    u8_append(&expected_eb, 0xf8);

    test_buffer(&eb, expected_eb.ptr, expected_eb.len, __func__);
}

s32 main(s32 argc, char* argv[])
{
#if 1
    test_mul_s64(5, 7);
    test_square_s64(10);
    test_increment_s64(10);
    test_increment_s64_slow(10);
    test_add_rax_imm32(5);
    test_mov_rax_imm32(19823);
    test_add_rax_imm32(5);
    test_mov_rax_rdi();
#else
#endif
}
