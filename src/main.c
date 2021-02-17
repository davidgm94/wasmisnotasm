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
    Rex  = 0b01000000,
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
    s64 displacement;
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
        OperandRegisterDisplacement reg_displacement;
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

static inline Operand imm8(s8 value)
{
    return (const Operand)
    {
        .type = OperandType_Immediate8,
        .imm8 = value,
    };
}

static inline Operand imm32(s32 value)
{
    return (const Operand)
    {
        .type = OperandType_Immediate32,
        .imm32 = value,
    };
}

static inline Operand stack(s32 offset)
{
    return (const Operand)
    {
        .type = OperandType_Register_Displacement,
        .reg_displacement =
        {
            .reg = rsp.reg_index,
            .displacement = offset,
        },
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
    const InstructionEncoding* encodings;
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

const InstructionEncoding mov_encoding[] =
{
    // mov r/m64, r64
    {
        .op_code = 0x89,
        .extension = IET_Register,
        .types =
        {
            [0] = OET_Register_Or_Memory,
            [1] = OET_Register,
        },
    },
    //mov_rm64_imm32_encoding
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
            [1] = OET_Immediate8,
        },
    },
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

const InstructionEncoding sub_encoding[] = 
{
    {
        .op_code = 0x83,
        .extension = IET_OpCode,
        .op_code_extension = 5,
        .types =
        {
            
            [0] = OET_Register_Or_Memory,
            [1] = OET_Immediate32,
        },
    },
};

const InstructionEncoding push_encoding[] =
{
    {
        .op_code = 0x50,
        .extension = IET_OpCode,
        .type1 = OET_Register,
    },
};

#define define_mnemonic(instruction)\
    const Mnemonic instruction = { .encodings = (const InstructionEncoding*) instruction ## _encoding, .encoding_count = array_length(instruction ## _encoding), }

define_mnemonic(mov);
define_mnemonic(add);
define_mnemonic(sub);
define_mnemonic(push);

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
        bool needs_sib = false;
        u8 sib_byte = 0;

        for (u32 j = 0; j < 2; j++)
        {
            Operand operand = instruction.operands[j];
            OperandEncodingType encoding_type = encoding.types[j];

            if (operand.type == OperandType_Register)
            {
                // TODO: add only if 64 bit
                rex_byte |= RexW;
                if (encoding_type == OET_Register)
                {
                    redassert(encoding.extension_type != IET_OpCode);
                    register_or_op_code = operand.reg_index;
                }
            }
            if (encoding_type == OET_Register_Or_Memory)
            {
                need_mod_rm = true;
                if (operand.type == OperandType_Register)
                {
                    r_m = operand.reg_index;
                    mod = Mod_Register;
                }
                else
                {
                    mod = Mod_Displacement_s32;
                    redassert(operand.type == OperandType_Register_Displacement);
                    r_m = operand.reg_displacement.reg;

                    if (r_m == rsp.reg_index)
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

        //print("Op code: 0x%02X\n", encoding.op_code_extension);
        if (encoding.extension == IET_OpCode)
        {
            register_or_op_code = encoding.op_code_extension;
            //print("Op code: 0x%02X\n", register_or_op_code);
        }

        if (rex_byte)
        {
            print("Rex byte: 0x%02X\n", rex_byte);
            u8_append(eb, rex_byte);
        }

        /*// TODO: check that the encoding matches the instruction*/
        /*// TODO: add REX.W only if necessary*/
        /*// TODO: if op_code is 2 bytes, give a different append*/
        print("Opcode: 0x%02X\n", encoding.op_code);
        u8_append(eb, (u8)encoding.op_code);

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
                case (OperandType_Register_Displacement):
                    s32_append(eb, operand.reg_displacement.displacement);
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
    encode(&fn->eb, (Instruction)RET);
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
        printf("TEST %s \t[FAILED] Unexpected result: %ld. Expected result: %ld\n", __func__, result, expected);\
        print_chunk_of_bytes_in_hex(eb.ptr, eb.len, "Buffer:\t");\
    }\
}

static void test_mul_s64(s64 a, s64 b)
{
    ExecutionBuffer eb = give_me(1024);
    encode(&eb, (Instruction) { mov, {rax, rdi}});

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

    encode(&eb, (Instruction) { mov, {rax, rdi} });
    array_append(&eb, IMUL_RAX_RDI);
    encode(&eb, RET);

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
    encode(&eb, RET);

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
    encode(&eb, RET);

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
static void test_mov_rax_rdi(void)
{
    ExecutionBuffer eb = give_me(1024);
    encode(&eb, (Instruction) {mov, rax, rdi});

    ExecutionBuffer expected_eb = give_me(1024);
    u8_append(&expected_eb, 0x48);
    u8_append(&expected_eb, 0x89);
    u8_append(&expected_eb, 0xf8);

    test_buffer(&eb, expected_eb.ptr, expected_eb.len, __func__);
}

static ExecutionBuffer push_rbp_buffer(void)
{
    ExecutionBuffer eb = give_me(1024);
    encode(&eb, (Instruction) { push, rbp });
    return eb;
}

s32 main(s32 argc, char* argv[])
{
#if 0
    test_mul_s64(5, 7);
    test_square_s64(10);
    test_increment_s64(10);
    test_increment_s64_slow(10);
    test_add_rax_imm32(5);
    test_mov_rax_imm32(19823);
    test_add_rax_imm32(5);
    test_mov_rax_rdi();
#else
    // Function f = foo();
    // make_increment_s64* test = (make_increment_s64*)(f.eb.ptr);

    // print_chunk_of_bytes_in_hex(f.eb.ptr, f.eb.len, "Buffer:\t");
    // make_increment_s64* expected_fn = make_increment_s64_fn();
    // s64 result = test(1);
    // s64 expected = expected_fn(1);
    // redassert(result == expected);

    ExecutionBuffer eb = push_rbp_buffer();
    ExecutionBuffer test = give_me(1024);
    u8_append(&test, 0x55);
    test_buffer(&eb, test.ptr, test.len, "Compare push rbp");

#endif
}
