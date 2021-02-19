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

typedef enum OperandSize
{
    OperandSize_Any = 0,
    OperandSize_8 = 8,
    OperandSize_16 = 16,
    OperandSize_32 = 32,
    OperandSize_64 = 64,
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
    Register_A = 0,
    Register_C = 1,
    Register_D = 2,
    Register_B = 3,
    Register_SP = 4,
    Register_BP = 5,
    Register_SI = 6,
    Register_DI = 7,

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
    s64 displacement;
    Register reg;
} OperandMemoryIndirect;

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
    };
} Operand;

#define reg_init(reg_index, reg_size) { .type = OperandType_Register, .size = reg_size, .reg = reg_index, }
#define define_register(reg_name, reg_index, reg_size)\
    const Operand reg_name = reg_init(reg_index, reg_size)

/* 64-bit registers */
define_register(rax,    Register_A, 64);
define_register(rcx,    Register_C, 64);
define_register(rdx,    Register_D, 64);
define_register(rbx,    Register_C, 64);
define_register(rsp,    Register_SP, 64);
define_register(rbp,    Register_BP, 64);
define_register(rsi,    Register_SI, 64);
define_register(rdi,    Register_DI, 64);
define_register(r8,     Register_8, 64);
define_register(r9,     Register_9, 64);
define_register(r10,    Register_10, 64);
define_register(r11,    Register_11, 64);
define_register(r12,    Register_12, 64);
define_register(r13,    Register_13, 64);
define_register(r14,    Register_14, 64);
define_register(r15,    Register_15, 64);

/* 32-bit registers */
define_register(eax,    Register_A, 32);
define_register(ecx,    Register_C, 32);
define_register(edx,    Register_D, 32);
define_register(ebx,    Register_B, 32);
define_register(esp,    Register_SP, 32);
define_register(ebp,    Register_BP, 32);
define_register(esi,    Register_SI, 32);
define_register(edi,    Register_DI, 32);
define_register(r8d,    Register_8,  32);
define_register(r9d,    Register_9,  32);
define_register(r10d,   Register_10, 32);
define_register(r11d,   Register_11, 32);
define_register(r12d,   Register_12, 32);
define_register(r13d,   Register_13, 32);
define_register(r14d,   Register_14, 32);
define_register(r15d,   Register_15, 32);

/* 16-bit registers */
define_register(ax,     Register_A,  16);
define_register(cx,     Register_C,  16);
define_register(dx,     Register_D,  16);
define_register(bx,     Register_C,  16);
define_register(sp,     Register_SP, 16);
define_register(bp,     Register_BP, 16);
define_register(si,     Register_SI, 16);
define_register(di,     Register_DI, 16);
define_register(r8w,    Register_8,  16);
define_register(r9w,    Register_9,  16);
define_register(r10w,   Register_10, 16);
define_register(r11w,   Register_11, 16);
define_register(r12w,   Register_12, 16);
define_register(r13w,   Register_13, 16);
define_register(r14w,   Register_14, 16);
define_register(r15w,   Register_15, 16);

/* 8-bit registers */
define_register(al,     Register_A,  8);
define_register(cl,     Register_C,  8);
define_register(dl,     Register_D,  8);
define_register(bl,     Register_C,  8);
define_register(spl,    Register_SP, 8);
define_register(bpl,    Register_BP, 8);
define_register(sil,    Register_SI, 8);
define_register(dil,    Register_DI, 8);
define_register(r8b,    Register_8,  8);
define_register(r9b,    Register_9,  8);
define_register(r10b,   Register_10, 8);
define_register(r11b,   Register_11, 8);
define_register(r12b,   Register_12, 8);
define_register(r13b,   Register_13, 8);
define_register(r14b,   Register_14, 8);
define_register(r15b,   Register_15, 8);

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

static inline Operand imm32(u32 value)
{
    return (const Operand)_imm(32, value);
}

static inline Operand imm64(u64 value)
{
    return (const Operand)_imm(64, value);
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
    // mov rm64, r64
    {
        .op_code = 0x89,
        .extension = IET_Register,
        .types =
        {
            [0] = {.type = OET_Register_Or_Memory, .size = OperandSize_64, },
            [1] = {.type = OET_Register, .size = OperandSize_64,},
        },
    },
    //mov rm64, imm32
    {
        .op_code = 0xc7,
        .extension = IET_Register,
        .types = 
        {
            [0] = {.type = OET_Register_Or_Memory, .size = OperandSize_64, },
            [1] = {.type = OET_Immediate, .size = OperandSize_32,},
        },
    },
    // mov r64, imm64
    {
        .op_code = 0xb8,
        .extension = IET_Register,
        .types =
        {
            [0] = {.type = OET_Register, .size = OperandSize_64,},
            [1] = {.type = OET_Immediate, .size = OperandSize_64,},
        },
    },
    // mov r32, imm32
    {
        .op_code = 0xb8,
        .extension = IET_Plus_Register,
        .types =
        {
            [0] = {.type = OET_Register, .size = OperandSize_32,},
            [1] = {.type = OET_Immediate, .size = OperandSize_32,},
        },
    },
    // mov r8, imm8
    {
        .op_code = 0xb0,
        .extension = IET_Plus_Register,
        .types =
        {
            [0] = {.type = OET_Register, .size = OperandSize_8,},
            [1] = {.type = OET_Immediate, .size = OperandSize_8,},
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
        .op_code = 0x05,
        .extension = IET_Register,
        .types = 
        {
            [0] = {.type = OET_Register_A, .size = OperandSize_32,},
            [1] = {.type = OET_Immediate, .size = OperandSize_32,},
        },
    },
    {
        .op_code = 0x03,
        .extension = IET_Register,
        .types =
        {
            [0] = {.type = OET_Register, .size = OperandSize_Any},
            [1] = {.type = OET_Register_Or_Memory, .size = OperandSize_Any, },
        },
    },
    {
        .op_code = 0x83,
        .extension = IET_OpCode,
        .op_code_extension = 0,
        .types =
        {
            [0] = {.type = OET_Register_Or_Memory, .size = OperandSize_Any, },
            [1] = {.type = OET_Immediate, .size = OperandSize_8, },
        },
    },
    {
        .op_code = 0x81,
        .extension = IET_Register,
        .op_code_extension = 0,
        .types =
        {
            [0] = {.type = OET_Register_Or_Memory, .size = OperandSize_Any, },
            [1] = {.type = OET_Immediate, .size = OperandSize_32, },
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
            Operand operand = instruction.operands[j];
            OperandType operand_type = operand.type;
            OperandSize operand_size = operand.size;

            if (operand_type == OperandType_None && encoding_type == OET_None)
            {
                continue;
            }
            if (operand_type == OperandType_Register && encoding_type == OET_Register_A && operand.reg == Register_A && (encoding_size == operand_size || encoding_size == OperandSize_Any))
            {
                continue;
            }
            if (operand_type == OperandType_Register && encoding_type == OET_Register && (encoding_size == operand_size || encoding_size == OperandSize_Any))
            {
                continue;
            }
            if (operand_type == OperandType_Register && encoding_type == OET_Register_Or_Memory && (encoding_size == operand_size || encoding_size == OperandSize_Any))
            {
                continue;
            }
            if (operand_type == OperandType_Immediate && encoding_type == OET_Immediate && (encoding_size == operand_size || encoding_size == OperandSize_Any))
            {
                continue;
            }
            if (operand_type == OperandType_MemoryIndirect && encoding_type == OET_Register_Or_Memory)
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

            if (operand.type == OperandType_Register && encoding.extension != IET_Plus_Register && operand.size == OperandSize_64)
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
			print("Mod register: 0x%02X, register_or_op_code: 0x%02X, r_m: 0x%02X. Appending: 0x%02X\n", Mod_Register, register_or_op_code, r_m, mod_rm);
			print("Result: ");
			print_binary(&mod_rm, 1);
			u8 mod_rm_expected = 0xc3;
			print("Expected: ");
			print_binary(&mod_rm_expected, 1);
			print("Expected: 0x%02X, result: 0x%02X\n", mod_rm_expected, mod_rm);

			//TODO: This hack was working before the crash
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
				case OperandType_Immediate:
					switch (operand.size)
					{
						case (OperandSize_64):
							u64_append(eb, operand.imm._64);
							break;
						case (OperandSize_32):
							u32_append(eb, operand.imm._32);
							break;
						case (OperandSize_8):
							u8_append(eb, operand.imm._8);
							break;
						default:
							break;
					}
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

static void test_mov_r64_imm64(void* s)
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

static void test_mov_r32_imm32(void* s)
{
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) {
        mov, { ebx, imm32(0xffffffff) },
    });

    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0xbb);
    u8_append(&expected, 0xff);
    u8_append(&expected, 0xff);
    u8_append(&expected, 0xff);
    u8_append(&expected, 0xff);

    test_buffer(&eb, expected.ptr, expected.len, __func__);
}

static void test_add_r64_imm8(void* s)
{
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) {
        add, { rax, imm8(0x8) },
    });

    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0x48);
    u8_append(&expected, 0x83);
    u8_append(&expected, 0xc0);
    u8_append(&expected, 0x08);

    test_buffer(&eb, expected.ptr, expected.len, __func__);
}
static void test_add_r32_imm8(void* s)
{
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) {
        add, { eax, imm8(0x8) },
    });

    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0x83);
    u8_append(&expected, 0xc0);
    u8_append(&expected, 0x08);

    test_buffer(&eb, expected.ptr, expected.len, __func__);
}

static void test_add_r64_imm32(void* s)
{
    u32 number = 0xfffff;
    ExecutionBuffer eb = give_me(64);
    encode(&eb, (Instruction) {
        add, { rbx, imm32(number) },
    });

    ExecutionBuffer expected = give_me(64);
    u8_append(&expected, 0x48);
    u8_append(&expected, 0x81);
    u8_append(&expected, 0xc3);
    u32_append(&expected, number);

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
    {test_add_r64_imm32}
};

s32 main(s32 argc, char* argv[])
{
    for (u32 i = 0; i < array_length(tests); i++)
    {
        tests[i].fn(tests[i].args);
    }
}
