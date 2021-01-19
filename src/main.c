#include "types.h"
#include "os.h"
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

typedef struct
{
    u8* ptr;
    u32 len;
    u32 cap;
} ExecutionBuffer;

static inline ExecutionBuffer give_me(u64 capacity)
{
    void* ptr = mmap(null, capacity, PROT_WRITE | PROT_READ | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    redassert(ptr);

    ExecutionBuffer eb =
    {
        .ptr = ptr,
        .len = 0,
        .cap = capacity,
    };
    
    return eb;
}

#define APPEND(type)\
    static inline void type##_append(ExecutionBuffer* eb, type value)\
{\
    usize size_to_be_added = sizeof(type);\
    redassert(eb->len + size_to_be_added < eb->cap);\
    type* ptr = (type*) &eb->ptr[eb->len];\
    *ptr = value;\
    eb->len += size_to_be_added;\
}

APPEND(u8)
APPEND(u16)
APPEND(u32)
APPEND(u64)
APPEND(s8)
APPEND(s16)
APPEND(s32)
APPEND(s64)

static inline void append_chunk(ExecutionBuffer* eb, void* ptr, usize size)
{
    redassert(eb->len + size < eb->cap);
    memcpy((void*)&eb->ptr[eb->len], ptr, size);
    eb->len += size;
}
// This only works with static arrays (compile-time known ones)
#define array_append(b, arr) append_chunk(b, (void*)arr, sizeof(arr))

typedef s64 square_fn(s64);
typedef s64 mul_fn(s64, s64);
typedef s64 make_increment_s64(s64);

static const u8 RET = 0xc3;
static const u8 MOV_RAX_RDI[] = { 0x48, 0x89, 0xf8 };
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

// Helper
static inline void ret(ExecutionBuffer* eb)
{
    u8_append(eb, RET);
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


static inline void add_rax_imm_s32(ExecutionBuffer* eb, s32 value)
{
    const u8 ADD_RAX_IMM_S32[] = { 0x48, 0x05 };
    array_append(eb, ADD_RAX_IMM_S32);
    s32_append(eb, value);
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
        printf("TEST %s\t[OK]\n", __func__);\
    }\
    else\
    {\
        printf("TEST %s \t[FAILED] Unexpected result: %ld. Expected result: %ld\n", __func__, result, expected);\
    }\
}

static void test_mul_s64(s64 a, s64 b)
{
    ExecutionBuffer eb = give_me(1024);

    array_append(&eb, MOV_RAX_RDI);
    array_append(&eb, IMUL_RAX_RSI);
    ret(&eb);

    mul_fn* fn = (mul_fn*)eb.ptr;
    s64 result = fn(a, b);
    s64 expected = a * b;

    TEST_EQUAL_S64(result, expected);
}

static void test_square_s64(s64 n)
{
    ExecutionBuffer eb = give_me(1024);

    array_append(&eb, MOV_RAX_RDI);
    array_append(&eb, IMUL_RAX_RDI);
    ret(&eb);

    square_fn* fn = (square_fn*)eb.ptr;
    s64 result = fn(n);
    s64 expected = n * n;

    TEST_EQUAL_S64(result, expected);
}

static void test_increment_s64(s64 n)
{
    ExecutionBuffer eb = give_me(1024);

    array_append(&eb, MOV_RAX_RDI);
    add_rax_imm_s32(&eb, 0x01);
    ret(&eb);

    square_fn* fn = (square_fn*)eb.ptr;
    s64 result = fn(n);
    s64 expected = n + 1;

    TEST_EQUAL_S64(result, expected);
}

static void test_increment_s64_slow(s64 n)
{
    ExecutionBuffer eb = give_me(1024);

    push_rbp(&eb);
    array_append(&eb, MOV_RBP_RSP);
    array_append(&eb, MOV_RAX_RDI);
    mov_rbp8_reg_0x48(&eb, RDI_0x48);
    mov_rbp16_imm32(&eb, 0x1);
    mov_reg_0x48_rbp16(&eb, RAX_0x48);
    add_reg_0x48_rbp8(&eb, RAX_0x48);
    pop_rbp(&eb);
    ret(&eb);

    square_fn* fn = (square_fn*)eb.ptr;
    s64 result = fn(n);
    s64 expected = n + 1;

    TEST_EQUAL_S64(result, expected);
}

s32 main(s32 argc, char* argv[])
{
    test_mul_s64(5, 7);
    test_square_s64(10);
    test_increment_s64(10);
    test_increment_s64_slow(10);
}
