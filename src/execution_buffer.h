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

static inline void print_chunk_of_bytes_in_hex(u8* buffer, usize size, const char* text)
{
    if (text)
    {
        print("%s", text);
    }

    for (usize i = 0; i < size; i++)
    {
        print("0x%02X ", buffer[i]);
    }
    print("\n");
}

static inline void print_binary(void* number_ptr, u32 bytes)
{
    s32 bits = 8 * bytes;
    u64 n = *(u64*)number_ptr;
    for (s32 i = bits - 1; i >= 0; i--)
    {
        print("%d", (n & (1 << i)) >> i);
    }
    print("\n");
}

static inline bool test_buffer(ExecutionBuffer* eb, u8* test_case, u32 case_size, const char* str)
{
    bool success = true;
    for (u32 i = 0; i < case_size; i++)
    {
        u8 got = eb->ptr[i];
        u8 expected = test_case[i];
        if (got != expected)
        {
            print("[Index %u] Expected 0x%02X. Found 0x%02X.\n", i, expected, got);
            success = false;
        }
    }

    s32 chars = printf("[TEST] %s", str);
    while (chars < 40)
    {
        putc(' ', stdout);
        chars++;
    }
    if (success)
    {
        print("[OK]\n");
    }
    else
    {
        print("[FAILED]\n");
        print_chunk_of_bytes_in_hex(test_case, case_size, "Expected:\t");
        print_chunk_of_bytes_in_hex(eb->ptr, eb->len, "Result:\t\t");
    }

    return success;
}
