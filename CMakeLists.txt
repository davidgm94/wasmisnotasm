project(wasmnotasm)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Debug)
set(WASM_NOT_ASM_SRC
    src/execution_buffer.h
    src/main.c
    src/os.c
)
add_executable(wasmnotasm ${WASM_NOT_ASM_SRC})
