#ifndef DV_H
#define DV_H

#if defined(_WIN32) || defined(_WIN64)
#define FQL __declspec(dllexport)
#else
#define FQL __attribute__((visibility("default")))
#endif

#include "dynarmic/interface/A64/config.h"
#include "dynarmic/interface/A32/config.h"
#include "khash.h"

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using usize = std::size_t;
using addr = u64;


#define PAGE_TABLE_ADDRESS_SPACE_BITS 40
#define DYN_PAGE_BITS 12 // 4k
#define DYN_PAGE_SIZE (1ULL << DYN_PAGE_BITS)
#define DYN_PAGE_MASK (DYN_PAGE_SIZE-1)
#define UC_PROT_WRITE 2

typedef struct memory_page {
    void *addr;
    int perms;
    bool is_external;
} *t_memory_page;

KHASH_MAP_INIT_INT64(memory, t_memory_page)

using Vector = std::array<std::uint64_t, 2>;
typedef struct context64 {
    std::uint64_t sp;
    std::uint64_t pc;
    std::array<std::uint64_t, 31> registers;
    std::array<Vector, 32> vectors;
    std::uint32_t fpcr;
    std::uint32_t fpsr;
    std::uint32_t pstate;
    std::uint64_t tpidr_el0;
    std::uint64_t tpidrro_el0;
} *t_context64;

typedef struct context32 {
    std::array<std::uint32_t, 16> registers; // R0-R15
    std::uint32_t cpsr;
    std::array<std::uint32_t, 64> ext_regs; // VFP/NEON
    std::uint32_t fpscr;
    std::uint32_t tpidrurw; // TPIDRURW (User Read/Write Thread ID)
    std::uint32_t tpidruro; // TPIDRURO (User Read-Only Thread ID)
} *t_context32;

using cb_interpreter_fallback = void(*)(addr vaddr, usize num_instructions, void* user_data);
using cb_call_svc =             void(*)(u32 swi, void* user_data);
using cb_exception_raised =     void(*)(addr pc, u32 exception, void* user_data);
using cb_mem_hook =             bool(*)(u64 addr, usize size, u64 value, void* user_data);

struct dynarmic;

typedef struct coprocessor_handler {
    void* user_data;
    void (*send_one_word)(void* user_data, bool two, unsigned opc1, unsigned CRn, unsigned CRm, unsigned opc2, u32 value);
    void (*send_two_words)(void* user_data, bool two, unsigned opc, unsigned CRm, u32 low, u32 high);
    u32 (*get_one_word)(void* user_data, bool two, unsigned opc1, unsigned CRn, unsigned CRm, unsigned opc2);
    u64 (*get_two_words)(void* user_data, bool two, unsigned opc, unsigned CRm);
} coprocessor_handler;

extern "C" {
FQL int dynarmic_version(); // Returns the version of Dynarmic

FQL const char *dynarmic_colorful_egg();

FQL khash_t(memory) *dynarmic_init_memory();

FQL Dynarmic::ExclusiveMonitor *dynarmic_init_monitor(u32 processor_count);

FQL void** dynarmic_init_page_table();

FQL dynarmic* dynarmic_new(
        u32 process_id,
        khash_t(memory) *memory,
        Dynarmic::ExclusiveMonitor *monitor,
        void **page_table,
        u64 jit_size,
        bool unsafe_optimizations
);

FQL dynarmic* dynarmic_new_a32(
        u32 process_id,
        khash_t(memory) *memory,
        Dynarmic::ExclusiveMonitor *monitor,
        void **page_table,
        u64 jit_size,
        bool unsafe_optimizations,
        coprocessor_handler* handlers
);

FQL u64 dynarmic_get_cache_size(dynarmic* dynarmic);

FQL void dynarmic_destroy(dynarmic *dynarmic);

FQL void dynarmic_set_svc_callback(dynarmic *dynarmic, cb_call_svc cb, void* user_data);

FQL void dynarmic_set_unmapped_mem_callback(dynarmic *dynarmic, cb_mem_hook cb, void* user_data);

FQL int dynarmic_munmap(dynarmic* dynarmic, u64 address, u64 size);

FQL void dynarmic_invalidate_cache(dynarmic* dynarmic, u64 addr, u64 size);

FQL int dynarmic_mmap(dynarmic* dynarmic, u64 address, u64 size, int perms);

FQL int dynarmic_mem_map_ptr(dynarmic* dynarmic, u64 address, u64 size, int perms, void* ptr);

FQL int dynarmic_mem_protect(dynarmic* dynarmic, u64 address, u64 size, int perms);

FQL int dynarmic_mem_write(dynarmic* dynarmic, u64 address, char* data, usize size);

FQL int dynarmic_mem_read(dynarmic* dynarmic, u64 address, char* bytes, usize size);

// A64 Registers
FQL u64 reg_read_pc(dynarmic* dynarmic);

FQL int reg_write_pc(dynarmic* dynarmic, u64 value);

FQL int reg_write_sp(dynarmic* dynarmic, u64 value);

FQL u64 reg_read_sp(dynarmic* dynarmic);

FQL u64 reg_read_nzcv(dynarmic* dynarmic);

FQL int reg_write_nzcv(dynarmic* dynarmic, u64 value);

FQL int reg_write_tpidr_el0(dynarmic* dynarmic, u64 value);

FQL u64 reg_read_tpidr_el0(dynarmic* dynarmic);

FQL int reg_write_vector(dynarmic* dynarmic, u64 index, u64* array);

FQL int reg_read_vector(dynarmic* dynarmic, u64 index, u64* array);

FQL int reg_write(dynarmic* dynarmic, u64 index, u64 value);

FQL u64 reg_read(dynarmic* dynarmic, u64 index);

// A32 Registers
FQL int reg_write_r(dynarmic* dynarmic, u32 index, u32 value);
FQL u32 reg_read_r(dynarmic* dynarmic, u32 index);
FQL int reg_write_cpsr(dynarmic* dynarmic, u32 value);
FQL u32 reg_read_cpsr(dynarmic* dynarmic);
FQL int reg_write_c13_c0_3(dynarmic* dynarmic, u32 value); // TPIDRURO
FQL u32 reg_read_c13_c0_3(dynarmic* dynarmic);

FQL int dynarmic_emu_start(dynarmic* dynarmic, u64 pc);

FQL int dynarmic_emu_stop(dynarmic* dynarmic);

FQL t_context64 dynarmic_context_alloc();

FQL void dynarmic_context_free(t_context64 context);

FQL int dynarmic_context_restore(dynarmic* dynarmic, t_context64 context);

FQL int dynarmic_context_save(dynarmic* dynarmic, t_context64 context);

FQL t_context32 dynarmic_context32_alloc();
FQL void dynarmic_context32_free(t_context32 context);
FQL int dynarmic_context32_restore(dynarmic* dynarmic, t_context32 context);
FQL int dynarmic_context32_save(dynarmic* dynarmic, t_context32 context);
}

#endif // DV_H