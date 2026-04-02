#include <array>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <optional>
#include <variant>
#include <vector>
#include <algorithm>
#include <cstring>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "ConstantConditionsOC"
#if defined(_WIN32) || defined(_WIN64)
#include "mman.h"
#include <errno.h>
#else
#include <sys/mman.h>
#include <sys/errno.h>
#endif

#include "dynarmic/interface/A64/a64.h"
#include "dynarmic/interface/A64/config.h"
#include "dynarmic/interface/A32/a32.h"
#include "dynarmic/interface/A32/config.h"
#include "dynarmic/interface/A32/coprocessor.h"
#include "dynarmic/interface/exclusive_monitor.h"
#include "dynarmic/interface/optimization_flags.h"
#include "dynarmic.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"

// #define LOG_DEBUG(fmt, ...) { fprintf(stderr, fmt, ##__VA_ARGS__); fflush(stderr); }
#define LOG_DEBUG(fmt, ...)

static inline char *get_memory_page(khash_t(memory) *memory, u64 vaddr, size_t num_page_table_entries, void **page_table) {
    u64 idx = vaddr >> DYN_PAGE_BITS;
    if(page_table && idx < num_page_table_entries && page_table[idx]) {
        return (char *)((uintptr_t)page_table[idx] + (vaddr & ~DYN_PAGE_MASK));
    }
    u64 base = vaddr & ~DYN_PAGE_MASK;
    khiter_t k = kh_get(memory, memory, base);
    if(k == kh_end(memory)) {
        return nullptr;
    }
    t_memory_page page = kh_value(memory, k);
    return (char *)page->addr;
}

static inline void *get_memory(khash_t(memory) *memory, u64 vaddr, size_t num_page_table_entries, void **page_table) {
    char *page = get_memory_page(memory, vaddr, num_page_table_entries, page_table);
    return page ? &page[vaddr & DYN_PAGE_MASK] : nullptr;
}

class DynarmicCallbacks64 final : public Dynarmic::A64::UserCallbacks {
public:
    explicit DynarmicCallbacks64(khash_t(memory) *memory)
            : memory{memory} {}

    // Strip MTE/TBI top byte from addresses (Android uses tagged pointers)
    static inline u64 strip_tag(u64 vaddr) { return vaddr & 0x00FFFFFFFFFFFFFFULL; }

    bool IsReadOnlyMemory(u64 vaddr) override { return false; }
    std::optional<std::uint32_t> MemoryReadCode(u64 vaddr) override {
        vaddr = strip_tag(vaddr);
        u32 *dest = (u32 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) return dest[0];
        // Unmapped code page — try callback, then halt if still unmapped
        if (unmapped_mem_callback) {
            unmapped_mem_callback(vaddr, 4, 0, unmapped_mem_user_data);
            dest = (u32 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
            if (dest) return dest[0];
        }
        // Return empty to signal halt
        if (cpu) cpu->HaltExecution(Dynarmic::HaltReason::MemoryAbort);
        return 0xD4200020; // BRK #1
    }

    u8 MemoryRead8(u64 vaddr) override {
        vaddr = strip_tag(vaddr);
        u8 *dest = (u8 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) return dest[0];
        if (unmapped_mem_callback && unmapped_mem_callback(vaddr, 1, 0, unmapped_mem_user_data)) {
            dest = (u8 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
            if (dest) return dest[0];
        }
        return 0;
    }
    u16 MemoryRead16(u64 vaddr) override {
        vaddr = strip_tag(vaddr);
        u16 *dest = (u16 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) return dest[0];
        return 0;
    }
    u32 MemoryRead32(u64 vaddr) override {
        vaddr = strip_tag(vaddr);
        u32 *dest = (u32 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) return dest[0];
        if (unmapped_mem_callback && unmapped_mem_callback(vaddr, 4, 0, unmapped_mem_user_data)) {
            dest = (u32 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
            if (dest) return dest[0];
        }
        return 0;
    }
    u64 MemoryRead64(u64 vaddr) override {
        vaddr = strip_tag(vaddr);
        u64 *dest = (u64 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) return dest[0];
        return 0;
    }
    Dynarmic::A64::Vector MemoryRead128(u64 vaddr) override {
        vaddr = strip_tag(vaddr);
        return {MemoryRead64(vaddr), MemoryRead64(vaddr + 8)};
    }

    void MemoryWrite8(u64 vaddr, u8 value) override {
        vaddr = strip_tag(vaddr);
        u8 *dest = (u8 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) { dest[0] = value; return; }
    }
    void MemoryWrite16(u64 vaddr, u16 value) override {
        vaddr = strip_tag(vaddr);
        u16 *dest = (u16 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) { dest[0] = value; return; }
    }
    void MemoryWrite32(u64 vaddr, u32 value) override {
        vaddr = strip_tag(vaddr);
        u32 *dest = (u32 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) { dest[0] = value; return; }
    }
    void MemoryWrite64(u64 vaddr, u64 value) override {
        vaddr = strip_tag(vaddr);
        u64 *dest = (u64 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) { dest[0] = value; return; }
    }
    void MemoryWrite128(u64 vaddr, Dynarmic::A64::Vector value) override {
        vaddr = strip_tag(vaddr);
        MemoryWrite64(vaddr, value[0]);
        MemoryWrite64(vaddr + 8, value[1]);
    }

    bool MemoryWriteExclusive8(u64 vaddr, std::uint8_t value, std::uint8_t expected) override { MemoryWrite8(vaddr, value); return true; }
    bool MemoryWriteExclusive16(u64 vaddr, std::uint16_t value, std::uint16_t expected) override { MemoryWrite16(vaddr, value); return true; }
    bool MemoryWriteExclusive32(u64 vaddr, std::uint32_t value, std::uint32_t expected) override { MemoryWrite32(vaddr, value); return true; }
    bool MemoryWriteExclusive64(u64 vaddr, std::uint64_t value, std::uint64_t expected) override { MemoryWrite64(vaddr, value); return true; }
    bool MemoryWriteExclusive128(u64 vaddr, Dynarmic::A64::Vector value, Dynarmic::A64::Vector expected) override { MemoryWrite128(vaddr, value); return true; }

    void InterpreterFallback(u64 pc, std::size_t num_instructions) override { fprintf(stderr, "[INTERP] Fallback at PC=0x%llx num=%zu\n", (unsigned long long)pc, num_instructions); fflush(stderr); cpu->HaltExecution(); }
    void ExceptionRaised(u64 pc, Dynarmic::A64::Exception exception) override { fprintf(stderr, "[EXC] PC=0x%llx exc=%d\n", (unsigned long long)pc, (int)exception); fflush(stderr); 
        if (exception == Dynarmic::A64::Exception::Yield) return;
        cpu->SetPC(pc); cpu->HaltExecution();
    }

    void CallSVC(u32 swi) override {
        if (svc_callback) { svc_callback(swi, svc_user_data); return; }
        cpu->HaltExecution();
    }

    u64 ticks_remaining = 5000000000ULL; // 5 billion ticks
    void AddTicks(u64 ticks) override { if(ticks_remaining > ticks) ticks_remaining -= ticks; else ticks_remaining = 0; }
    u64 GetTicksRemaining() override { return ticks_remaining; }
    u64 GetCNTPCT() override { return 0x10000000000ULL - ticks_remaining; }

    u64 tpidrro_el0 = 0;
    u64 tpidr_el0 = 0;
    khash_t(memory) *memory = nullptr;
    size_t num_page_table_entries = 0;
    void **page_table = nullptr;
    Dynarmic::A64::Jit *cpu = nullptr;
    cb_call_svc svc_callback = nullptr;
    void* svc_user_data = nullptr;
    cb_mem_hook unmapped_mem_callback = nullptr;
    void* unmapped_mem_user_data = nullptr;

    ~DynarmicCallbacks64() override = default;
};

class DynarmicCallbacks32 final : public Dynarmic::A32::UserCallbacks {
public:
    explicit DynarmicCallbacks32(khash_t(memory) *memory)
            : memory{memory} {}

    u8 MemoryRead8(u32 vaddr) override {
        u8 *dest = (u8 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
        if(dest) return dest[0];
        if (unmapped_mem_callback && unmapped_mem_callback(vaddr, 1, 0, unmapped_mem_user_data)) {
            dest = (u8 *) get_memory(memory, vaddr, num_page_table_entries, page_table);
            if (dest) return dest[0];
        }
        return 0;
    }
    u16 MemoryRead16(u32 vaddr) override { u16 *dest = (u16 *) get_memory(memory, vaddr, num_page_table_entries, page_table); return dest ? dest[0] : 0; }
    u32 MemoryRead32(u32 vaddr) override { u32 *dest = (u32 *) get_memory(memory, vaddr, num_page_table_entries, page_table); return dest ? dest[0] : 0; }
    u64 MemoryRead64(u32 vaddr) override { u64 *dest = (u64 *) get_memory(memory, vaddr, num_page_table_entries, page_table); return dest ? dest[0] : 0; }

    void MemoryWrite8(u32 vaddr, u8 value) override { u8 *dest = (u8 *) get_memory(memory, vaddr, num_page_table_entries, page_table); if(dest) dest[0] = value; }
    void MemoryWrite16(u32 vaddr, u16 value) override { u16 *dest = (u16 *) get_memory(memory, vaddr, num_page_table_entries, page_table); if(dest) dest[0] = value; }
    void MemoryWrite32(u32 vaddr, u32 value) override { u32 *dest = (u32 *) get_memory(memory, vaddr, num_page_table_entries, page_table); if(dest) dest[0] = value; }
    void MemoryWrite64(u32 vaddr, u64 value) override { u64 *dest = (u64 *) get_memory(memory, vaddr, num_page_table_entries, page_table); if(dest) dest[0] = value; }

    bool MemoryWriteExclusive8(u32 vaddr, std::uint8_t value, std::uint8_t expected) override { MemoryWrite8(vaddr, value); return true; }
    bool MemoryWriteExclusive16(u32 vaddr, std::uint16_t value, std::uint16_t expected) override { MemoryWrite16(vaddr, value); return true; }
    bool MemoryWriteExclusive32(u32 vaddr, std::uint32_t value, std::uint32_t expected) override { MemoryWrite32(vaddr, value); return true; }
    bool MemoryWriteExclusive64(u32 vaddr, std::uint64_t value, std::uint64_t expected) override { MemoryWrite64(vaddr, value); return true; }

    void InterpreterFallback(u32 pc, std::size_t num_instructions) override { cpu->HaltExecution(); }
    void ExceptionRaised(u32 pc, Dynarmic::A32::Exception exception) override { 
        if (exception == Dynarmic::A32::Exception::Yield) return;
        cpu->Regs()[15] = pc; cpu->HaltExecution();
    }

    void CallSVC(u32 swi) override {
        if (svc_callback) { svc_callback(swi, svc_user_data); return; }
        cpu->HaltExecution();
    }

    void AddTicks(u64 ticks) override {}
    u64 GetTicksRemaining() override { return 0x10000000000ULL; }

    khash_t(memory) *memory = nullptr;
    size_t num_page_table_entries = 0;
    void **page_table = nullptr;
    Dynarmic::A32::Jit *cpu = nullptr;
    cb_call_svc svc_callback = nullptr;
    void* svc_user_data = nullptr;
    cb_mem_hook unmapped_mem_callback = nullptr;
    void* unmapped_mem_user_data = nullptr;
    u32 tpidruro = 0;
    u32 tpidrurw = 0;

    ~DynarmicCallbacks32() override = default;
};

class RustCoprocessor final : public Dynarmic::A32::Coprocessor {
public:
    struct CallInfo { RustCoprocessor* self; unsigned opc1; unsigned CRn; unsigned CRm; unsigned opc2; unsigned opc; };
    explicit RustCoprocessor(int cp_num, DynarmicCallbacks32* callbacks) : cp_num(cp_num), callbacks(callbacks) { std::memset(&handler, 0, sizeof(handler)); }
    void SetHandler(const coprocessor_handler& h) { handler = h; }
    
    std::optional<Callback> CompileInternalOperation(bool two, unsigned opc, Dynarmic::A32::CoprocReg CRd, Dynarmic::A32::CoprocReg CRn, Dynarmic::A32::CoprocReg CRm, unsigned opc2) override { 
        return Callback{[](void*, uint32_t, uint32_t) -> uint64_t { return 0; }, nullptr}; 
    }
    
    CallbackOrAccessOneWord CompileSendOneWord(bool two, unsigned opc1, Dynarmic::A32::CoprocReg CRn, Dynarmic::A32::CoprocReg CRm, unsigned opc2) override { 
        if (cp_num == 15 && opc1 == 0 && (int)CRn == 13 && (int)CRm == 0 && opc2 == 2) { 
            return Callback{[](void* arg, uint32_t value, uint32_t) -> uint64_t { ((RustCoprocessor*)arg)->callbacks->tpidrurw = value; return 0; }, this}; 
        } 
        CallInfo* info = new CallInfo{this, opc1, (unsigned)CRn, (unsigned)CRm, opc2, 0}; 
        infos.push_back(info); 
        return Callback{[](void* arg, uint32_t value, uint32_t) -> uint64_t { 
            auto info = (CallInfo*)arg; 
            if (info->self->handler.send_one_word) info->self->handler.send_one_word(info->self->handler.user_data, false, info->opc1, info->CRn, info->CRm, info->opc2, value); 
            return 0; 
        }, info}; 
    }
    
    CallbackOrAccessTwoWords CompileSendTwoWords(bool two, unsigned opc, Dynarmic::A32::CoprocReg CRm) override { 
        CallInfo* info = new CallInfo{this, 0, 0, (unsigned)CRm, 0, opc}; 
        infos.push_back(info); 
        return Callback{[](void* arg, uint32_t low, uint32_t high) -> uint64_t { auto info = (CallInfo*)arg; if (info->self->handler.send_two_words) info->self->handler.send_two_words(info->self->handler.user_data, false, info->opc, info->CRm, low, high); return 0; }, info}; 
    }
    
    CallbackOrAccessOneWord CompileGetOneWord(bool two, unsigned opc1, Dynarmic::A32::CoprocReg CRn, Dynarmic::A32::CoprocReg CRm, unsigned opc2) override { 
        if (cp_num == 15 && opc1 == 0 && (int)CRn == 13 && (int)CRm == 0 && opc2 == 2) { return Callback{[](void* arg, uint32_t, uint32_t) -> uint64_t { return (uint64_t)((RustCoprocessor*)arg)->callbacks->tpidrurw; }, this}; } 
        if (cp_num == 15 && opc1 == 0 && (int)CRn == 13 && (int)CRm == 0 && opc2 == 3) { return Callback{[](void* arg, uint32_t, uint32_t) -> uint64_t { return (uint64_t)((RustCoprocessor*)arg)->callbacks->tpidruro; }, this}; } 
        CallInfo* info = new CallInfo{this, opc1, (unsigned)CRn, (unsigned)CRm, opc2, 0}; infos.push_back(info); return Callback{[](void* arg, uint32_t, uint32_t) -> uint64_t { auto info = (CallInfo*)arg; 
            return info->self->handler.get_one_word ? (uint64_t)info->self->handler.get_one_word(info->self->handler.user_data, false, info->opc1, info->CRn, info->CRm, info->opc2) : 0; }, info}; }
    
    CallbackOrAccessTwoWords CompileGetTwoWords(bool two, unsigned opc, Dynarmic::A32::CoprocReg CRm) override { 
        CallInfo* info = new CallInfo{this, 0, 0, (unsigned)CRm, 0, opc}; infos.push_back(info); return Callback{[](void* arg, uint32_t, uint32_t) -> uint64_t { auto info = (CallInfo*)arg; return info->self->handler.get_two_words ? info->self->handler.get_two_words(info->self->handler.user_data, false, info->opc, info->CRm) : 0; }, info}; } 
    
    std::optional<Callback> CompileLoadWords(bool two, bool long_transfer, Dynarmic::A32::CoprocReg CRd, std::optional<std::uint8_t> option) override { 
        return Callback{[](void*, uint32_t, uint32_t) -> uint64_t { return 0; }, nullptr}; 
    }
    
    std::optional<Callback> CompileStoreWords(bool two, bool long_transfer, Dynarmic::A32::CoprocReg CRd, std::optional<std::uint8_t> option) override { 
        return Callback{[](void*, uint32_t, uint32_t) -> uint64_t { return 0; }, nullptr}; 
    }
    
    ~RustCoprocessor() { for (auto info : infos) delete info; }
    int cp_num; DynarmicCallbacks32* callbacks; coprocessor_handler handler; std::vector<CallInfo*> infos;
};

typedef struct dynarmic {
    khash_t(memory) *memory;
    size_t num_page_table_entries;
    void **page_table;
    DynarmicCallbacks64 *cb64;
    Dynarmic::A64::Jit *jit64;
    DynarmicCallbacks32 *cb32;
    Dynarmic::A32::Jit *jit32;
    Dynarmic::ExclusiveMonitor *monitor;
    std::shared_ptr<Dynarmic::A32::Coprocessor> coprocessors[16];
    u64 tpidrro_el0_val = 0;
} *t_dynarmic;

extern "C" {

FQL int dynarmic_version() { return 20260209; } 
FQL const char* dynarmic_colorful_egg() { return "🥚"; }

FQL khash_t(memory) *dynarmic_init_memory() {
    khash_t(memory) *memory = kh_init(memory);
    kh_resize(memory, memory, 0x1000);
    return memory;
}

FQL Dynarmic::ExclusiveMonitor *dynarmic_init_monitor(u32 processor_count) {
    return new Dynarmic::ExclusiveMonitor(processor_count);
}

FQL void** dynarmic_init_page_table() {
    size_t size = (1ULL << (PAGE_TABLE_ADDRESS_SPACE_BITS - DYN_PAGE_BITS)) * sizeof(void *);
    void **page_table = (void **) mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    return (page_table == MAP_FAILED) ? nullptr : page_table;
}

FQL dynarmic* dynarmic_new(u32 process_id, khash_t(memory) *memory, Dynarmic::ExclusiveMonitor *monitor, void **page_table, uint64_t jit_size, bool unsafe_optimizations) {
    auto backend = (t_dynarmic) malloc(sizeof(struct dynarmic));
    memset(backend, 0, sizeof(struct dynarmic));
    backend->memory = memory;
    backend->monitor = monitor;
    backend->cb32 = nullptr;
    backend->jit32 = nullptr;
    auto *callbacks = new DynarmicCallbacks64(backend->memory);

    Dynarmic::A64::UserConfig config;
    config.callbacks = callbacks;
    config.tpidrro_el0 = &backend->tpidrro_el0_val;
    config.tpidr_el0 = &callbacks->tpidr_el0;
    config.processor_id = process_id;
    config.global_monitor = backend->monitor;
    config.wall_clock_cntpct = true;
    config.code_cache_size = jit_size;

    if(unsafe_optimizations) {
        config.unsafe_optimizations = true;
        config.optimizations |= Dynarmic::OptimizationFlag::Unsafe_IgnoreGlobalMonitor;
        config.optimizations |= Dynarmic::OptimizationFlag::Unsafe_ReducedErrorFP;
    }

    backend->num_page_table_entries = 1ULL << (PAGE_TABLE_ADDRESS_SPACE_BITS - DYN_PAGE_BITS);
    backend->page_table = page_table;
    callbacks->num_page_table_entries = backend->num_page_table_entries;
    callbacks->page_table = backend->page_table;

    config.dczid_el0 = 4;
    config.ctr_el0 = 0x8444c004;
    config.cntfrq_el0 = 19200000;
    config.define_unpredictable_behaviour = true;
    config.page_table = nullptr;  // disable page table, use hash map only
    config.page_table_address_space_bits = PAGE_TABLE_ADDRESS_SPACE_BITS;
    config.absolute_offset_page_table = false;
    config.detect_misaligned_access_via_page_table = 0;
    config.only_detect_misalignment_via_page_table_on_page_boundary = true;
    config.fastmem_pointer = std::nullopt;
    config.recompile_on_exclusive_fastmem_failure = true;
    config.enable_cycle_counting = true;

    backend->cb64 = callbacks;
    backend->jit64 = new Dynarmic::A64::Jit(config);
    callbacks->cpu = backend->jit64;
    return backend;
}

FQL dynarmic* dynarmic_new_a32(u32 process_id, khash_t(memory) *memory, Dynarmic::ExclusiveMonitor *monitor, void **page_table, uint64_t jit_size, bool unsafe_optimizations, coprocessor_handler* handlers) {
    auto backend = (t_dynarmic) malloc(sizeof(struct dynarmic));
    memset(backend, 0, sizeof(struct dynarmic));
    backend->memory = memory;
    backend->monitor = monitor;
    backend->cb64 = nullptr;
    backend->jit64 = nullptr;
    auto *callbacks = new DynarmicCallbacks32(backend->memory);

    Dynarmic::A32::UserConfig config;
    config.callbacks = callbacks;
    config.processor_id = process_id;
    config.global_monitor = backend->monitor;
    config.wall_clock_cntpct = true;
    config.code_cache_size = jit_size;
    config.arch_version = Dynarmic::A32::ArchVersion::v7;

    if(unsafe_optimizations) {
        config.unsafe_optimizations = true;
        config.optimizations |= Dynarmic::OptimizationFlag::Unsafe_IgnoreGlobalMonitor;
        config.optimizations |= Dynarmic::OptimizationFlag::Unsafe_ReducedErrorFP;
    }

    backend->num_page_table_entries = 1ULL << (32 - DYN_PAGE_BITS);
    backend->page_table = page_table;
    callbacks->num_page_table_entries = backend->num_page_table_entries;
    callbacks->page_table = backend->page_table;

    config.define_unpredictable_behaviour = true;
    config.page_table = reinterpret_cast<std::array<std::uint8_t*, 1048576>*>(backend->page_table);
    config.absolute_offset_page_table = true;
    config.detect_misaligned_access_via_page_table = 0;
    config.only_detect_misalignment_via_page_table_on_page_boundary = true;
    config.fastmem_pointer = std::nullopt;
    config.recompile_on_exclusive_fastmem_failure = true;
    config.enable_cycle_counting = true;

    for (int i = 0; i < 16; i++) {
        auto cp = std::make_shared<RustCoprocessor>(i, callbacks);
        backend->coprocessors[i] = cp;
        if (handlers) { cp->SetHandler(handlers[i]); }
        config.coprocessors[i] = cp;
    }

    backend->cb32 = callbacks;
    backend->jit32 = new Dynarmic::A32::Jit(config);
    callbacks->cpu = backend->jit32;
    return backend;
}

FQL u64 dynarmic_get_cache_size(dynarmic* dynarmic) {
    if (dynarmic->jit64) return dynarmic->jit64->GetCacheSize();
    return 0;
}

FQL void dynarmic_destroy(dynarmic *dynarmic) {
    if (!dynarmic) return;
    khash_t(memory) *memory = dynarmic->memory;
    for (auto k = kh_begin(memory); k < kh_end(memory); k++) {
        if(kh_exist(memory, k)) {
            t_memory_page page = kh_value(memory, k);
            if (!page->is_external) { munmap(page->addr, DYN_PAGE_SIZE); }
            free(page);
        }
    }
    kh_destroy(memory, memory);
    if (dynarmic->jit64) delete dynarmic->jit64;
    if (dynarmic->cb64) delete dynarmic->cb64;
    if (dynarmic->jit32) delete dynarmic->jit32;
    if (dynarmic->cb32) delete dynarmic->cb32;
    delete dynarmic->monitor;
    free(dynarmic);
}

FQL void dynarmic_set_svc_callback(dynarmic *dynarmic, cb_call_svc cb, void* user_data) {
    if (dynarmic->cb64) { dynarmic->cb64->svc_callback = cb; dynarmic->cb64->svc_user_data = user_data; }
    if (dynarmic->cb32) { dynarmic->cb32->svc_callback = cb; dynarmic->cb32->svc_user_data = user_data; }
}

FQL void dynarmic_set_unmapped_mem_callback(dynarmic *dynarmic, cb_mem_hook cb, void* user_data) {
    if (dynarmic->cb64) { dynarmic->cb64->unmapped_mem_callback = cb; dynarmic->cb64->unmapped_mem_user_data = user_data; }
    if (dynarmic->cb32) { dynarmic->cb32->unmapped_mem_callback = cb; dynarmic->cb32->unmapped_mem_user_data = user_data; }
}

FQL int dynarmic_munmap(dynarmic* dynarmic, u64 address, u64 size) {
    khash_t(memory) *memory = dynarmic->memory;
    for(u64 vaddr = address; vaddr < address + size; vaddr += DYN_PAGE_SIZE) {
        u64 idx = vaddr >> DYN_PAGE_BITS;
        khiter_t k = kh_get(memory, memory, vaddr);
        if(k == kh_end(memory)) return 3;
        if(dynarmic->page_table && idx < (1ULL << (PAGE_TABLE_ADDRESS_SPACE_BITS - DYN_PAGE_BITS))) dynarmic->page_table[idx] = nullptr;
        t_memory_page page = kh_value(memory, k);
        if (!page->is_external) { munmap(page->addr, DYN_PAGE_SIZE); }
        free(page);
        kh_del(memory, memory, k);
    }
    return 0;
}

FQL int dynarmic_mmap(dynarmic* dynarmic, u64 address, u64 size, int perms) {
    khash_t(memory) *memory = dynarmic->memory;
    int ret;
    for(u64 vaddr = address; vaddr < address + size; vaddr += DYN_PAGE_SIZE) { if(kh_get(memory, memory, vaddr) != kh_end(memory)) return 4; }
    int prot = PROT_READ | PROT_WRITE;
    if (perms & 4) prot |= PROT_EXEC;
    void *block_addr = mmap(NULL, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(block_addr == MAP_FAILED) {
        fprintf(stderr, "[C] mmap FAILED: addr=0x%llx size=0x%llx errno=%d\n",
            (unsigned long long)address, (unsigned long long)size, errno);
        return 5;
    }
    madvise(block_addr, size, MADV_WILLNEED);
    char* current_ptr = (char*)block_addr;
    for(u64 vaddr = address; vaddr < address + size; vaddr += DYN_PAGE_SIZE) {
        u64 idx = vaddr >> DYN_PAGE_BITS;
        if(dynarmic->page_table && idx < (1ULL << (PAGE_TABLE_ADDRESS_SPACE_BITS - DYN_PAGE_BITS))) { dynarmic->page_table[idx] = (void*)((uintptr_t)current_ptr - vaddr); }
        khiter_t k = kh_put(memory, memory, vaddr, &ret);
        auto page = (t_memory_page) malloc(sizeof(struct memory_page));
        page->addr = current_ptr; page->perms = perms; page->is_external = false; kh_value(memory, k) = page;
        current_ptr += DYN_PAGE_SIZE;
    }
    return 0;
}

FQL int dynarmic_mem_map_ptr(dynarmic* dynarmic, u64 address, u64 size, int perms, void* ptr) {
    khash_t(memory) *memory = dynarmic->memory;
    int ret;
    char* current_ptr = (char*)ptr;
    for(u64 vaddr = address; vaddr < address + size; vaddr += DYN_PAGE_SIZE) { if(kh_get(memory, memory, vaddr) != kh_end(memory)) return 4; }
    for(u64 vaddr = address; vaddr < address + size; vaddr += DYN_PAGE_SIZE) {
        u64 idx = vaddr >> DYN_PAGE_BITS;
        if(dynarmic->page_table && idx < (1ULL << (PAGE_TABLE_ADDRESS_SPACE_BITS - DYN_PAGE_BITS))) { dynarmic->page_table[idx] = (void*)((uintptr_t)current_ptr - vaddr); }
        khiter_t k = kh_put(memory, memory, vaddr, &ret);
        auto page = (t_memory_page) malloc(sizeof(struct memory_page));
        page->addr = current_ptr; page->perms = perms; page->is_external = true; kh_value(memory, k) = page;
        current_ptr += DYN_PAGE_SIZE;
    }
    return 0;
}

FQL int dynarmic_mem_protect(dynarmic* dynarmic, u64 address, u64 size, int perms) {
    khash_t(memory) *memory = dynarmic->memory;
    for(u64 vaddr = address; vaddr < address + size; vaddr += DYN_PAGE_SIZE) {
        khiter_t k = kh_get(memory, memory, vaddr);
        if(k == kh_end(memory)) return 3;
        t_memory_page page = kh_value(memory, k);
        page->perms = perms;
        int prot = PROT_NONE;
        if (perms & 1) prot |= PROT_READ;
        if (perms & 2) prot |= PROT_WRITE;
        if (perms & 4) prot |= PROT_EXEC;
        mprotect(page->addr, DYN_PAGE_SIZE, prot);
    }
    return 0;
}

FQL int dynarmic_mem_write(dynarmic* dynarmic, u64 address, char* data, usize size) {
    khash_t(memory) *memory = dynarmic->memory;
    char *src = (char *)data;
    u64 vaddr_end = address + size;
    static int write_dbg = 0;
    for(u64 vaddr = address & ~DYN_PAGE_MASK; vaddr < vaddr_end; vaddr += DYN_PAGE_SIZE) {
        u64 start = vaddr < address ? address - vaddr : 0;
        u64 end = vaddr + DYN_PAGE_SIZE <= vaddr_end ? DYN_PAGE_SIZE : (vaddr_end - vaddr);
        u64 len = end - start;
        char *addr = get_memory_page(memory, vaddr, (1ULL << (PAGE_TABLE_ADDRESS_SPACE_BITS - DYN_PAGE_BITS)), dynarmic->page_table);
        if(addr == nullptr) {
            if(write_dbg < 3) {
                u64 base = vaddr & ~DYN_PAGE_MASK;
                u64 idx = vaddr >> DYN_PAGE_BITS;
                u64 max_idx = 1ULL << (PAGE_TABLE_ADDRESS_SPACE_BITS - DYN_PAGE_BITS);
                khiter_t k = kh_get(memory, memory, base);
                fprintf(stderr, "[C] mem_write fail: vaddr=0x%llx base=0x%llx idx=0x%llx max=0x%llx pt=%p kh=%s n_pages=%u\n",
                    (unsigned long long)vaddr, (unsigned long long)base,
                    (unsigned long long)idx, (unsigned long long)max_idx,
                    (void*)dynarmic->page_table,
                    k == kh_end(memory) ? "MISS" : "HIT",
                    kh_size(memory));
                write_dbg++;
            }
            return 1;
        }
        memcpy(&addr[start], src, len); src += len;
    }
    return 0;
}

FQL int dynarmic_mem_read(dynarmic* dynarmic, u64 address, char* bytes, usize size) {
    khash_t(memory) *memory = dynarmic->memory;
    u64 dest = 0;
    u64 vaddr_end = address + size;
    for(u64 vaddr = address & ~DYN_PAGE_MASK; vaddr < vaddr_end; vaddr += DYN_PAGE_SIZE) {
        u64 start = vaddr < address ? address - vaddr : 0;
        u64 end = vaddr + DYN_PAGE_SIZE <= vaddr_end ? DYN_PAGE_SIZE : (vaddr_end - vaddr);
        u64 len = end - start;
        char *addr = get_memory_page(memory, vaddr, (1ULL << (PAGE_TABLE_ADDRESS_SPACE_BITS - DYN_PAGE_BITS)), dynarmic->page_table);
        if(addr == nullptr) return 1;
        memcpy(&bytes[dest], &addr[start], len); dest += len;
    }
    return 0;
}

FQL u64 reg_read_pc(dynarmic* dynarmic) {
    if (dynarmic->jit64) return dynarmic->jit64->GetPC();
    if (dynarmic->jit32) { u32 pc = dynarmic->jit32->Regs()[15]; return (dynarmic->jit32->Cpsr() & 0x20) ? (u64)pc | 1 : (u64)pc; }
    return 0;
}
FQL int reg_write_pc(dynarmic* dynarmic, u64 value) {
    if (dynarmic->jit64) dynarmic->jit64->SetPC(value);
    if (dynarmic->jit32) {
        if (value & 1) { dynarmic->jit32->SetCpsr(dynarmic->jit32->Cpsr() | 0x20); dynarmic->jit32->Regs()[15] = (u32)(value & ~1ULL); }
        else { dynarmic->jit32->SetCpsr(dynarmic->jit32->Cpsr() & ~0x20); dynarmic->jit32->Regs()[15] = (u32)value; }
    }
    return 0;
}
FQL int reg_write_sp(dynarmic* dynarmic, u64 value) {
    if (dynarmic->jit64) dynarmic->jit64->SetSP(value);
    if (dynarmic->jit32) dynarmic->jit32->Regs()[13] = (u32)value;
    return 0;
}
FQL u64 reg_read_sp(dynarmic* dynarmic) {
    if (dynarmic->jit64) return dynarmic->jit64->GetSP();
    if (dynarmic->jit32) return dynarmic->jit32->Regs()[13];
    return 0;
}
FQL u64 reg_read_nzcv(dynarmic* dynarmic) {
    if (dynarmic->jit64) return dynarmic->jit64->GetPstate();
    if (dynarmic->jit32) return dynarmic->jit32->Cpsr();
    return 0;
}
FQL int reg_write_nzcv(dynarmic* dynarmic, u64 value) {
    if (dynarmic->jit64) dynarmic->jit64->SetPstate((u32)value);
    if (dynarmic->jit32) dynarmic->jit32->SetCpsr((u32)value);
    return 0;
}
FQL int reg_write_tpidr_el0(dynarmic* dynarmic, u64 value) { if (dynarmic->jit64) dynarmic->jit64->SetTPIDR_EL0(value); return 0; }
FQL u64 reg_read_tpidr_el0(dynarmic* dynarmic) { return dynarmic->jit64 ? dynarmic->jit64->GetTPIDR_EL0() : 0; }
FQL int reg_write_tpidrr0_el0(dynarmic* dynarmic, u64 value) { if (dynarmic->jit64) dynarmic->jit64->SetTPIDRRO_EL0(value); return 0; }

FQL int reg_write(dynarmic* d, u64 index, u64 value) { 
    if (d->jit64) {
        if (index < 31) d->jit64->SetRegister(index, value);
        else if (index == 31 || index == 410) d->jit64->SetSP(value);
        else if (index == 400) d->jit64->SetPC(value);
        else if (index == 402) { d->jit64->SetTPIDR_EL0(value); }
        else if (index == 403) { d->jit64->SetTPIDRRO_EL0(value); }
        else if (index == 66 || index == 405) { d->jit64->SetPstate((u32)value); }
    }
    if (d->jit32) {
        if (index >= 1 && index <= 15) d->jit32->Regs()[index-1] = (u32)value; 
        else if (index == 16) reg_write_pc(d, value); 
        else if (index == 17) d->jit32->SetCpsr((u32)value); 
        else if (index == 18) d->cb32->tpidruro = (u32)value;
        else if (index == 19) d->cb32->tpidrurw = (u32)value;
        else if (index == 21) d->jit32->SetFpscr((u32)value);
    }
    return 0; 
}
FQL u64 reg_read(dynarmic* d, u64 index) { 
    if (d->jit64) {
        if (index < 31) return d->jit64->GetRegister(index);
        if (index == 31 || index == 410) return d->jit64->GetSP();
        if (index == 400) return d->jit64->GetPC();
        if (index == 402) return d->jit64->GetTPIDR_EL0();
        if (index == 403) return d->tpidrro_el0_val;
        if (index == 66 || index == 405) return d->jit64->GetPstate();
    }
    if (d->jit32) {
        if (index >= 1 && index <= 15) return d->jit32->Regs()[index-1]; 
        if (index == 16) return reg_read_pc(d); 
        if (index == 17) return d->jit32->Cpsr(); 
        if (index == 18) return d->cb32->tpidruro;
        if (index == 19) return d->cb32->tpidrurw;
        if (index == 21) return d->jit32->Fpscr();
    }
    return 0; 
}

FQL int reg_write_r(dynarmic* d, u32 index, u32 value) { if (d->jit32 && index < 16) d->jit32->Regs()[index] = value; return 0; }
FQL u32 reg_read_r(dynarmic* d, u32 index) { return (d->jit32 && index < 16) ? d->jit32->Regs()[index] : 0; }
FQL int reg_write_cpsr(dynarmic* d, u32 value) { if (d->jit32) d->jit32->SetCpsr(value); return 0; }
FQL u32 reg_read_cpsr(dynarmic* d) { return d->jit32 ? d->jit32->Cpsr() : 0; }
FQL int reg_write_c13_c0_3(dynarmic* d, u32 value) { if (d->cb32) d->cb32->tpidruro = value; return 0; }
FQL u32 reg_read_c13_c0_3(dynarmic* d) { return d->cb32 ? d->cb32->tpidruro : 0; }

FQL void dynarmic_invalidate_cache(dynarmic* d, u64 addr, u64 size) {
    if (d->jit64) d->jit64->InvalidateCacheRange(addr, (size_t)size);
    if (d->jit32) d->jit32->InvalidateCacheRange((u32)addr, (size_t)size);
}

FQL int dynarmic_emu_start(dynarmic* d, u64 pc) {
    if (d->jit64) {
        // Reset tick counter and clear stale halt flags for each run
        if (d->cb64) d->cb64->ticks_remaining = 5000000000ULL;
        d->jit64->ClearHalt(Dynarmic::HaltReason::UserDefined1);
        d->jit64->ClearHalt(Dynarmic::HaltReason::UserDefined2);
        d->jit64->ClearHalt(Dynarmic::HaltReason::UserDefined3);
        d->jit64->ClearHalt(Dynarmic::HaltReason::UserDefined4);
        d->jit64->ClearHalt(Dynarmic::HaltReason::UserDefined5);
        d->jit64->ClearHalt(Dynarmic::HaltReason::UserDefined6);
        d->jit64->ClearHalt(Dynarmic::HaltReason::UserDefined7);
        d->jit64->ClearHalt(Dynarmic::HaltReason::UserDefined8);
        d->jit64->ClearHalt(Dynarmic::HaltReason::MemoryAbort);
        d->jit64->ClearHalt(Dynarmic::HaltReason::CacheInvalidation);
        d->jit64->SetPC(pc);
        d->jit64->Run();
    }
    if (d->jit32) { reg_write_pc(d, pc); d->jit32->Run(); }
    return 0;
}
FQL int dynarmic_emu_step(dynarmic* d, u64 pc) {
    if (d->jit64) {
        if (d->cb64) d->cb64->ticks_remaining = 1;
        d->jit64->ClearHalt(Dynarmic::HaltReason::UserDefined1);
        d->jit64->ClearHalt(Dynarmic::HaltReason::UserDefined2);
        d->jit64->ClearHalt(Dynarmic::HaltReason::MemoryAbort);
        d->jit64->ClearHalt(Dynarmic::HaltReason::CacheInvalidation);
        d->jit64->SetPC(pc);
        d->jit64->Step();
    }
    return 0;
}
FQL int dynarmic_emu_stop(dynarmic* d) { if (d->jit64) d->jit64->HaltExecution(); if (d->jit32) d->jit32->HaltExecution(); return 0; }

FQL t_context64 dynarmic_context_alloc() { return (t_context64) malloc(sizeof(struct context64)); } 
FQL void dynarmic_context_free(t_context64 context) { free(context); }
FQL int dynarmic_context_restore(dynarmic* d, t_context64 context) {
    if (!context || !d->jit64) return -1;
    d->jit64->SetRegisters(context->registers); d->jit64->SetSP(context->sp); d->jit64->SetPC(context->pc);
    d->jit64->SetPstate(context->pstate); d->jit64->SetVectors(context->vectors);
    d->jit64->SetFpcr(context->fpcr); d->jit64->SetFpsr(context->fpsr);
    d->jit64->SetTPIDR_EL0(context->tpidr_el0); d->jit64->SetTPIDRRO_EL0(context->tpidr_el0);
    return 0;
}
FQL int dynarmic_context_save(dynarmic* d, t_context64 context) {
    if (!context || !d->jit64) return -1;
    context->registers = d->jit64->GetRegisters(); context->sp = d->jit64->GetSP(); context->pc = d->jit64->GetPC();
    context->pstate = d->jit64->GetPstate(); context->vectors = d->jit64->GetVectors();
    context->fpcr = d->jit64->GetFpcr(); context->fpsr = d->jit64->GetFpsr();
    context->tpidr_el0 = d->jit64->GetTPIDR_EL0(); context->tpidrro_el0 = d->tpidrro_el0_val;
    return 0;
}

FQL t_context32 dynarmic_context32_alloc() { return (t_context32) malloc(sizeof(struct context32)); } 
FQL void dynarmic_context32_free(t_context32 context) { free(context); }
FQL int dynarmic_context32_restore(dynarmic* d, t_context32 context) {
    if (!context || !d->jit32) return -1;
    d->jit32->Regs() = context->registers; d->jit32->SetCpsr(context->cpsr);
    d->jit32->ExtRegs() = context->ext_regs; d->jit32->SetFpscr(context->fpscr);
    return 0;
}
FQL int dynarmic_context32_save(dynarmic* d, t_context32 context) {
    if (!context || !d->jit32) return -1;
    context->registers = d->jit32->Regs(); context->cpsr = d->jit32->Cpsr();
    context->ext_regs = d->jit32->ExtRegs(); context->fpscr = d->jit32->Fpscr();
    return 0;
}

} // extern "C"

#pragma clang diagnostic pop
#pragma clang diagnostic pop
