cmake_minimum_required(VERSION 3.12)
project(dynarmic LANGUAGES C CXX ASM VERSION 10.1.0)

set(MASTER_PROJECT OFF)
if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(MASTER_PROJECT ON)
endif()

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 OLD)
endif()

option(DYNARMIC_ENABLE_CPU_FEATURE_DETECTION "Turning this off causes dynarmic to assume the host CPU doesn't support anything later than SSE3" ON)
option(DYNARMIC_ENABLE_NO_EXECUTE_SUPPORT "Enables support for systems that require W^X" OFF)
option(DYNARMIC_DEBUG "Debug mode" OFF)
option(DYNARMIC_FATAL_ERRORS "Errors are fatal" OFF)
option(DYNARMIC_IGNORE_ASSERTS "Ignore asserts" OFF)
option(DYNARMIC_TESTS "Build tests" OFF)
option(DYNARMIC_USE_LLVM "Support disassembly of jitted x86_64 code using LLVM" OFF)
option(DYNARMIC_USE_PRECOMPILED_HEADERS "Use precompiled headers" OFF)
option(DYNARMIC_USE_BUNDLED_EXTERNALS "Use all bundled externals" ON)

if (NOT DEFINED DYNARMIC_FRONTENDS)
    set(DYNARMIC_FRONTENDS "A32;A64" CACHE STRING "")
endif()

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(DYNARMIC_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dynarmic")

# Add the module directory to the list of paths
list(APPEND CMAKE_MODULE_PATH "${DYNARMIC_SOURCE_DIR}/CMakeModules")

if (MSVC)
    set(DYNARMIC_CXX_FLAGS /experimental:external /external:W0 /external:anglebrackets /W4 /MP /Zi /Zo /EHsc /Zc:externConstexpr /Zc:inline /Zc:throwingNew /volatile:iso /bigobj /DNOMINMAX)
else()
    set(DYNARMIC_CXX_FLAGS -Wall -Wextra -Wcast-qual -pedantic -Wno-missing-braces -O3)
endif()

include(DetectArchitecture)
message(STATUS "Target architecture: ${ARCHITECTURE}")

# Link static helper
include("${DYNARMIC_SOURCE_DIR}/cmake/bundle_static.cmake")

find_package(Boost 1.57 REQUIRED)
if (NOT DYNARMIC_USE_BUNDLED_EXTERNALS)
    find_package(fmt 9 CONFIG)
    find_package(mcl 0.1.12 EXACT CONFIG)
endif()
find_package(tsl-robin-map CONFIG)

if ("arm64" IN_LIST ARCHITECTURE OR DYNARMIC_TESTS)
    find_package(oaknut 2.0.1 CONFIG)
endif()
if ("x86_64" IN_LIST ARCHITECTURE)
    find_package(xbyak 7 CONFIG)
    find_package(Zydis 4 CONFIG)
endif()

# Externals are in vendor/dynarmic/externals
add_subdirectory("${DYNARMIC_SOURCE_DIR}/externals")

# Architecture specific sources
include(TargetArchitectureSpecificSources)

# The C++ source files
add_library(dynarmic STATIC
    "${DYNARMIC_SOURCE_DIR}/dynarmic.cpp"
    "${DYNARMIC_SOURCE_DIR}/dynarmic.h"
    "${DYNARMIC_SOURCE_DIR}/khash.h"
    "${DYNARMIC_SOURCE_DIR}/backend/block_range_information.cpp"
    "${DYNARMIC_SOURCE_DIR}/backend/block_range_information.h"
    "${DYNARMIC_SOURCE_DIR}/backend/exception_handler.h"
    "${DYNARMIC_SOURCE_DIR}/common/always_false.h"
    "${DYNARMIC_SOURCE_DIR}/common/cast_util.h"
    "${DYNARMIC_SOURCE_DIR}/common/crypto/aes.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/crypto/aes.h"
    "${DYNARMIC_SOURCE_DIR}/common/crypto/crc32.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/crypto/crc32.h"
    "${DYNARMIC_SOURCE_DIR}/common/crypto/sm4.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/crypto/sm4.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/fpcr.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/fpsr.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/fused.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/fused.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/info.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/mantissa_util.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPCompare.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPCompare.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPConvert.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPConvert.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPMulAdd.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPMulAdd.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPNeg.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPRecipEstimate.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPRecipEstimate.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPRecipExponent.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPRecipExponent.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPRecipStepFused.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPRecipStepFused.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPRoundInt.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPRoundInt.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPRSqrtEstimate.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPRSqrtEstimate.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPRSqrtStepFused.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPRSqrtStepFused.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPToFixed.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/op/FPToFixed.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/process_exception.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/process_exception.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/process_nan.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/process_nan.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/rounding_mode.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/unpacked.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/fp/unpacked.h"
    "${DYNARMIC_SOURCE_DIR}/common/fp/util.h"
    "${DYNARMIC_SOURCE_DIR}/common/llvm_disassemble.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/llvm_disassemble.h"
    "${DYNARMIC_SOURCE_DIR}/common/lut_from_list.h"
    "${DYNARMIC_SOURCE_DIR}/common/math_util.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/math_util.h"
    "${DYNARMIC_SOURCE_DIR}/common/memory_pool.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/memory_pool.h"
    "${DYNARMIC_SOURCE_DIR}/common/safe_ops.h"
    "${DYNARMIC_SOURCE_DIR}/common/spin_lock.h"
    "${DYNARMIC_SOURCE_DIR}/common/string_util.h"
    "${DYNARMIC_SOURCE_DIR}/common/u128.cpp"
    "${DYNARMIC_SOURCE_DIR}/common/u128.h"
    "${DYNARMIC_SOURCE_DIR}/common/variant_util.h"
    "${DYNARMIC_SOURCE_DIR}/frontend/A32/a32_types.cpp"
    "${DYNARMIC_SOURCE_DIR}/frontend/A32/a32_types.h"
    "${DYNARMIC_SOURCE_DIR}/frontend/A64/a64_types.cpp"
    "${DYNARMIC_SOURCE_DIR}/frontend/A64/a64_types.h"
    "${DYNARMIC_SOURCE_DIR}/frontend/decoder/decoder_detail.h"
    "${DYNARMIC_SOURCE_DIR}/frontend/decoder/matcher.h"
    "${DYNARMIC_SOURCE_DIR}/frontend/imm.cpp"
    "${DYNARMIC_SOURCE_DIR}/frontend/imm.h"
    "${DYNARMIC_SOURCE_DIR}/interface/exclusive_monitor.h"
    "${DYNARMIC_SOURCE_DIR}/interface/optimization_flags.h"
    "${DYNARMIC_SOURCE_DIR}/ir/acc_type.h"
    "${DYNARMIC_SOURCE_DIR}/ir/basic_block.cpp"
    "${DYNARMIC_SOURCE_DIR}/ir/basic_block.h"
    "${DYNARMIC_SOURCE_DIR}/ir/cond.h"
    "${DYNARMIC_SOURCE_DIR}/ir/ir_emitter.cpp"
    "${DYNARMIC_SOURCE_DIR}/ir/ir_emitter.h"
    "${DYNARMIC_SOURCE_DIR}/ir/location_descriptor.cpp"
    "${DYNARMIC_SOURCE_DIR}/ir/location_descriptor.h"
    "${DYNARMIC_SOURCE_DIR}/ir/microinstruction.cpp"
    "${DYNARMIC_SOURCE_DIR}/ir/microinstruction.h"
    "${DYNARMIC_SOURCE_DIR}/ir/opcodes.cpp"
    "${DYNARMIC_SOURCE_DIR}/ir/opcodes.h"
    "${DYNARMIC_SOURCE_DIR}/ir/opcodes.inc"
    "${DYNARMIC_SOURCE_DIR}/ir/opt/constant_propagation_pass.cpp"
    "${DYNARMIC_SOURCE_DIR}/ir/opt/dead_code_elimination_pass.cpp"
    "${DYNARMIC_SOURCE_DIR}/ir/opt/identity_removal_pass.cpp"
    "${DYNARMIC_SOURCE_DIR}/ir/opt/ir_matcher.h"
    "${DYNARMIC_SOURCE_DIR}/ir/opt/naming_pass.cpp"
    "${DYNARMIC_SOURCE_DIR}/ir/opt/passes.h"
    "${DYNARMIC_SOURCE_DIR}/ir/opt/polyfill_pass.cpp"
    "${DYNARMIC_SOURCE_DIR}/ir/opt/verification_pass.cpp"
    "${DYNARMIC_SOURCE_DIR}/ir/terminal.h"
    "${DYNARMIC_SOURCE_DIR}/ir/type.cpp"
    "${DYNARMIC_SOURCE_DIR}/ir/type.h"
    "${DYNARMIC_SOURCE_DIR}/ir/value.cpp"
    "${DYNARMIC_SOURCE_DIR}/ir/value.h"
)

if (WIN32)
    target_sources(dynarmic PRIVATE "${DYNARMIC_SOURCE_DIR}/mman.c" "${DYNARMIC_SOURCE_DIR}/mman.h")
endif()

if ("A32" IN_LIST DYNARMIC_FRONTENDS)
    target_sources(dynarmic PRIVATE
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/a32_ir_emitter.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/a32_ir_emitter.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/a32_location_descriptor.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/a32_location_descriptor.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/decoder/arm.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/decoder/arm.inc"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/decoder/asimd.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/decoder/asimd.inc"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/decoder/thumb16.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/decoder/thumb16.inc"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/decoder/thumb32.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/decoder/thumb32.inc"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/decoder/vfp.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/decoder/vfp.inc"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/disassembler/disassembler.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/disassembler/disassembler_arm.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/disassembler/disassembler_thumb.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/FPSCR.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/ITState.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/PSR.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/a32_translate.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/a32_translate.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/conditional_state.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/conditional_state.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/a32_branch.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/a32_crc32.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/a32_exception_generating.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/a32_translate_impl.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/a32_translate_impl.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/asimd_load_store_structures.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/asimd_misc.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/asimd_one_reg_modified_immediate.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/asimd_three_regs.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/asimd_two_regs_misc.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/asimd_two_regs_scalar.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/asimd_two_regs_shift.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/barrier.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/coprocessor.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/data_processing.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/divide.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/extension.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/hint.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/load_store.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/misc.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/multiply.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/packing.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/parallel.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/reversal.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/saturated.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/status_register_access.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/synchronization.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb16.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_branch.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_control.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_coprocessor.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_data_processing_modified_immediate.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_data_processing_plain_binary_immediate.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_data_processing_register.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_data_processing_shifted_register.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_load_byte.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_load_halfword.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_load_store_dual.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_load_store_multiple.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_load_word.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_long_multiply.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_misc.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_multiply.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_parallel.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/thumb32_store_single_data_item.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/impl/vfp.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/translate_arm.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A32/translate/translate_thumb.cpp"
        "${DYNARMIC_SOURCE_DIR}/interface/A32/a32.h"
        "${DYNARMIC_SOURCE_DIR}/interface/A32/arch_version.h"
        "${DYNARMIC_SOURCE_DIR}/interface/A32/config.h"
        "${DYNARMIC_SOURCE_DIR}/interface/A32/coprocessor.h"
        "${DYNARMIC_SOURCE_DIR}/interface/A32/coprocessor_util.h"
        "${DYNARMIC_SOURCE_DIR}/interface/A32/disassembler.h"
        "${DYNARMIC_SOURCE_DIR}/ir/opt/a32_constant_memory_reads_pass.cpp"
        "${DYNARMIC_SOURCE_DIR}/ir/opt/a32_get_set_elimination_pass.cpp"
    )
endif()

if ("A64" IN_LIST DYNARMIC_FRONTENDS)
    target_sources(dynarmic PRIVATE
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/a64_ir_emitter.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/a64_ir_emitter.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/a64_location_descriptor.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/a64_location_descriptor.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/decoder/a64.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/decoder/a64.inc"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/a64_translate.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/a64_translate.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/a64_branch.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/a64_exception_generating.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/data_processing_addsub.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/data_processing_bitfield.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/data_processing_conditional_compare.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/data_processing_conditional_select.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/data_processing_crc32.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/data_processing_logical.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/data_processing_multiply.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/data_processing_pcrel.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/data_processing_register.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/data_processing_shift.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/floating_point_compare.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/floating_point_conditional_compare.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/floating_point_conditional_select.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/floating_point_conversion_fixed_point.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/floating_point_conversion_integer.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/floating_point_data_processing_one_register.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/floating_point_data_processing_three_register.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/floating_point_data_processing_two_register.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/impl.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/impl.h"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/load_store_exclusive.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/load_store_load_literal.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/load_store_multiple_structures.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/load_store_no_allocate_pair.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/load_store_register_immediate.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/load_store_register_pair.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/load_store_register_register_offset.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/load_store_register_unprivileged.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/load_store_single_structure.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/move_wide.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_across_lanes.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_aes.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_copy.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_crypto_four_register.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_crypto_three_register.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_extract.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_modified_immediate.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_permute.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_scalar_pairwise.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_scalar_shift_by_immediate.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_scalar_three_same.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_scalar_two_register_misc.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_scalar_x_indexed_element.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_sha.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_sha512.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_shift_by_immediate.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_table_lookup.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_three_different.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_three_same.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_three_same_extra.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_two_register_misc.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/simd_vector_x_indexed_element.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/sys_dc.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/sys_ic.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/system.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/system_flag_format.cpp"
        "${DYNARMIC_SOURCE_DIR}/frontend/A64/translate/impl/system_flag_manipulation.cpp"
        "${DYNARMIC_SOURCE_DIR}/interface/A64/a64.h"
        "${DYNARMIC_SOURCE_DIR}/interface/A64/config.h"
        "${DYNARMIC_SOURCE_DIR}/ir/opt/a64_callback_config_pass.cpp"
        "${DYNARMIC_SOURCE_DIR}/ir/opt/a64_get_set_elimination_pass.cpp"
        "${DYNARMIC_SOURCE_DIR}/ir/opt/a64_merge_interpret_blocks.cpp"
    )
endif()

if ("x86_64" IN_LIST ARCHITECTURE)
    target_link_libraries(dynarmic PRIVATE xbyak::xbyak Zydis::Zydis)
    target_architecture_specific_sources(dynarmic "x86_64"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/abi.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/abi.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/block_of_code.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/block_of_code.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/callback.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/callback.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/constant_pool.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/constant_pool.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/constants.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/devirtualize.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64_aes.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64_crc32.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64_data_processing.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64_floating_point.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64_memory.cpp.inc"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64_memory.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64_packed.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64_saturation.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64_sha.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64_sm4.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64_vector.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64_vector_floating_point.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/emit_x64_vector_saturation.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/exclusive_monitor.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/exclusive_monitor_friend.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/host_feature.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/hostloc.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/hostloc.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/jitstate_info.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/oparg.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/perf_map.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/perf_map.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/reg_alloc.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/reg_alloc.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/stack_layout.h"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/verbose_debugging_output.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/x64/verbose_debugging_output.h"
        "${DYNARMIC_SOURCE_DIR}/common/spin_lock_x64.cpp"
        "${DYNARMIC_SOURCE_DIR}/common/spin_lock_x64.h"
        "${DYNARMIC_SOURCE_DIR}/common/x64_disassemble.cpp"
        "${DYNARMIC_SOURCE_DIR}/common/x64_disassemble.h"
    )
    if ("A32" IN_LIST DYNARMIC_FRONTENDS)
        target_architecture_specific_sources(dynarmic "x86_64"
            "${DYNARMIC_SOURCE_DIR}/backend/x64/a32_emit_x64.cpp"
            "${DYNARMIC_SOURCE_DIR}/backend/x64/a32_emit_x64.h"
            "${DYNARMIC_SOURCE_DIR}/backend/x64/a32_emit_x64_memory.cpp"
            "${DYNARMIC_SOURCE_DIR}/backend/x64/a32_interface.cpp"
            "${DYNARMIC_SOURCE_DIR}/backend/x64/a32_jitstate.cpp"
            "${DYNARMIC_SOURCE_DIR}/backend/x64/a32_jitstate.h"
        )
    endif()
    if ("A64" IN_LIST DYNARMIC_FRONTENDS)
        target_architecture_specific_sources(dynarmic "x86_64"
            "${DYNARMIC_SOURCE_DIR}/backend/x64/a64_emit_x64.cpp"
            "${DYNARMIC_SOURCE_DIR}/backend/x64/a64_emit_x64.h"
            "${DYNARMIC_SOURCE_DIR}/backend/x64/a64_emit_x64_memory.cpp"
            "${DYNARMIC_SOURCE_DIR}/backend/x64/a64_interface.cpp"
            "${DYNARMIC_SOURCE_DIR}/backend/x64/a64_jitstate.cpp"
            "${DYNARMIC_SOURCE_DIR}/backend/x64/a64_jitstate.h"
        )
    endif()
endif()

if ("arm64" IN_LIST ARCHITECTURE)
    target_link_libraries(dynarmic PRIVATE merry::oaknut)
    target_architecture_specific_sources(dynarmic "arm64"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/a32_jitstate.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/a32_jitstate.h"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/a64_jitstate.h"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/abi.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/abi.h"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/address_space.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/address_space.h"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/devirtualize.h"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64.h"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_a32.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_a32_coprocessor.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_a32_memory.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_a64.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_a64_memory.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_cryptography.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_data_processing.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_floating_point.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_memory.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_memory.h"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_packed.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_saturation.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_vector.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_vector_floating_point.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_arm64_vector_saturation.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/emit_context.h"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/exclusive_monitor.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/fastmem.h"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/fpsr_manager.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/fpsr_manager.h"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/reg_alloc.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/reg_alloc.h"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/stack_layout.h"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/verbose_debugging_output.cpp"
        "${DYNARMIC_SOURCE_DIR}/backend/arm64/verbose_debugging_output.h"
        "${DYNARMIC_SOURCE_DIR}/common/spin_lock_arm64.cpp"
        "${DYNARMIC_SOURCE_DIR}/common/spin_lock_arm64.h"
    )
    if ("A32" IN_LIST DYNARMIC_FRONTENDS)
        target_architecture_specific_sources(dynarmic "arm64"
            "${DYNARMIC_SOURCE_DIR}/backend/arm64/a32_address_space.cpp"
            "${DYNARMIC_SOURCE_DIR}/backend/arm64/a32_address_space.h"
            "${DYNARMIC_SOURCE_DIR}/backend/arm64/a32_core.h"
            "${DYNARMIC_SOURCE_DIR}/backend/arm64/a32_interface.cpp"
        )
    endif()
    if ("A64" IN_LIST DYNARMIC_FRONTENDS)
        target_architecture_specific_sources(dynarmic "arm64"
            "${DYNARMIC_SOURCE_DIR}/backend/arm64/a64_address_space.cpp"
            "${DYNARMIC_SOURCE_DIR}/backend/arm64/a64_address_space.h"
            "${DYNARMIC_SOURCE_DIR}/backend/arm64/a64_core.h"
            "${DYNARMIC_SOURCE_DIR}/backend/arm64/a64_interface.cpp"
        )
    endif()
endif()

if (WIN32)
    target_sources(dynarmic PRIVATE "${DYNARMIC_SOURCE_DIR}/backend/exception_handler_windows.cpp")
elseif (APPLE)
    target_sources(dynarmic PRIVATE "${DYNARMIC_SOURCE_DIR}/backend/exception_handler_macos.cpp")
elseif (UNIX)
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_libraries(dynarmic PRIVATE rt)
    endif()
    target_sources(dynarmic PRIVATE "${DYNARMIC_SOURCE_DIR}/backend/exception_handler_posix.cpp")
else()
    target_sources(dynarmic PRIVATE "${DYNARMIC_SOURCE_DIR}/backend/exception_handler_generic.cpp")
endif()

# Important: Use the current vendor dir as root for includes
target_include_directories(dynarmic PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(dynarmic PRIVATE ${DYNARMIC_CXX_FLAGS})
target_link_libraries(dynarmic PRIVATE Boost::boost fmt::fmt merry::mcl tsl::robin_map)

if (DYNARMIC_ENABLE_CPU_FEATURE_DETECTION)
    target_compile_definitions(dynarmic PRIVATE DYNARMIC_ENABLE_CPU_FEATURE_DETECTION=1)
endif()
if (DYNARMIC_ENABLE_NO_EXECUTE_SUPPORT)
    target_compile_definitions(dynarmic PRIVATE DYNARMIC_ENABLE_NO_EXECUTE_SUPPORT=1)
endif()
if (DYNARMIC_IGNORE_ASSERTS)
    target_compile_definitions(dynarmic PRIVATE MCL_IGNORE_ASSERTS=1)
endif()
target_compile_definitions(dynarmic PRIVATE FMT_USE_USER_DEFINED_LITERALS=1)
