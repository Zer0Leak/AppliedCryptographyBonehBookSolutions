cmake_minimum_required(VERSION 3.22)

# ---------- (optional) force Clang: do this BEFORE project() ----------
if(NOT DEFINED CMAKE_C_COMPILER AND NOT DEFINED CMAKE_CXX_COMPILER)
  set(CMAKE_C_COMPILER clang)
  set(CMAKE_CXX_COMPILER clang++)
endif()

# ---------- single place to rename your target ----------
set(TARGET_NAME discrete_log)

project(${TARGET_NAME} LANGUAGES CXX)

# ===== Global defaults =====
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ===== Feature toggles =====
option(ENABLE_EIGEN           "Use Eigen3"                            OFF)
option(ENABLE_XTENSOR         "Use xtensor"                           OFF)
option(ENABLE_XTENSOR_BLAS    "Use xtensor-blas (requires BLAS)"      OFF)
option(ENABLE_BLAS_LAPACK     "Link BLAS/LAPACK"                      OFF)
option(ENABLE_BLAZE           "Use Blaze (header-only)"               OFF)
option(ENABLE_ARRAYFIRE       "Use ArrayFire (CPU/unified)"           OFF)
option(ENABLE_DLIB            "Use dlib via pkg-config"               OFF)
option(ENABLE_OPENMP          "Enable OpenMP for C++"                 OFF)
option(ENABLE_FMT             "Use fmt formatting library"            OFF)
option(ENABLE_CRYPTOPP        "Use Crypto++ cryptographic library"    OFF)
option(ENABLE_GMP             "Link GNU MP (C API)"                   ON)
option(ENABLE_GMPXX           "Link GNU MP C++ API"                   ON)

# ===== Target =====
add_executable(${TARGET_NAME}
  src/main.cpp
  src/second.cpp
)

target_compile_options(${TARGET_NAME} PRIVATE
  $<$<CONFIG:Debug>:-O0;-g3;-fno-omit-frame-pointer>
  $<$<CONFIG:Release>:-O3;-DNDEBUG;-march=native;-mtune=native>
  $<$<CONFIG:RelWithDebInfo>:-O3;-g;-DNDEBUG;-fno-omit-frame-pointer>
  $<$<CONFIG:MinSizeRel>:-Os;-DNDEBUG>
)

# Enable Link Time Optimization (IPO/LTO) for Release when supported
include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
if(ipo_supported)
  set_property(TARGET ${TARGET_NAME} PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
  # Also pass explicit -flto for compilers that honor it (GCC/Clang)
  target_link_options(${TARGET_NAME} PRIVATE $<$<CONFIG:Release>:-flto>)
else()
  message(STATUS "IPO/LTO not supported: ${ipo_error}")
endif()


if(UNIX AND NOT APPLE AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  find_program(MOLD_LINKER mold)
  if(MOLD_LINKER)
    target_link_options(${TARGET_NAME} PRIVATE -fuse-ld=mold)
    message(STATUS "Using mold linker")
  else()
    find_program(LLD_LINKER lld)
    if(LLD_LINKER)
      target_link_options(${TARGET_NAME} PRIVATE -fuse-ld=lld)
      message(STATUS "Using lld linker")
    else()
      message(STATUS "Using default linker")
    endif()
  endif()
endif()


target_include_directories(${TARGET_NAME} PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_target_properties(${TARGET_NAME} PROPERTIES
  CXX_STANDARD 23
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)

# ===== Warnings =====
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(${TARGET_NAME} PRIVATE -Wall -Wextra -Wpedantic)
endif()

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  # Only apply if Clang is older than version 19.0
  if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS "19.0")
    # lies to libstdc++ that clang fully support c++ 202002. I hope it is safe. I want std::expect
    message(STATUS "Patching Clang < 19 for libstdc++ std::expect compatibility")
    add_compile_options(-Wno-builtin-macro-redefined -D__cpp_concepts=202002L)
  endif()
endif()

# ===== Dependencies =====

# fmt
if(ENABLE_FMT)
  find_package(fmt REQUIRED)
  target_link_libraries(${TARGET_NAME} PRIVATE fmt::fmt)
endif()

# Crypto++
if(ENABLE_CRYPTOPP)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(CRYPTOPP REQUIRED libcrypto++)
  target_link_libraries(${TARGET_NAME} PRIVATE ${CRYPTOPP_LIBRARIES})
  target_include_directories(${TARGET_NAME} PRIVATE ${CRYPTOPP_INCLUDE_DIRS})
  target_compile_definitions(${TARGET_NAME} PRIVATE ${CRYPTOPP_CFLAGS_OTHER})
endif()

# GMP / GMPXX (Ubuntu packages ship pkg-config files)
if(ENABLE_GMP OR ENABLE_GMPXX)
  find_package(PkgConfig REQUIRED)

  if(ENABLE_GMP)
    pkg_check_modules(GMP REQUIRED IMPORTED_TARGET gmp)
    target_link_libraries(${TARGET_NAME} PRIVATE PkgConfig::GMP)
  endif()

  if(ENABLE_GMPXX)
    pkg_check_modules(GMPXX REQUIRED IMPORTED_TARGET gmpxx)
    target_link_libraries(${TARGET_NAME} PRIVATE PkgConfig::GMPXX)
  endif()
endif()

# Eigen
if(ENABLE_EIGEN)
  find_package(Eigen3 3.4 REQUIRED NO_MODULE)
  target_link_libraries(${TARGET_NAME} PRIVATE Eigen3::Eigen)
endif()

# BLAS / LAPACK
if(ENABLE_BLAS_LAPACK)
  find_package(BLAS REQUIRED)
  find_package(LAPACK REQUIRED)
  target_link_libraries(${TARGET_NAME} PRIVATE BLAS::BLAS LAPACK::LAPACK)
endif()

# xtensor + xtensor-blas
if(ENABLE_XTENSOR)
  find_package(xtensor REQUIRED)
  target_link_libraries(${TARGET_NAME} PRIVATE xtensor)
endif()

if(ENABLE_XTENSOR_BLAS)
  find_package(xtensor-blas REQUIRED)
  target_link_libraries(${TARGET_NAME} PRIVATE xtensor-blas)
  if(ENABLE_BLAS_LAPACK)
    target_compile_definitions(${TARGET_NAME} PRIVATE HAVE_CBLAS=1)
  endif()
endif()

# Blaze (header-only)
if(ENABLE_BLAZE)
  include(FetchContent)
  FetchContent_Declare(
    blaze
    GIT_REPOSITORY https://bitbucket.org/blaze-lib/blaze.git
    GIT_TAG        v3.8.2
  )
  FetchContent_MakeAvailable(blaze)
  add_library(Blaze::Blaze INTERFACE IMPORTED)
  set_target_properties(Blaze::Blaze PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${blaze_SOURCE_DIR}"
  )
  target_link_libraries(${TARGET_NAME} PRIVATE Blaze::Blaze)
  if(ENABLE_BLAS_LAPACK)
    target_compile_definitions(${TARGET_NAME} PRIVATE BLAZE_BLAS_MODE=1)
  endif()
endif()

# ArrayFire
if(ENABLE_ARRAYFIRE)
  find_package(ArrayFire REQUIRED)
  if(TARGET ArrayFire::afcpu)
    set(AF_TARGET ArrayFire::afcpu)
  elseif(TARGET afcpu)
    set(AF_TARGET afcpu)
  elseif(TARGET ArrayFire::af)
    set(AF_TARGET ArrayFire::af)
  elseif(TARGET af)
    set(AF_TARGET af)
  elseif(DEFINED ArrayFire_CPU_LIBRARIES)
    add_library(AF_CPU_LEGACY INTERFACE)
    target_link_libraries(AF_CPU_LEGACY INTERFACE ${ArrayFire_CPU_LIBRARIES})
    target_include_directories(AF_CPU_LEGACY INTERFACE ${ArrayFire_INCLUDE_DIRS})
    set(AF_TARGET AF_CPU_LEGACY)
  else()
    message(FATAL_ERROR "ArrayFire found but no usable target detected.")
  endif()
  target_link_libraries(${TARGET_NAME} PRIVATE ${AF_TARGET})
endif()

# dlib
if(ENABLE_DLIB)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(dlib REQUIRED dlib-1)
  target_link_libraries(${TARGET_NAME} PRIVATE ${dlib_LIBRARIES})
  target_include_directories(${TARGET_NAME} PRIVATE ${dlib_INCLUDE_DIRS})
endif()

# OpenMP
if(ENABLE_OPENMP)
  find_package(OpenMP REQUIRED)
  target_link_libraries(${TARGET_NAME} PRIVATE OpenMP::OpenMP_CXX)
endif()

# ===== Post-build: create/update symbolic link to the latest build =====
add_custom_command(
    TARGET ${TARGET_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Updating 'Active' symlink → ${CMAKE_BUILD_TYPE}"
    COMMAND ${CMAKE_COMMAND} -E remove -f "${CMAKE_BINARY_DIR}/../Active"
    COMMAND ${CMAKE_COMMAND} -E create_symlink "${CMAKE_BINARY_DIR}" "${CMAKE_BINARY_DIR}/../Active"
)

# ===== Usage hint =====
#
# cmake --preset ram-debug  -DENABLE_ARRAYFIRE=OFF
# cmake --preset ram-release -DENABLE_DLIB=ON
#
# export BUILD_FOLDER=/mnt/ram/DiscreteLog/build  # to build in RAM FS
#
# For Debug
# cmake -S . -B "$BUILD_FOLDER/Debug" -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
# cmake --build "$BUILD_FOLDER/Debug"
#
# For Release
# cmake -S . -B "${BUILD_FOLDER}/Release" -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release
# cmake --build "${BUILD_FOLDER}/Release"
#
# Or use Presets (defined in CMakePresets.json):
#
# Debug
# cmake --preset ram-debug
# cmake --build --preset build-ram-debug
#
# Release
# cmake --preset ram-release
# cmake --build --preset build-ram-release
