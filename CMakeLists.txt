cmake_minimum_required(VERSION 3.10)
project(MultimodalAuthAPI VERSION 1.0)

# 要求支持到 C++20 因为代码用到了一些类似 std::span 的新特性
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 指定项目根目录作为头文件查找基础路径，使得所有子算法能用 #include "ascon/..." 找到
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# ====================================================
# 第一部分：对外提供静态库 (.a) 与 动态链接库 (.so / .dll)
# ====================================================

# 1. 编译核心通用静态库 libMultimodalAuth.a 
add_library(Auth_STATIC STATIC 
    auth_api.cpp 
    key_vault.cpp
    libauth.cpp
)
# 输出文件改名为干净的名称
set_target_properties(Auth_STATIC PROPERTIES OUTPUT_NAME "MultimodalAuth")

# 2. 编译核心通用动态库 libMultimodalAuth.so
add_library(Auth_SHARED SHARED 
    auth_api.cpp 
    key_vault.cpp
    libauth.cpp
)
set_target_properties(Auth_SHARED PROPERTIES OUTPUT_NAME "MultimodalAuth")
add_custom_command(TARGET Auth_SHARED POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:Auth_SHARED> ${CMAKE_CURRENT_SOURCE_DIR}/libauth.so
    COMMENT "Copy shared library to ./libauth.so for Python ctypes client")

# ====================================================
# 第二部分：编译我们的极简测试演示程序以证明库能够正常工作
# ====================================================

add_executable(test_api example_usage.cpp)

# 将刚刚编译的静态库链接到测试程序中去
target_link_libraries(test_api PRIVATE Auth_STATIC)
