cmake_minimum_required(VERSION 3.10) # 指定最低的CMake版本要求

# 项目名称和语言
project(IPv6Router LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找TinyXML-2库
find_package(tinyxml2 REQUIRED)

# 指定头文件搜索路径
include_directories(include)

# 定义一个可执行文件，其源文件为 src 目录下的 Router.cpp
add_executable(IPv6Router src/Router.cpp)


file(READ "${PROJECT_SOURCE_DIR}/src/routing_table.xml" xml_content)

# 打印XML文件内容
message(STATUS "XML content:\n${xml_content}")
# 如果需要链接其他库，可以使用target_link_libraries
target_link_libraries(IPv6Router PRIVATE tinyxml2::tinyxml2)
# target_link_libraries(IPv6Router PRIVATE some_library)