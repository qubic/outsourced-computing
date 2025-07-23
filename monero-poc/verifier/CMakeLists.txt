cmake_minimum_required(VERSION 3.1)
project(OCVerifier CXX)
# Find GCC compiler
find_program(GCC_COMPILER NAMES gcc g++
		DOC "Path to the GNU C/C++ compiler")

if(NOT GCC_COMPILER)
	message(FATAL_ERROR "GCC/G++ compiler not found. Please install GCC or ensure it's in your PATH.")
endif()

set (CMAKE_CXX_STANDARD 17)
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
	SET(CXX_OCVERIFIER_FLAGS "-Wunused-variable")
endif()

message(STATUS "Using C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Using C++ compiler: ${CMAKE_CXX_COMPILER}")

if(CMAKE_C_COMPILER MATCHES "gcc")
	#ok
else()
	message(FATAL_ERROR "Must use gcc/g++ to compile")
endif()
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${CXX_OCVERIFIER_FLAGS}")
SET(FILES ${CMAKE_SOURCE_DIR}/connection.cpp
		${CMAKE_SOURCE_DIR}/keyUtils.cpp
)
add_subdirectory(RandomX)
ADD_EXECUTABLE(oc_verifier main.cpp ${FILES})
target_link_libraries(oc_verifier pthread randomx lmdb)
set_property(TARGET oc_verifier PROPERTY COMPILE_WARNING_AS_ERROR ON)
