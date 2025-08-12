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

set(XMR_ROOT "/root/monero/" CACHE PATH "Monero root folder")
message(STATUS "This project requires monero header files to compile")
message(STATUS "Setting XMR_ROOT at: " ${XMR_ROOT})
include_directories(${XMR_ROOT}/src/)
include_directories(${XMR_ROOT}/external/)
include_directories(${XMR_ROOT}/external/easylogging++/)
include_directories(${XMR_ROOT}/contrib/epee/include/)

message(WARNING "This project is using many precompiled libraries, it is recommended to use your own library version")

SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${CXX_OCVERIFIER_FLAGS}")
SET(FILES ${CMAKE_SOURCE_DIR}/connection.cpp
		${CMAKE_SOURCE_DIR}/keyUtils.cpp
)
link_directories(${CMAKE_SOURCE_DIR}/precompiledMoneroLibraries/)
add_library(oc_verifier_lib STATIC verifierLib.cpp xmr.cpp)
ADD_EXECUTABLE(oc_verifier main.cpp ${FILES})

target_link_libraries(oc_verifier pthread lmdb oc_verifier_lib cryptonote_basic cncrypto common ringct_basic device
		cryptonote_format_utils_basic wallet-crypto epee easylogging version randomx boost_system boost_date_time
		boost_chrono boost_filesystem boost_thread boost_regex boost_serialization boost_program_options sodium
		unbound ssl crypto hidapi-libusb dl)
target_link_libraries(oc_verifier_lib cryptonote_basic cncrypto common ringct_basic device
		cryptonote_format_utils_basic wallet-crypto epee easylogging version randomx boost_system boost_date_time
		boost_chrono boost_filesystem boost_thread boost_regex boost_serialization boost_program_options sodium
		unbound ssl crypto hidapi-libusb dl)
target_compile_options(oc_verifier_lib PRIVATE -Ofast)
set_property(TARGET oc_verifier PROPERTY COMPILE_WARNING_AS_ERROR ON)
