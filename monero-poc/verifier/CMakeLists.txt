cmake_minimum_required(VERSION 3.1)
project(OCVerifier CXX)
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    message(STATUS "Detected GCC/G++ compiler")
    set(CXX_OCVERIFIER_FLAGS "-Wunused-variable")
else()
    message(FATAL_ERROR "Must use GCC/G++ to compile")
endif()

message(STATUS "Using C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Using C++ compiler: ${CMAKE_CXX_COMPILER}")

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

if (BOOST_ROOT)
	message(STATUS "Look for Boost at: " ${BOOST_ROOT})
else()
	message(STATUS "Look for Boost at default path")
endif()

# This verion is required for precompiled libraries
find_package(Boost 1.71 EXACT REQUIRED COMPONENTS
    filesystem system date_time chrono thread regex serialization program_options
)

target_link_libraries(oc_verifier PRIVATE 
		pthread lmdb oc_verifier_lib)
target_link_libraries(oc_verifier_lib PRIVATE
		cryptonote_basic cncrypto common ringct_basic device cryptonote_format_utils_basic
		wallet-crypto epee easylogging version randomx ${Boost_LIBRARIES} sodium unbound
		ssl crypto hidapi-libusb dl)
target_compile_options(oc_verifier_lib PRIVATE -Ofast)
set_property(TARGET oc_verifier PROPERTY COMPILE_WARNING_AS_ERROR ON)
