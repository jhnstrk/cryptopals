cmake_minimum_required(VERSION 2.8)

project( cryptopals )

#------------------------------------------------------------------------------
# Find QT

find_path(QT5_ROOT_PREFIX 
   PATHS lib/cmake/Qt5Core/Qt5CoreConfig.cmake
   HINTS "${CMAKE_PREFIX_PATH}" 
   DOC   "Qt5 root path")

if( (NOT QT5_ROOT_PREFIX) OR (NOT IS_DIRECTORY "${QT5_ROOT_PREFIX}") )
    message(FATAL_ERROR "Qt5 path not found. please set QT5_ROOT_PREFIX")
endif()

list(FIND CMAKE_PREFIX_PATH "${QT5_ROOT_PREFIX}" _index)
if(_index LESS 0)
    list(APPEND CMAKE_PREFIX_PATH "${QT5_ROOT_PREFIX}")
endif()


find_package(Qt5Core        REQUIRED)

#------------------------------------------------------------------------------
# Find OpenSSL

find_package( OpenSSL REQUIRED )

#------------------------------------------------------------------------------


if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

add_subdirectory(src)

option(BUILD_TESTING "Build test suite" ON)
option(BUILD_EXAMPLES "Build examples"  ON)

if (BUILD_TESTING)
  add_subdirectory(test)
endif()

#if (BUILD_EXAMPLES)
#  add_subdirectory(examples)
#endif()

