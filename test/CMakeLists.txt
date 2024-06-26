project(test)

include_directories("../src")

set( ${PROJECT_NAME}_HEADERS_MOC
  testSet1.h
  testSet2.h
  testSet3.h
  testSet4.h
  testSet5.h
  testSet5_srp.h
  testSet5_rsa.h
  testSet6.h
  testSet6_dsa.h
  testSet6_bleichenbacher.h
  testSet7_CBC_MAC.h
  testSet7_51.h
  testSet7_52_53_54.h
  testSet7_55_wang.h
  testBigInt.h
  )

set( ${PROJECT_NAME}_HEADERS
  ${${PROJECT_NAME}_HEADERS_MOC}
  test.h
  )

set( ${PROJECT_NAME}_MAIN_SOURCES
  testSet1.cpp
  testSet2.cpp
  testSet3.cpp
  testSet4.cpp
  testSet5.cpp
  testSet5_srp.cpp
  testSet5_rsa.cpp
  testSet6.cpp
  testSet6_dsa.cpp
  testSet6_bleichenbacher.cpp
  testSet7_CBC_MAC.cpp
  testSet7_51.cpp
  testSet7_52_53_54.cpp
  testSet7_55_wang.cpp
  testBigInt.cpp
  )

set( ${PROJECT_NAME}_SOURCES 
  ${${PROJECT_NAME}_MAIN_SOURCES}
  test.cpp
  )

set( ${PROJECT_NAME}_RESOURCES
  qossl_test_resources.qrc
  )

qt5_wrap_cpp(${PROJECT_NAME}_SOURCES_MOC ${${PROJECT_NAME}_HEADERS_MOC})
qt5_add_resources(${PROJECT_NAME}_SOURCES_QRC ${${PROJECT_NAME}_RESOURCES})

set (${PROJECT_NAME}_RESOURCES qossl_test_resources.qrc)

add_executable(${PROJECT_NAME}
  ${${PROJECT_NAME}_SOURCES}
  ${${PROJECT_NAME}_SOURCES_MOC}
  ${${PROJECT_NAME}_SOURCES_QRC}
  ${${PROJECT_NAME}_HEADERS}
  )

target_link_libraries(${PROJECT_NAME} qossl)

qt5_use_modules(${PROJECT_NAME} Test)   #testlib?

add_custom_target(RunTests
                  COMMAND ${PROJECT_NAME}
                  DEPENDS ${PROJECT_NAME}
                  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
                  COMMENT "Run tests" # [VERBATIM]
                  #SOURCES source1...
                  )
