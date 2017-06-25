project(test)

include_directories("../src")

set( ${PROJECT_NAME}_HEADERS_MOC
  testSet1.h
  )

set( ${PROJECT_NAME}_HEADERS
  ${${PROJECT_NAME}_HEADERS_MOC}
  test.h
  )

set( ${PROJECT_NAME}_MAIN_SOURCES
  testSet1.cpp
  )

set( ${PROJECT_NAME}_SOURCES 
  ${${PROJECT_NAME}_MAIN_SOURCES}
  test.cpp
  )


qt5_wrap_cpp(${PROJECT_NAME}_SOURCES_MOC ${${PROJECT_NAME}_HEADERS_MOC})

add_executable(${PROJECT_NAME}
  ${${PROJECT_NAME}_SOURCES}
  ${${PROJECT_NAME}_SOURCES_MOC}
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