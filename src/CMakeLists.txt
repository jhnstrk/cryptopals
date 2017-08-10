project( qossl )

if (unix)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

include_directories(${OPENSSL_INCLUDE_DIR})

set( ${PROJECT_NAME}_HEADERS_MOC
)

set( ${PROJECT_NAME}_HEADERS
  ${${PROJECT_NAME}_HEADERS_MOC}
  qossl_internal.h
  bitsnbytes.h
  hmac.h
  md4.h
  mersene_twister.h
  qbigint.h
  sha_1.h
  utils.h
)


# Generated files
qt5_wrap_cpp(${PROJECT_NAME}_SOURCES_MOC ${${PROJECT_NAME}_HEADERS_MOC})

add_library( qossl SHARED 
  ${${PROJECT_NAME}_SOURCES_MOC}
  ${${PROJECT_NAME}_HEADERS}
  qossl_internal.cpp
  bitsnbytes.cpp
  hmac.cpp
  utils.cpp
  md4.cpp
  mersene_twister.cpp
  qbigint.cpp
  sha_1.cpp
  )

find_package( ZLIB REQUIRED )
if ( ZLIB_FOUND )
    include_directories( ${ZLIB_INCLUDE_DIRS} )
    target_link_libraries( qossl ${ZLIB_LIBRARIES} )
endif( ZLIB_FOUND )

target_link_libraries( qossl ${OPENSSL_LIBRARIES})

qt5_use_modules(qossl Core Network)

install(TARGETS qossl
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
