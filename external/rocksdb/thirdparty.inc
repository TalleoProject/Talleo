# Edit definitions below to specify paths to include files and libraries of all 3rd party libraries

# TODO: Make this work with find_package and/or get rid of it
#
# This example assumes all the libraries locate in directories under THIRDPARTY_HOME environment variable
# Set environment variable THIRDPARTY_HOME to point to your third party libraries home (Unix style dir separators)
# or change the paths below to reflect where the libraries actually reside
#
set (THIRDPARTY_LIBS "")         # Initialization, don't touch

#
# Defaults
#
set(GFLAGS_HOME $ENV{THIRDPARTY_HOME}/Gflags.Library)
set(GFLAGS_INCLUDE ${GFLAGS_HOME}/inc/include)
set(GFLAGS_LIB_DEBUG ${GFLAGS_HOME}/bin/debug/amd64/gflags.lib)
set(GFLAGS_LIB_RELEASE ${GFLAGS_HOME}/bin/retail/amd64/gflags.lib)

# ================================================== GFLAGS ==================================================
# For compatibility
if (GFLAGS)
  set(WITH_GFLAGS ON)
endif ()

if (WITH_GFLAGS)
  message(STATUS "GFLAGS library is enabled")
  
  if(DEFINED ENV{GFLAGS_INCLUDE})
    set(GFLAGS_INCLUDE $ENV{GFLAGS_INCLUDE})
  endif()
  
  if(DEFINED ENV{GFLAGS_LIB_DEBUG})
    set(GFLAGS_LIB_DEBUG $ENV{GFLAGS_LIB_DEBUG})
  endif()

  if(DEFINED ENV{GFLAGS_LIB_RELEASE})
    set(GFLAGS_LIB_RELEASE $ENV{GFLAGS_LIB_RELEASE})
  endif()
  
  set(GFLAGS_CXX_FLAGS -DGFLAGS=gflags)
  set(GFLAGS_LIBS debug ${GFLAGS_LIB_DEBUG} optimized ${GFLAGS_LIB_RELEASE})

  add_definitions(${GFLAGS_CXX_FLAGS})
  include_directories(${GFLAGS_INCLUDE})
  set (THIRDPARTY_LIBS ${THIRDPARTY_LIBS} ${GFLAGS_LIBS})
else ()
  message(STATUS "GFLAGS library is disabled")
endif ()

# ================================================== SNAPPY ==================================================
#
# Edit these 4 lines to define paths to Snappy
#
set(SNAPPY_HOME $ENV{THIRDPARTY_HOME}/Snappy.Library)
set(SNAPPY_INCLUDE ${SNAPPY_HOME}/inc/inc)
set(SNAPPY_LIB_DEBUG ${SNAPPY_HOME}/bin/debug/amd64/snappy.lib)
set(SNAPPY_LIB_RELEASE ${SNAPPY_HOME}/bin/retail/amd64/snappy.lib)

# For compatibility
if(SNAPPY)
  set(WITH_SNAPPY ON)
endif ()

if (WITH_SNAPPY)
  message(STATUS "SNAPPY library is enabled")
  
  if(DEFINED ENV{SNAPPY_INCLUDE})
    set(SNAPPY_INCLUDE $ENV{SNAPPY_INCLUDE})
  endif()
  
  if(DEFINED ENV{SNAPPY_LIB_DEBUG})
    set(SNAPPY_LIB_DEBUG $ENV{SNAPPY_LIB_DEBUG})
  endif()

  if(DEFINED ENV{SNAPPY_LIB_RELEASE})
    set(SNAPPY_LIB_RELEASE $ENV{SNAPPY_LIB_RELEASE})
  endif()
  
  set(SNAPPY_CXX_FLAGS -DSNAPPY)
  set(SNAPPY_LIBS debug ${SNAPPY_LIB_DEBUG} optimized ${SNAPPY_LIB_RELEASE})

  add_definitions(${SNAPPY_CXX_FLAGS})
  include_directories(${SNAPPY_INCLUDE})
  set (THIRDPARTY_LIBS ${THIRDPARTY_LIBS} ${SNAPPY_LIBS})
else ()
  message(STATUS "SNAPPY library is disabled")
endif ()

# ================================================== LZ4 ==================================================
#
# Edit these 4 lines to define paths to LZ4
#
set(LZ4_HOME $ENV{THIRDPARTY_HOME}/LZ4.Library)
set(LZ4_INCLUDE ${LZ4_HOME}/inc/include)
set(LZ4_LIB_DEBUG ${LZ4_HOME}/bin/debug/amd64/lz4.lib)
set(LZ4_LIB_RELEASE ${LZ4_HOME}/bin/retail/amd64/lz4.lib)

#
# Don't touch these lines
#
if (DEFINED LZ4)
  set(WITH_LZ4 ON)
endif ()

if (WITH_LZ4)
  message(STATUS "LZ4 library is enabled")
  
  if(DEFINED ENV{LZ4_INCLUDE})
    set(LZ4_INCLUDE $ENV{LZ4_INCLUDE})
  endif()
  
  if(DEFINED ENV{LZ4_LIB_DEBUG})
    set(LZ4_LIB_DEBUG $ENV{LZ4_LIB_DEBUG})
  endif()

  if(DEFINED ENV{LZ4_LIB_RELEASE})
    set(LZ4_LIB_RELEASE $ENV{LZ4_LIB_RELEASE})
  endif()
  
  set(LZ4_CXX_FLAGS -DLZ4)
  set(LZ4_LIBS debug ${LZ4_LIB_DEBUG} optimized ${LZ4_LIB_RELEASE})

  add_definitions(${LZ4_CXX_FLAGS})
  include_directories(${LZ4_INCLUDE})
  set (THIRDPARTY_LIBS ${THIRDPARTY_LIBS} ${LZ4_LIBS})
else ()
  message(STATUS "LZ4 library is disabled")
endif ()

# For compatibilty
if (XPRESS)
  set(WITH_XPRESS ON)
endif ()

if (WITH_XPRESS)
  message(STATUS "XPRESS is enabled")

  add_definitions(-DXPRESS)
  
  # We are using the implementation provided by the system
  set (SYSTEM_LIBS ${SYSTEM_LIBS} Cabinet.lib)
else ()
  message(STATUS "XPRESS is disabled")
endif ()

#
# Edit these 4 lines to define paths to Jemalloc
#
set(JEMALLOC_HOME $ENV{THIRDPARTY_HOME}/Jemalloc.Library)
set(JEMALLOC_INCLUDE ${JEMALLOC_HOME}/inc/include)
set(JEMALLOC_LIB_DEBUG ${JEMALLOC_HOME}/bin/debug/amd64/jemalloc.lib)
set(JEMALLOC_LIB_RELEASE ${JEMALLOC_HOME}/bin/retail/amd64/jemalloc.lib)

# ================================================== JEMALLOC ==================================================
#
# Don't touch these lines
#

# For compatibilty
if(JEMALLOC)
  set(WITH_JEMALLOC ON)
endif()

if (WITH_JEMALLOC)
  message(STATUS "JEMALLOC library is enabled")
  set(JEMALLOC_CXX_FLAGS "-DROCKSDB_JEMALLOC -DJEMALLOC_EXPORT= ")
  
  if(DEFINED ENV{JEMALLOC_INCLUDE})
    set(JEMALLOC_INCLUDE $ENV{JEMALLOC_INCLUDE})
  endif()
  
  if(DEFINED ENV{JEMALLOC_LIB_DEBUG})
    set(JEMALLOC_LIB_DEBUG $ENV{JEMALLOC_LIB_DEBUG})
  endif()

  if(DEFINED ENV{JEMALLOC_LIB_RELEASE})
    set(JEMALLOC_LIB_RELEASE $ENV{JEMALLOC_LIB_RELEASE})
  endif()

  set(JEMALLOC_LIBS debug ${JEMALLOC_LIB_DEBUG} optimized ${JEMALLOC_LIB_RELEASE})

  add_definitions(${JEMALLOC_CXX_FLAGS})
  include_directories(${JEMALLOC_INCLUDE})
  set (THIRDPARTY_LIBS ${THIRDPARTY_LIBS} ${JEMALLOC_LIBS})
  set (ARTIFACT_SUFFIX "_je")
  
  set(WITH_JEMALLOC ON)
  
else ()
  set (ARTIFACT_SUFFIX "")
  message(STATUS "JEMALLOC library is disabled")
endif ()
