cmake_minimum_required(VERSION 3.2)
project(nashromi)

set(output_dir "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${output_dir}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${output_dir}")

set(SHOW_RESULTS_DEFAULT ON)
set(DynamoRIO_USE_LIBC OFF)

set(DynamoRIO_MAIN "/home/zhani/Thesis/installer/dynamorio")

set(DynamoRIO_DIR "${DynamoRIO_MAIN}/build/cmake")

include_directories("${DynamoRIO_MAIN}" "include" "${DynamoRIO_MAIN}/build/ext/include" "third_party/lp_solve_5.5")
link_directories("third_party/lp_solve_5.5")

option(SHOW_RESULTS
    "Display client results in pop-up (Windows) or console message (Linux)"
    ${SHOW_RESULTS_DEFAULT})
if (SHOW_RESULTS)
  add_definitions(-DSHOW_RESULTS)
endif (SHOW_RESULTS)

if (STATIC_LIBRARY)
  set(libtype STATIC)
else ()
  set(libtype SHARED)
endif ()

set(IGNORE_WARNINGS "-Wno-unused-function -Wno-unused-variable -Wno-missing-field-initializers")

if (NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE MATCHES Debug)
  set(CMAKE_C_FLAGS "${IGNORE_WARNINGS} -std=gnu99 -DDEBUG -Wall -Wextra -g -O0 -Wno-unused-parameter")
  set(CMAKE_CXX_FLAGS "${IGNORE_WARNINGS} -DDEBUG -Wall -Wextra -std=c++11 -g -O0 -Wno-unused-parameter")
else ()
  set(CMAKE_C_FLAGS "${IGNORE_WARNINGS} -O2 -Wall -std=gnu99")
  set(CMAKE_CXX_FLAGS "${IGNORE_WARNINGS} -O2 -Wall -std=c++11")
endif ()

if (NOT DEFINED DynamoRIO_DIR)
  set(DynamoRIO_DIR "${DR_ROOT}/cmake" CACHE PATH
      "DynamoRIO installation's cmake directory")

endif (NOT DEFINED DynamoRIO_DIR)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO package required to build")
endif (NOT DynamoRIO_FOUND)

###########################################################################
function(add_dr_client name source_file_list extension_list)
  add_library(${name} ${libtype} ${source_file_list})
  set_target_properties(${name} PROPERTIES LINKER_LANGUAGE C)
  target_link_libraries(${name} "lpsolver")
  configure_DynamoRIO_client(${name})
  foreach (ext ${extension_list})
    use_DynamoRIO_extension(${name} ${ext})
  endforeach (ext)
  # Provide a hint for how to use the client
  if (NOT DynamoRIO_INTERNAL OR NOT "${CMAKE_GENERATOR}" MATCHES "Ninja")
    add_custom_command(TARGET ${name}
        POST_BUILD
        COMMAND ${CMAKE_COMMAND}
        ARGS -E echo "Usage: pass to drconfig or drrun: -c ${output_dir}"
        VERBATIM)
  endif ()

endfunction(add_dr_client)

###########################################################################

# As we'll be calling configure_DynamoRIO_{client} from within
# a function scope, we must set the global vars ahead of time:
configure_DynamoRIO_global(OFF ON)
set(nashromi_sources
    src/instruction.c
    src/module.c
    src/syscall.c
    src/taint.c
    src/vars.c
    src/ilp.c)
# Use ;-separated lists for source files and extensions.
add_dr_client(nashromi "${nashromi_sources}" "drmgr;drsyms;drwrap")
