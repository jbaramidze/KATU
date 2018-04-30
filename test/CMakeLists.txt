cmake_minimum_required(VERSION 2.5)
project (annotation)
set(srcs "annotation.cpp") 
include("/home/zhani/Thesis/installer/dynamorio/build/cmake/DynamoRIOConfig.cmake")
include_directories("/home/zhani/Thesis/installer/dynamorio/core/lib" "/custobuilds/include")

set(CMAKE_C_FLAGS "-g -Wall -nostartfiles -nodefaultlibs -Wl,--dynamic-linker=/custobuilds/lib/ld-2.27.so" )
set(CMAKE_CXX_FLAGS "-g -Wall -nostartfiles -nodefaultlibs -Wl,--dynamic-linker=/custobuilds/lib/ld-2.27.so" )

set(CMAKE_EXE_LINKER_FLAGS "/custobuilds/lib/crt1.o /custobuilds/lib/crti.o ")

link_directories("/custobuilds/lib")

use_ZHANI_annotations(annotation, srcs)
add_executable(annotation ${srcs} )

target_link_libraries(annotation "c" "/custobuilds/lib/crtn.o")

