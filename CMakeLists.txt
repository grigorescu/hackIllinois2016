
cmake_minimum_required(VERSION 2.8)

project(Plugin)

include(BroPlugin)

find_package(LibCURL)

if ( LIBCURL_FOUND )
  bro_plugin_begin(HackIllinois Safe_Browsing)
  bro_plugin_cc(src/ChunkData.pb.cc)
  bro_plugin_cc(src/Plugin.cc)
  bro_plugin_bif(src/safe_browsing.bif)
  bro_plugin_link_library(${LibCURL_LIBRARIES})
  bro_plugin_link_library(/usr/lib64/libprotobuf.so)
  bro_plugin_dist_files(README CHANGES COPYING VERSION)
  bro_plugin_end()
  message(STATUS "LibCurl prefix      : ${LibCURL_ROOT_DIR}")
else ()
  message(FATAL_ERROR "LibCURL not found.")
endif ()