cmake_minimum_required(VERSION 2.8)

project(BroPluginTCPWriter)

include(BroPlugin)

find_package(OpenSSL)

if (NOT OPENSSL_FOUND)
    message(FATAL_ERROR "Cannot find OpenSSL, use --with-openssl=DIR.")
endif ()

include_directories(BEFORE ${OPENSSL_INCLUDE_DIR})
bro_plugin_begin(Writer TCP)
bro_plugin_cc(src/Plugin.cc)
bro_plugin_cc(src/TCP.cc)
bro_plugin_bif(src/tcpwriter.bif)
bro_plugin_dist_files(README CHANGES COPYING VERSION)
bro_plugin_link_library(${OPENSSL_LIBRARIES})
bro_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
