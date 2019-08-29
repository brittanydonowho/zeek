
cmake_minimum_required(VERSION 2.8)

project(ZeekPluginRot13)

include(ZeekPlugin)

zeek_plugin_begin(Demo Rot13)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_bif(src/rot13.bif)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_end()

file(STRINGS "VERSION" VERSION LIMIT_COUNT 1)

if ("../.." STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
