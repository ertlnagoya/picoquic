# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.10.2/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.10.2/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/komatsu/src/quic-wolfssl/picoquic

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/komatsu/src/quic-wolfssl/picoquic/build

# Utility rule file for clangformat.

# Include the progress variables for this target.
include CMakeFiles/clangformat.dir/progress.make

CMakeFiles/clangformat:
	clang-format -style=Webkit -i /Users/komatsu/src/quic-wolfssl/picoquic/build/CMakeFiles/3.10.2/CompilerIdC/CMakeCCompilerId.c /Users/komatsu/src/quic-wolfssl/picoquic/build/CMakeFiles/feature_tests.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/cubic.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/democlient.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/demoserver.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/fnv1a.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/frames.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/h3zero.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/http0dot9.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/intformat.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/logger.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/newreno.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/packet.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/picohash.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/picosocks.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/picosplay.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/quicctx.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/sacks.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/sender.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/spinbit.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/ticket_store.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/tls_api.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/token_store.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/transport.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/util.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquic_t/picoquic_t.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquicfirst/getopt.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquicfirst/picoquicdemo.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/ack_of_ack_test.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/cleartext_aead_test.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/cnx_creation_test.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/float16test.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/fnv1atest.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/h3zerotest.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/hashtest.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/http0dot9test.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/intformattest.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/parseheadertest.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/pn2pn64test.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/sacktest.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/sim_link.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/skip_frame_test.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/socket_test.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/splay_test.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/stream0_frame_test.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/stresstest.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/ticket_store_test.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/tls_api_test.c /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/transport_param_test.c /Users/komatsu/src/quic-wolfssl/picoquic/UnitTest1/stdafx.h /Users/komatsu/src/quic-wolfssl/picoquic/UnitTest1/targetver.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/democlient.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/demoserver.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/fnv1a.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/h3zero.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/picohash.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/picoquic.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/picoquic_internal.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/picoquic_logger.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/picosocks.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/picosplay.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/picotlsapi.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/tls_api.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/util.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquic/wincompat.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquicfirst/getopt.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/picoquictest.h /Users/komatsu/src/quic-wolfssl/picoquic/picoquictest/picoquictest_internal.h

clangformat: CMakeFiles/clangformat
clangformat: CMakeFiles/clangformat.dir/build.make

.PHONY : clangformat

# Rule to build all files generated by this target.
CMakeFiles/clangformat.dir/build: clangformat

.PHONY : CMakeFiles/clangformat.dir/build

CMakeFiles/clangformat.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/clangformat.dir/cmake_clean.cmake
.PHONY : CMakeFiles/clangformat.dir/clean

CMakeFiles/clangformat.dir/depend:
	cd /Users/komatsu/src/quic-wolfssl/picoquic/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/komatsu/src/quic-wolfssl/picoquic /Users/komatsu/src/quic-wolfssl/picoquic /Users/komatsu/src/quic-wolfssl/picoquic/build /Users/komatsu/src/quic-wolfssl/picoquic/build /Users/komatsu/src/quic-wolfssl/picoquic/build/CMakeFiles/clangformat.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/clangformat.dir/depend

