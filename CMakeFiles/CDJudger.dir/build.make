# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

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
CMAKE_COMMAND = /opt/cmake-3.16/bin/cmake

# The command to remove a file.
RM = /opt/cmake-3.16/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/keane/Documents/OnlineJudge/CDJudger

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/keane/Documents/OnlineJudge/CDJudger

# Include any dependencies generated for this target.
include CMakeFiles/CDJudger.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/CDJudger.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/CDJudger.dir/flags.make

CMakeFiles/CDJudger.dir/src/main.cpp.o: CMakeFiles/CDJudger.dir/flags.make
CMakeFiles/CDJudger.dir/src/main.cpp.o: src/main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/keane/Documents/OnlineJudge/CDJudger/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/CDJudger.dir/src/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/CDJudger.dir/src/main.cpp.o -c /home/keane/Documents/OnlineJudge/CDJudger/src/main.cpp

CMakeFiles/CDJudger.dir/src/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/CDJudger.dir/src/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/keane/Documents/OnlineJudge/CDJudger/src/main.cpp > CMakeFiles/CDJudger.dir/src/main.cpp.i

CMakeFiles/CDJudger.dir/src/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/CDJudger.dir/src/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/keane/Documents/OnlineJudge/CDJudger/src/main.cpp -o CMakeFiles/CDJudger.dir/src/main.cpp.s

# Object files for target CDJudger
CDJudger_OBJECTS = \
"CMakeFiles/CDJudger.dir/src/main.cpp.o"

# External object files for target CDJudger
CDJudger_EXTERNAL_OBJECTS =

CDJudger: CMakeFiles/CDJudger.dir/src/main.cpp.o
CDJudger: CMakeFiles/CDJudger.dir/build.make
CDJudger: CMakeFiles/CDJudger.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/keane/Documents/OnlineJudge/CDJudger/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable CDJudger"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/CDJudger.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/CDJudger.dir/build: CDJudger

.PHONY : CMakeFiles/CDJudger.dir/build

CMakeFiles/CDJudger.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/CDJudger.dir/cmake_clean.cmake
.PHONY : CMakeFiles/CDJudger.dir/clean

CMakeFiles/CDJudger.dir/depend:
	cd /home/keane/Documents/OnlineJudge/CDJudger && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/keane/Documents/OnlineJudge/CDJudger /home/keane/Documents/OnlineJudge/CDJudger /home/keane/Documents/OnlineJudge/CDJudger /home/keane/Documents/OnlineJudge/CDJudger /home/keane/Documents/OnlineJudge/CDJudger/CMakeFiles/CDJudger.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/CDJudger.dir/depend

