# FAT32 emulator

Basic FAT32 emulator, that use regular file.
The emulator provides CLI (command line interface) with commands: cd, format, ls, mkdir, touch. The commands operate on FAT32 filesystem.

## Dependencies

* [GCC 11.4.0](https://gcc.gnu.org/gcc-11/)
* [CMake 3.5.0](https://cmake.org/download/) _(or higher)_

## Installing

1. Check you have all of the dependencies
2. Configure and build project
  ```bash
  cmake -B ./build . # configure
  cmake --build -B ./build . # build
  ```

## Run

In the `./bin` folder we have all the binaries to execute

1. `FileFAT32 <path to file>` file, just run it with file in first argument

## What I used for testing 

* VS Code HEX file Viewer
* VS Code

## Restrictions

  * not optimized for faster work
  * max file name 11 symbols, need support LFN
  * file/folder change Date Time support 


 




