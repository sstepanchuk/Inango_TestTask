# DNS_proxy

The DNS_proxy proxy project is a simple multithreaded DNS proxy server implemented in C with blacklist functionality. It processes requests using basic blocking sockets and 8 threads. This project includes the main DNS proxy server and a suite of tests to ensure functionality, along with memory leak checks.

Used simple thread pool (thpool) from this repo https://github.com/Pithikos/C-Thread-Pool

## Dependencies

* [CMake 3.5.0](https://cmake.org/download/) _(or higher)_
* [Check 0.15.2](https://github.com/libcheck/check/releases) _(for unit testing)_
* [Valgrind 3.15.0](https://valgrind.org/docs/manual/dist.readme.html) _(for memory leak detection)_

## Installing

1. Check you have all of the dependencies
2. Configure and build project
  ```bash
  cmake -B ./build . # configure
  cmake --build -B ./build . # build
  ```

## Configure DNS proxy

` // IN DEVELOPMENT `

## Run

In the `./bin` folder we have all the binaries to execute

1. `DNS_proxy` file, it's our dns proxy
2. `tests` file, it's all tests

## Tests

```bash
cd ./build 
ctest -V
```

## Memory leak checks 

```bash
cmake --build ./build --target tests_memory_leak_check # Memory leaks check for all tests
cmake --build ./build --target DNS_proxy_memory_leak_check # Memory leaks check for all tests
```

## What I used for testing 

` // IN DEVELOPMENT `

## Advantages and restrictions

* Advantages 
  * It multithreaded
  * Thread pool for maximizing productivity
  * Nice project structure
  * Test coverage (Check lib and CTest)

* Restrictions 
  * not fully optimized, think I can find ways to make it faster 
  * max received traffic is ~3 Mb/s, but I send ~10 Mb/s (used Packet Sender for intensive tests, I think some packets are lost)


 




