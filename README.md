# vmtracer - VMProtect 2 Virtual Machine Tracer Library

The base library for `um-tracer`. This project contains an execution environment agnostic C++ class and trap handler aimed to aid in hooking into VMProtect 2 virtual machines. This project uses no STL, heap allocations, or any other limiting C++ code. The library requires executing in long mode however. You can find an example usage of this very small project over at the [um-tracer repo](https://githacks.org/vmp2/um-tracer).

