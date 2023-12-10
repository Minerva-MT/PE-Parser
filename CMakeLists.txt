cmake_minimum_required(VERSION 3.26)
project(PE-Parser C)

set(CMAKE_C_STANDARD 11)

include_directories(Headers)

add_executable(PE-Parser Source/Parser.c Source/Printer.c main.c)
