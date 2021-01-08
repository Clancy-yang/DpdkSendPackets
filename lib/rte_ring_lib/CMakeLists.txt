# cmake_minimum_required(VERSION <specify CMake version here>)
project(rte_ring C)

set(CMAKE_C_STANDARD 99)

add_library(rte_ring
        rte_ring.c
        rte_ring.h
        rte_atomic_x86.h)