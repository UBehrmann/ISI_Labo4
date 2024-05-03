cmake_minimum_required(VERSION 3.27)
project(ISI_Labo4)

set(CMAKE_CXX_STANDARD 17)

add_executable(RC4_1
        RC4_1/part1.cpp
        RC4_1/laboCryptoUtils.h
        RC4_1/laboCryptoUtils.cpp
)

add_executable(RC4_2
        RC4_2/part2.cpp
        RC4_2/laboCryptoUtils.h
        RC4_2/laboCryptoUtils.cpp
)

add_executable(AES
        AES/part3.cpp
        AES/aes.h
        AES/aes.cpp
)