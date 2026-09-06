cmake_minimum_required(VERSION 3.10)
project(LiberaCryptInstallConsumer LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(LiberaCrypt 0.6 CONFIG REQUIRED)

add_executable(liberacrypt_install_consumer main.c)
target_link_libraries(liberacrypt_install_consumer PRIVATE LiberaCrypt::LiberaCrypt)
