cmake_minimum_required(VERSION 3.17)
project(
  totp
  VERSION 1.0
  LANGUAGES CXX)

find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)

add_executable(${CMAKE_PROJECT_NAME} ${CMAKE_CURRENT_LIST_DIR}/otp.cc)
set_property(TARGET ${CMAKE_PROJECT_NAME} PROPERTY CXX_STANDARD 17)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include/)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE OpenSSL::Crypto)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE OpenSSL::SSL)
