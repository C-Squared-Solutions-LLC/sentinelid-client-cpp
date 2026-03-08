cmake_minimum_required(VERSION 3.20)
project(sentinelid-client VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)

# hidapi is typically installed via the system package manager:
#   Windows : vcpkg install hidapi
#   macOS   : brew install hidapi
#   Linux   : apt install libhidapi-dev
find_package(hidapi REQUIRED)

add_library(sentinelid-client
  src/device.cpp
)

target_include_directories(sentinelid-client PUBLIC include)
target_link_libraries(sentinelid-client PUBLIC hidapi::hidapi nlohmann_json::nlohmann_json)

if(WIN32)
  target_link_libraries(sentinelid-client PUBLIC setupapi)
endif()
