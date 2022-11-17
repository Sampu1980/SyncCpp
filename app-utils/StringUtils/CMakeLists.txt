project (StringUtils)

add_library(${PROJECT_NAME} STATIC include/app-utils/StringUtils.h src/StringUtils.cpp)

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} PUBLIC fmt)