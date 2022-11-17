project (TaskRunner)

add_library(${PROJECT_NAME} STATIC
        include/app-utils/Task.h
        include/app-utils/TaskRunner.h src/TaskRunner.cpp )

target_include_directories(${PROJECT_NAME} PUBLIC include)
target_link_libraries(${PROJECT_NAME} PUBLIC StringUtils logger)