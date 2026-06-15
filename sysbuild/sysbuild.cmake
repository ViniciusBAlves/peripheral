ExternalProject_Add_Step(
    app
    force_config
    COMMAND ${CMAKE_COMMAND} -E copy 
            ${CMAKE_CURRENT_SOURCE_DIR}/prj.conf 
            ${CMAKE_CURRENT_BINARY_DIR}/peripheral/zephyr/.config
    DEPENDEES configure
    DEPENDERS build
)