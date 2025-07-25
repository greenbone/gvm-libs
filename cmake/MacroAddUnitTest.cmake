macro(add_unit_test _testName _testSource)
  add_executable(${_testName} ${_testSource})
  target_link_libraries(${_testName} ${CGREEN_LIBRARIES} ${ARGN})
  target_include_directories(${_testName} PRIVATE ${CGREEN_INCLUDE_DIRS})
  target_compile_options(${_testName} PRIVATE "-fsanitize=address")
  target_link_options(${_testName} PRIVATE "-fsanitize=address")
  add_test(NAME ${_testName} COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${_testName})
  set_tests_properties(
    ${_testName}
    PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1"
  )
endmacro()
