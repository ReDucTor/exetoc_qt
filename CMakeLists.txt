PROJECT(ExeToC_Qt)
SET(CMAKE_BUILD_TYPE Debug)
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

cmake_policy(SET CMP0020 NEW)

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/CMakeScripts;${CMAKE_MODULE_PATH})
IF(CMAKE_CXX_COMPILER MATCHES cl)
	ADD_DEFINITIONS( -D_CRT_SECURE_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS)
	SET(wxWidgets_CONFIGURATION msw)
	ADD_DEFINITIONS(-DNOMINMAX -D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_WARNINGS )
ENDIF ()
SET(Boost_USE_STATIC_LIBS   ON)
SET(Boost_USE_MULTITHREADED ON)
FIND_PACKAGE(Boost COMPONENTS filesystem system)

find_package(Qt5Widgets REQUIRED)

INCLUDE_DIRECTORIES(
	.
	exe2c
	exe2c/include
	${Boost_INCLUDE_DIR}
)

LINK_DIRECTORIES(
${Boost_LIBRARY_DIRS}
)

ADD_SUBDIRECTORY(exe2c)
ADD_SUBDIRECTORY(exe2c_gui)
