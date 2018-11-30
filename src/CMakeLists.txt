CMAKE_MINIMUM_REQUIRED(VERSION 3.12)
PROJECT(Gb28181)


#Add the source in project root directory
AUX_SOURCE_DIRECTORY(. DIRSRCS)


#Add header file include directories
INCLUDE_DIRECTORIES(/src )


SET(CMAKE_CXX_STANDARD 17)


# Target
ADD_EXECUTABLE(Gb28181 main.cpp SipUA.cpp SipHeader.cpp)

TARGET_LINK_LIBRARIES(Gb28181)