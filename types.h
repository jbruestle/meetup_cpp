
#pragma once

#include <memory>
#include <map>
#include <exception>
#include <functional>
#include <boost/asio.hpp>

typedef boost::asio::io_service io_service;

#define LL_DEBUG  0
#define LL_INFO   1
#define LL_WARN   2  
#define LL_ERROR  3

// TODO: Make this not ignore level
#define LOG(level, format, ...) fprintf(stderr, format "\n", ##__VA_ARGS__)

#define LOG_DEBUG(format, ...) LOG(LL_DEBUG, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) LOG(LL_INFO, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...) LOG(LL_WARN, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) LOG(LL_ERROR, format, ##__VA_ARGS__)

#define FATAL(format, ...) do { LOG_ERROR(format, ##__VA_ARGS__); exit(1); } while(0)

#define runtime_assert(COND) do { if (!(COND)) { throw std::runtime_error(#COND); }} while(0)


