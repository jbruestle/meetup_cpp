
#pragma once

#include <memory>
#include <map>
#include <exception>
#include <functional>
#include <boost/asio.hpp>
#include "log.h"

typedef boost::asio::io_service io_service;
typedef boost::system::error_code error_code;
typedef boost::asio::ip::address ip_address;
typedef boost::asio::ip::address_v4 ip_address_v4;
typedef boost::asio::ip::address_v6 ip_address_v6;
typedef boost::asio::ip::udp::endpoint udp_endpoint;
typedef boost::asio::ip::tcp::endpoint tcp_endpoint;
typedef boost::asio::ip::udp::resolver udp_resolver;

#define FATAL(format, ...) do { LOG_ERROR(format, ##__VA_ARGS__); exit(1); } while(0)
#define runtime_assert(COND) do { if (!(COND)) { throw std::runtime_error(#COND); }} while(0)

namespace std {
template<typename T, typename ...Args>
std::unique_ptr<T> make_unique( Args&& ...args )
{
        return std::unique_ptr<T>( new T( std::forward<Args>(args)... ) );
}
}



