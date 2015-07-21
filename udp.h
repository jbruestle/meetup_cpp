
#pragma once

#include "types.h"

typedef boost::asio::ip::udp::endpoint endpoint;
typedef std::function<bool (const endpoint& src, const char* buf, size_t len)> protocol_hander_t; 

inline endpoint ep_from_string(const std::string& ip, uint16_t port) {
	return endpoint(boost::asio::ip::address::from_string(ip), port);
}

class udp_port
{
public:
	static const size_t max_size = 2048;
	// Make a UDP transceiver
	udp_port(io_service& ios, uint16_t port);
	// For recv, each protocol is tried in order, first one to return true gets the packet
	void add_protocol(const protocol_hander_t& proto);
	// Sends are synchronous
	void send(const endpoint& dest, const char* buf, size_t len);

private:
	void start_recv();
	void on_recv(const boost::system::error_code& error, size_t size);

	boost::asio::ip::udp::socket m_socket;
	endpoint m_endpoint;
	char m_buffer[max_size];
	std::vector<protocol_hander_t> m_protocols;
};

