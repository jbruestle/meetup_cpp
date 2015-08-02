
#pragma once

#include "types.h"

typedef std::function<bool (const udp_endpoint& src, const char* buf, size_t len)> protocol_hander_t; 

// Helper functions
udp_endpoint udp_resolve(io_service& ios, const std::string& ip, const std::string& port);
tcp_endpoint tcp_resolve(io_service& ios, const std::string& ip, const std::string& port);
std::string to_string(const udp_endpoint& ep);

class udp_port
{
public:
	static const size_t max_size = 2048;
	// Make a UDP transceiver
	udp_port(io_service& ios, uint16_t port);
	// For recv, each protocol is tried in order, first one to return true gets the packet
	void add_protocol(const protocol_hander_t& proto);
	// Sends are synchronous
	void send(const udp_endpoint& dest, const char* buf, size_t len);

private:
	void start_recv();
	void on_recv(const error_code& error, size_t size);

	boost::asio::ip::udp::socket m_socket;
	udp_endpoint m_endpoint;
	char m_buffer[max_size];
	std::vector<protocol_hander_t> m_protocols;
};

