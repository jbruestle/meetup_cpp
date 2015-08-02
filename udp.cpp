
#include "udp.h"

#define LOG_TOPIC LT_UDP

udp_endpoint udp_resolve(io_service& ios, const std::string& ip, const std::string& port) {
        udp_resolver resolver(ios);
        udp_resolver::query query(boost::asio::ip::udp::v4(), ip, port);
        udp_resolver::iterator it = resolver.resolve(query);
        return *it;
}

tcp_endpoint tcp_resolve(io_service& ios, const std::string& ip, const std::string& port) {
        boost::asio::ip::tcp::resolver resolver(ios);
        boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), ip, port);
        boost::asio::ip::tcp::resolver::iterator it = resolver.resolve(query);
        return *it;
}

std::string to_string(const udp_endpoint& ep) {
	return ep.address().to_string() + ":" + std::to_string(ep.port());
}

udp_port::udp_port(io_service& ios, uint16_t port)
	: m_socket(ios, udp_endpoint(boost::asio::ip::udp::v4(), port))
{
	start_recv();
}

void udp_port::add_protocol(const protocol_hander_t& proto)
{
	m_protocols.push_back(proto);
}

void udp_port::send(const udp_endpoint& dest, const char* buf, size_t len)
{
	error_code err;
	m_socket.send_to(boost::asio::buffer(buf, len), dest, 0, err);
}

void udp_port::start_recv()
{
	m_socket.async_receive_from(boost::asio::buffer(m_buffer, max_size), m_endpoint, 
		[this](const error_code& err, size_t size) { on_recv(err, size); });
}

void udp_port::on_recv(const error_code& error, size_t size)
{
	if (error == boost::asio::error::message_size) {
		LOG_DEBUG("UDP received oversized message");
		start_recv();
	}
	if (error) {
		FATAL("UDP fatal error: %s", error.message().c_str());
	}
	for(auto proto : m_protocols) {
		if (proto(m_endpoint, m_buffer, size)) {
			break;
		}
	}
	start_recv();
}

/*
int main()
{
	io_service ios;
	udp_port up(ios, 5000);
	up.add_protocol([](const endpoint& src, const char* buf, size_t len) -> bool {
		printf("Got a packet, size = %d\n", int(len));
		return true;
	});
	ios.run();
}
*/

