
#include "udp.h"

using boost::asio::ip::udp;

udp_port::udp_port(io_service& ios, uint16_t port)
	: m_socket(ios, udp_endpoint(udp::v4(), port))
{
	start_recv();
}

void udp_port::add_protocol(const protocol_hander_t& proto)
{
	m_protocols.push_back(proto);
}

void udp_port::send(const udp_endpoint& dest, const char* buf, size_t len)
{
	boost::system::error_code err;
	m_socket.send_to(boost::asio::buffer(buf, len), dest, 0, err);
}

void udp_port::start_recv()
{
	m_socket.async_receive_from(boost::asio::buffer(m_buffer, max_size), m_endpoint, 
		[this](const boost::system::error_code& err, size_t size) { on_recv(err, size); });
}

void udp_port::on_recv(const boost::system::error_code& error, size_t size)
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

