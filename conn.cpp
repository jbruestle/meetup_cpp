
#include "conn.h"
#include "log.h"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/sha.h>
#include <openssl/rand.h>

#define LOG_TOPIC LT_CONN

conn::conn(conn_mgr& mgr, const udp_endpoint& who, const conn_hdr &hdr) 
	: m_mgr(mgr)
	, m_who(who)
	, m_state(state::starting)
	, m_time(hdr.s_time)
	, m_token(hdr.s_token)
{
	start_connect();
}

void conn::reset(const conn_hdr &hdr) 
{
	assert(m_state == state::time_wait);
	m_state = state::starting;
	m_time = hdr.s_time;
	m_token = hdr.s_token;
	start_connect();
}

void conn::on_packet(const conn_hdr &hdr, const char* data, size_t len)
{
	assert(m_state != state::time_wait);
	// Update remote time + token
	if (uint8_t(hdr.s_time - m_time) < 127) {
		m_time = hdr.s_time;
		m_token = hdr.s_token;
	}
	if (hdr.type != ptype::data && hdr.type != ptype::data_ack) {
		// Ignore any other types
		return;
	}
	if (m_state == state::starting) {
		m_queue.emplace(hdr, data, len);
		if (m_queue.size() > 5) {
			m_queue.pop();
		}
		return;
	}
	process_packet(hdr, data, len);
}

struct data_hdr {
        uint32_t seq;
        uint32_t timestamp; 
};

struct data_ack_hdr {
        uint32_t ack;
        uint32_t window;
        uint32_t timestamp;
};

void conn::send_seq(seq_t seq, const char* buf, size_t len)
{
        // Push back keepalive
        m_mgr.m_tm.cancel(m_keepalive);
        m_keepalive = m_mgr.m_tm.add(now() + KEEP_ALIVE, [this]() { do_keepalive(); });
        // Make space for headers
        conn_hdr& chdr = *((conn_hdr*) (m_mgr.m_send_buf));
        data_hdr& dhdr = *((data_hdr*) (m_mgr.m_send_buf + sizeof(conn_hdr)));
	char* data = m_mgr.m_send_buf + sizeof(conn_hdr) + sizeof(data_hdr);
	assert(sizeof(conn_hdr) + sizeof(data_hdr) + len < 2048);
	// Setup chdr
	chdr.type = ptype::data;
	chdr.r_time = m_time;
	chdr.r_token = m_token;
	// Setup dhdr
        dhdr.seq = htonl(uint32_t(seq));
        dhdr.timestamp = htonl(now_us_wrap());
        if (dhdr.timestamp == 0) { dhdr.timestamp = htonl(1); }
	// Copy actual data, maybe remove memcpy someday
        memcpy(data, buf, len);
	// Send away
        LOG_DEBUG("send SEQ (%u, %u, %u)", uint32_t(seq), uint32_t(len), htonl(dhdr.timestamp));
	m_mgr.send_packet(m_who, sizeof(conn_hdr) + sizeof(data_hdr) + len);
}

void conn::send_ack(seq_t ack, size_t window, timestamp_t stamp)
{
        // Push back keepalive
        m_mgr.m_tm.cancel(m_keepalive);
        m_keepalive = m_mgr.m_tm.add(now() + KEEP_ALIVE, [this]() { do_keepalive(); });
        // Make space for headers
        conn_hdr& chdr = *((conn_hdr*) (m_mgr.m_send_buf));
        data_ack_hdr& dhdr = *((data_ack_hdr*) (m_mgr.m_send_buf + sizeof(conn_hdr)));
	// Setup chdr
	chdr.type = ptype::data_ack;
	chdr.r_time = m_time;
	chdr.r_token = m_token;
	// Setup dhdr
        dhdr.ack = htonl(uint32_t(ack));
        dhdr.window = htonl(uint32_t(window));
        dhdr.timestamp = htonl(uint32_t(stamp));
        LOG_DEBUG("send ACK (%u, %u, %u)", uint32_t(ack), uint32_t(window), uint32_t(stamp));
	m_mgr.send_packet(m_who, sizeof(conn_hdr) + sizeof(data_ack_hdr));
}

void conn::do_keepalive()
{
        // Make space for headers
        conn_hdr& chdr = *((conn_hdr*) (m_mgr.m_send_buf));
	// Setup chdr
	chdr.type = ptype::probe_ack;
	chdr.r_time = m_time;
	chdr.r_token = m_token;
	// Send packet + reschedule
        LOG_DEBUG("Sending keepalive");
	m_mgr.send_packet(m_who, sizeof(conn_hdr));
        m_keepalive = m_mgr.m_tm.add(now() + KEEP_ALIVE, [this]() { do_keepalive(); });
}

bool conn::process_packet(const conn_hdr &hdr, const char* data, size_t size)
{
        if (hdr.type == ptype::data_ack) {
                if (size != sizeof(data_ack_hdr)) {
                        return false;
                }
                const data_ack_hdr& hdr = *((const data_ack_hdr*) data);
                duration d = std::chrono::microseconds(uint32_t(now_us_wrap() - ntohl(hdr.timestamp)));
                m_send->on_ack(
                        seq_t(ntohl(hdr.ack)),
                        size_t(ntohl(hdr.window)),
                        (hdr.timestamp == 0 ? NULL : &d));
                return true;
        } else if (hdr.type == ptype::data) {
                if (size < sizeof(data_hdr)) {
                        return false;
                }
                if (size > sizeof(data_hdr) + MSS) {
                        return false;
                }
                size_t len = size - sizeof(data_hdr);
                const data_hdr& hdr = *((const data_hdr*) data);
                m_recv->on_packet(
                        seq_t(ntohl(hdr.seq)),
                        ntohl(hdr.timestamp),
                        data + sizeof(data_hdr),
                        len); 
		return true;
        }
	return false;
}

void conn::start_connect()
{
	m_socket = std::make_unique<tcp_socket>(m_mgr.m_tm.get_ios());
	m_socket->async_connect(tcp_endpoint(ip_address_v4::loopback(), m_mgr.m_tcp_port), 
		[this](const boost::system::error_code& error) { on_connect(error); });
	m_local_connect = m_mgr.m_tm.add(now() + 10_sec, [this]() {
		m_local_connect = 0;
		m_socket->cancel();
	});
};

void conn::on_connect(const boost::system::error_code& error)
{
	if (m_local_connect != 0) {
		m_mgr.m_tm.cancel(m_local_connect);
	}
	if (error) {
		m_state = state::time_wait;
		m_down_time = now_sec();
		return;
	}
	m_state = state::running;
	m_recv = std::make_unique<flow_recv>(m_mgr.m_tm, *m_socket, 
		[this](seq_t ack, size_t window, timestamp_t stamp) {
			send_ack(ack, window, stamp);
		});
	m_send = std::make_unique<flow_send>(m_mgr.m_tm, *m_socket, 
		[this](seq_t seq, const char* buf, size_t len) {
			send_seq(seq, buf, len);
		});
	m_keepalive = m_mgr.m_tm.add(now() + KEEP_ALIVE, [this]() { do_keepalive(); });
	while(!m_queue.empty()) {
		const pkt_queue_entry& entry = m_queue.front();
		process_packet(entry.hdr, entry.data, entry.len);
		m_queue.pop();
	}
}

conn_mgr::conn_mgr(timer_mgr& tm, udp_port& udp, uint16_t tcp_port, size_t goal_conns)
	: m_tm(tm)
	, m_udp(udp)
	, m_tcp_port(tcp_port)
	, m_goal_conns(std::max(goal_conns, size_t(4)))
	, m_max_conns(2*m_goal_conns)
{
        m_udp.add_protocol([this](const udp_endpoint& src, const char* buf, size_t len) -> bool {
		if (len >= sizeof(conn_hdr) && buf[0] == 'M') {
			on_packet(src, buf, len);
			return true;
		}
		return false;
        });
	RAND_bytes(m_secret, 16);
}

void conn_mgr::send_probe(const udp_endpoint& remote)
{
	auto it = m_state.find(remote);
	if (it != m_state.end() && it->second.m_state != conn::state::time_wait) {
		LOG_DEBUG("Not sending a probe, since I'm connected");
		return;
	}
        // Make space for headers
        conn_hdr& chdr = *((conn_hdr*) (m_send_buf));
	// Setup chdr
	chdr.type = ptype::probe;
	chdr.r_time = 0;
	chdr.r_token = 0;
	// Send packet
        LOG_DEBUG("Sending probe to %s", to_string(remote).c_str());
	send_packet(remote, sizeof(conn_hdr));
}

uint32_t conn_mgr::make_token(const udp_endpoint& who, uint32_t time) {
	// This doesn't need to be globally agreed on, it's a secret
	// hash, so I can change it, also, no need to correct endian
	unsigned char buf[20];
	std::string who_str = to_string(who);
	SHA_CTX ctx;
        SHA1_Init(&ctx);
        SHA1_Update(&ctx, m_secret, 16);
        SHA1_Update(&ctx, (const unsigned char *) who_str.c_str(), who_str.size());
        SHA1_Update(&ctx, (const unsigned char *) &time, sizeof(uint32_t));
        SHA1_Update(&ctx, m_secret, 16);
        SHA1_Final(buf, &ctx);
        return *((uint32_t*) buf);
}

void conn_mgr::send_packet(const udp_endpoint& dest, size_t len)
{
	conn_hdr& hdr = *((conn_hdr*) m_send_buf);
	hdr.magic = 'M';
	uint32_t now = now_sec();
	hdr.s_time = now & 0xff;
	hdr.s_token = make_token(dest, now);
	m_udp.send(dest, m_send_buf, len);
}

void conn_mgr::on_packet(const udp_endpoint& src, const char* buf, size_t len)
{
	const conn_hdr* hdr = (const conn_hdr*) buf;
	uint32_t r_time = now_sec();
	if (hdr->type == ptype::probe) {
		// No need to validate probes
		auto it = m_state.find(src);
		if (it == m_state.end() || 
			(it->second.m_state == conn::state::time_wait && it->second.m_down_time < r_time)) {
			// We are actually or logical down, respond
			LOG_DEBUG("Acking a probe");
			conn_hdr& rhdr = *((conn_hdr*) m_send_buf);
			rhdr.type = ptype::probe_ack;
			rhdr.r_time = hdr->s_time;
			rhdr.r_token = hdr->s_token;
			send_packet(src, sizeof(conn_hdr));
		} else {
			LOG_DEBUG("Ignoring a probe");
		}
		return;
	}
	// Otherwise validate token	
	if (hdr->r_time > (r_time & 0xff)) r_time -= 256;
	r_time = (r_time & 0xffffff00) | hdr->r_time;
	uint32_t token = make_token(src, r_time);
	if (token != hdr->r_token) {
		LOG_DEBUG("Got a junk packet, ignoring");
		return;
	}
	// Find or make state
	auto it = m_state.find(src);
	if (it == m_state.end()) {
		it = m_state.emplace(std::piecewise_construct, 
			std::forward_as_tuple(src),
			std::forward_as_tuple(*this, src, *hdr)).first;
	}
	if (it->second.m_state == conn::state::time_wait) {
		if (r_time <= it->second.m_down_time) {
			// Packet is from previous connection, ignore
			return;
		} else {
			it->second.reset(*hdr);
		}
	}
	// Give them the packet
	it->second.on_packet(*hdr, buf + sizeof(conn_hdr), len - sizeof(conn_hdr));
}

/*
int main() 
{
	g_log_level[LT_FLOW] = LL_DEBUG;
	g_log_level[LT_CONN] = LL_DEBUG;
        io_service ios;
	int listeners = 2;
	boost::asio::ip::tcp::acceptor l1 = {ios, tcp_endpoint(ip_address_v4::loopback(), 2000)};
	boost::asio::ip::tcp::acceptor l2 = {ios, tcp_endpoint(ip_address_v4::loopback(), 2001)};
	l1.listen();
	l2.listen();
	tcp_socket s1(ios);
	tcp_socket s2(ios);
	l1.async_accept(s1, [&](const boost::system::error_code& error) {
		if (error) {
			LOG_DEBUG("Accept error");
			exit(1);
		}
		LOG_DEBUG("GOT ACCEPT #1");
		listeners--;
		s1.send(boost::asio::buffer("Hello", 5));
	});
	l2.async_accept(s2, [&](const boost::system::error_code& error) {
		if (error) {
			LOG_DEBUG("Accept error");
			exit(1);
		}
		LOG_DEBUG("GOT ACCEPT #2");
		listeners--;
		s2.send(boost::asio::buffer("World", 5));
	});
	LOG_DEBUG("Listeners running");
        timer_mgr tm(ios);
        udp_port up1(ios, 5000);
        udp_port up2(ios, 5001);
	conn_mgr cm1(tm, up1, 2000);
	conn_mgr cm2(tm, up2, 2001);
	LOG_DEBUG("Connection managers running");
	cm1.send_probe(udp_endpoint(ip_address_v4::loopback(), 5001));
	LOG_DEBUG("Probe sent");
	ios.run();
}
*/

