
#include "conn.h"
#include "log.h"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/sha.h>
#include <openssl/rand.h>

#define LOG_TOPIC LT_CONN

static const duration REMOTE_CONN_TIME = 30_sec;
static const duration LOCAL_CONN_TIME = 5_sec;
static const duration SEND_KEEPALIVE_TIME = 5_sec;
static const duration RECV_KEEPALIVE_TIME = 7 * SEND_KEEPALIVE_TIME / 2; 

conn::conn(conn_mgr& mgr, const udp_endpoint& who, uint32_t s_time, uint32_t s_token) 
	: m_mgr(mgr)
	, m_who(who)
	, m_state(state::outbound)
	, m_r_time(0)
	, m_r_token(0)
	, m_s_time(s_time)
	, m_s_token(s_token)
	, m_send_keep_alive(0)
{
	// Arm expiration
	m_timer = m_mgr.m_tm.add(time_from_sec(s_time) + REMOTE_CONN_TIME, [this]() { on_timeout(); });
}

void conn::start_connect(uint8_t time, uint32_t token)
{
	assert(m_state == state::outbound);
	LOG_INFO("Connecting to localhost");
	// Disarm remote connect, arm local connect
	m_mgr.m_tm.cancel(m_timer);
	m_timer = m_mgr.m_tm.add(now() + LOCAL_CONN_TIME, [this]() { on_timeout(); });
	// Update state
	m_state = state::starting;
	m_r_time = time;
	m_r_token = token;
	// Kick off socket connect
	m_socket = std::make_unique<tcp_socket>(m_mgr.m_tm.get_ios());
	m_socket->async_connect(tcp_endpoint(ip_address_v4::loopback(), m_mgr.m_tcp_port), 
		[this](const error_code& error) { on_connect(error); });
}

void conn::on_packet(const conn_hdr &hdr, const char* data, size_t len)
{
	// Only should get data in two states
	assert(m_state == state::starting || m_state == state::running);

	// Push back keepalive timer
	m_mgr.m_tm.cancel(m_timer);
	m_timer = m_mgr.m_tm.add(now() + RECV_KEEPALIVE_TIME, [this]() { on_timeout(); });
	if (hdr.type != ptype::data && hdr.type != ptype::data_ack) {
		if (hdr.type != ptype::final_ack) {
			LOG_WARN("Ignore strange packet from %s", to_string(m_who).c_str());
		}
		return;
	}
	// If we don't yet have a local connection, queue it up
	if (m_state == state::starting) {
		LOG_INFO("Still connecting, queueing packet from %s", to_string(m_who).c_str());
		m_queue.emplace(hdr, data, len);
		if (m_queue.size() > 5) {
			m_queue.pop();
		}
		return;
	}
	// Process packet
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

void conn::setup_chdr(conn_hdr& hdr)
{
	// Helper to stamp state onto chdr
	hdr.s_time = m_s_time & 0xff;
	hdr.s_token = m_s_token;
	hdr.r_time = m_r_time;
	hdr.r_token = m_r_token;
}

void conn::send_seq(seq_t seq, const char* buf, size_t len)
{
	// Push back keep alive send
	m_mgr.m_tm.cancel(m_send_keep_alive);
	m_send_keep_alive = m_mgr.m_tm.add(now() + SEND_KEEPALIVE_TIME, [this]() { send_keep_alive(); });
	// Make space for headers
	conn_hdr& chdr = *((conn_hdr*) (m_mgr.m_send_buf));
	data_hdr& dhdr = *((data_hdr*) (m_mgr.m_send_buf + sizeof(conn_hdr)));
	char* data = m_mgr.m_send_buf + sizeof(conn_hdr) + sizeof(data_hdr);
	assert(sizeof(conn_hdr) + sizeof(data_hdr) + len < 2048);
	// Setup chdr
	chdr.type = ptype::data;
	setup_chdr(chdr);
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
	// Push back keep alive send
	m_mgr.m_tm.cancel(m_send_keep_alive);
	m_send_keep_alive = m_mgr.m_tm.add(now() + SEND_KEEPALIVE_TIME, [this]() { send_keep_alive(); });
	// Make space for headers
	conn_hdr& chdr = *((conn_hdr*) (m_mgr.m_send_buf));
	data_ack_hdr& dhdr = *((data_ack_hdr*) (m_mgr.m_send_buf + sizeof(conn_hdr)));
	// Setup chdr
	chdr.type = ptype::data_ack;
	setup_chdr(chdr);
	// Setup dhdr
	dhdr.ack = htonl(uint32_t(ack));
	dhdr.window = htonl(uint32_t(window));
	dhdr.timestamp = htonl(uint32_t(stamp));
	LOG_DEBUG("send ACK (%u, %u, %u)", uint32_t(ack), uint32_t(window), uint32_t(stamp));
	m_mgr.send_packet(m_who, sizeof(conn_hdr) + sizeof(data_ack_hdr));
}

void conn::send_keep_alive()
{
	// Make space for headers
	conn_hdr& chdr = *((conn_hdr*) (m_mgr.m_send_buf));
	// Setup chdr
	chdr.type = ptype::final_ack;
	setup_chdr(chdr);
	// Send packet + reschedule
	LOG_INFO("Sending keepalive to %s", to_string(m_who).c_str());
	m_mgr.send_packet(m_who, sizeof(conn_hdr));
	m_send_keep_alive = m_mgr.m_tm.add(now() + SEND_KEEPALIVE_TIME, [this]() { send_keep_alive(); });
}

void conn::on_timeout()
{
	LOG_INFO("Timeout with state = %d", m_state);
	if (m_state == state::outbound || m_state == state::time_wait) {
		// Delete myself
		m_mgr.m_state.erase(m_who);
	} else {
		// Kick off destruction
		m_socket->close();
	}
}

void conn::socket_error(const error_code& error)
{
	LOG_INFO("Socket error on %s: %s", to_string(m_who).c_str(), error.message().c_str());
	assert(m_state == state::running);
	if (!m_recv->stop()) {
		return; // Will be called again soon
	}
	if (!m_send->stop()) {
		return; // Will be called again soon
	}
	LOG_INFO("Changing state to time_wait");
	// Cancel sending of keep alive
	m_mgr.m_tm.cancel(m_send_keep_alive);
	// Cancel per state timer
	m_mgr.m_tm.cancel(m_timer);
	// Erase send and receive + socket
	m_recv.reset();
	m_send.reset();
	m_socket.reset();
	// Go to time wait
	go_time_wait();
}

bool conn::process_packet(const conn_hdr &hdr, const char* data, size_t size)
{
	assert(m_state == state::running);
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

void conn::on_connect(const error_code& error)
{
	m_mgr.m_tm.cancel(m_timer);
	if (error) {
		LOG_INFO("Connection to localhost failed: %s", error.message().c_str());
		go_time_wait();
		return;
	}
	LOG_INFO("Connection to localhost up");
	m_state = state::running;
	m_recv = std::make_unique<flow_recv>(m_mgr.m_tm, *m_socket, 
		[this](seq_t ack, size_t window, timestamp_t stamp) {
			send_ack(ack, window, stamp);
		},
		[this](const error_code& err) { socket_error(err); });
	m_send = std::make_unique<flow_send>(m_mgr.m_tm, *m_socket, 
		[this](seq_t seq, const char* buf, size_t len) {
			send_seq(seq, buf, len);
		},
		[this](const error_code& err) { socket_error(err); });
	m_timer = m_mgr.m_tm.add(now() + RECV_KEEPALIVE_TIME, [this]() { on_timeout(); });
	m_send_keep_alive = m_mgr.m_tm.add(now() + SEND_KEEPALIVE_TIME, [this]() { send_keep_alive(); });
	while(!m_queue.empty()) {
		const pkt_queue_entry& entry = m_queue.front();
		process_packet(entry.hdr, entry.data, entry.len);
		m_queue.pop();
	}
}

void conn::go_time_wait()
{
	// If I need to wait, do the time wait thing
	time_point tp_wait = time_from_sec(m_s_time) + REMOTE_CONN_TIME;
	if (now() <= tp_wait) {
		m_state = state::time_wait;
		m_timer = m_mgr.m_tm.add(tp_wait, [this]() { on_timeout(); });
	} else {
		// Delete myself
		m_mgr.m_state.erase(m_who);
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

bool conn_mgr::has_conn(const udp_endpoint& remote)
{
	// TODO: Who calls this, does this mean what we thing?
	auto it = m_state.find(remote);
	if (it != m_state.end() && it->second.m_state != conn::state::time_wait) {
		return true;
	}
	return false;
}

void conn_mgr::send_probe(const udp_endpoint& remote)
{
	auto it = m_state.find(remote);
	if (it == m_state.end()) {
		// Make a new 'outgoing' state if needed
		uint32_t s_time = now_sec();
		uint32_t s_token = make_token(remote, s_time);
		it = m_state.emplace(std::piecewise_construct, 
			std::forward_as_tuple(remote),
			std::forward_as_tuple(*this, remote, s_time, s_token)).first;
	}
	// Make space for headers
	conn_hdr& chdr = *((conn_hdr*) (m_send_buf));
	// Setup chdr
	chdr.type = ptype::probe;
	it->second.setup_chdr(chdr);
	LOG_INFO("Sending probe to %s", to_string(remote).c_str());
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
	m_udp.send(dest, m_send_buf, len);
}

void conn_mgr::on_packet(const udp_endpoint& src, const char* buf, size_t len)
{
	const conn_hdr* hdr = (const conn_hdr*) buf;
	uint32_t r_time = now_sec();
	auto it = m_state.find(src);

	// Handle probe case
	if (hdr->type == ptype::probe) {
		if (it == m_state.end() || it->second.m_state == conn::state::outbound) {
			// Respond with a valid token
			LOG_INFO("Probe from %s, ACKing", to_string(src).c_str());
			conn_hdr& rhdr = *((conn_hdr*) m_send_buf);
			rhdr.type = ptype::probe_ack;
			rhdr.r_time = hdr->s_time;
			rhdr.r_token = hdr->s_token;
			if (it != m_state.end()) {
				rhdr.s_time = it->second.m_s_time & 0xff;
				rhdr.s_time = it->second.m_s_token;
			} else {
				rhdr.s_time = r_time & 0xff;
				rhdr.s_token = make_token(src, r_time);
			}
			send_packet(src, sizeof(conn_hdr));
		} else {
			LOG_INFO("Probe from %s, Ignoring", to_string(src).c_str());
		}
		return;
	}
	// Handle final-ack construction case
	if (it == m_state.end() && hdr->type == ptype::final_ack) {
		// No current state, if valid, start connection
		if (hdr->r_time > (r_time & 0xff)) r_time -= 256;
		r_time = (r_time & 0xffffff00) | hdr->r_time;
		uint32_t token = make_token(src, r_time);
		if (token != hdr->r_token) {
			LOG_INFO("From %s: Invalid token for probe_ack", to_string(src).c_str());
			return;
		}
		LOG_INFO("From %s: Valid final_ack for forgotten probe_ack", to_string(src).c_str());
		// Brings us to 'outgoing' state
		it = m_state.emplace(std::piecewise_construct, 
			std::forward_as_tuple(src),
			std::forward_as_tuple(*this, src, r_time, hdr->r_token)).first;
	}
	if (it == m_state.end()) {
		LOG_INFO("From %s: Ignoring everything but probe/final-ack for empty state", to_string(src).c_str());
		return;
	}
	if (hdr->type == ptype::probe_ack || hdr->type == ptype::final_ack) {
		// If not a valid response based on outgoing, bail right away
		if (hdr->r_time != (it->second.m_s_time & 0xff) || 
			hdr->r_token != it->second.m_s_token) {
			LOG_INFO("From %s: Invalid local token for probe_ack", to_string(src).c_str());
			return;
		}
		// Ok, move outgoing connections forward to starting
		if (it->second.m_state == conn::state::outbound) {
			it->second.start_connect(hdr->s_time, hdr->s_token);
		}
		// Make sure we are not in time wait
		if (it->second.m_state == conn::state::time_wait) {
			LOG_INFO("From %s: Ignoring probe-ack while in time_wait", to_string(src).c_str());
			return;
		}
		// If not valid remote tokens, bail
		if (hdr->s_time != it->second.m_r_time ||
			hdr->s_token != it->second.m_r_token) {
			LOG_INFO("From %s: Invalid remote token for probe_ack", to_string(src).c_str());
			return;
		}
		if (hdr->type == ptype::probe_ack) {
			// Maybe Send final ack
			LOG_INFO("From %s: Got probe ack, sending final_ack", to_string(src).c_str());
			conn_hdr& rhdr = *((conn_hdr*) m_send_buf);
			rhdr.type = ptype::final_ack;
			it->second.setup_chdr(rhdr);
			send_packet(src, sizeof(conn_hdr));
			return;
		}
		LOG_INFO("From %s: Got final ack", to_string(src).c_str());
		// Fall through to on packet to allow keepalive to conn
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
	l1.async_accept(s1, [&](const error_code& error) {
		if (error) {
			LOG_DEBUG("Accept error");
			exit(1);
		}
		LOG_DEBUG("GOT ACCEPT #1");
		listeners--;
		s1.send(boost::asio::buffer("Hello", 5));
	});
	l2.async_accept(s2, [&](const error_code& error) {
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
	for(size_t i = 0; i < 3; i++) {	
		tm.add(now() + 5_sec*i, [&]() {
			cm1.send_probe(udp_endpoint(ip_address_v4::loopback(), 5001));
		});
	}
	LOG_DEBUG("Probe sent");
	ios.run();
}
*/

