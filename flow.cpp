
#include "flow.h"
#include "time.h"
#include <stdio.h>

#define LOG_TOPIC LT_FLOW

flow_recv::flow_recv(timer_mgr& tm, tcp_socket& sink, const send_func_t& do_send)
	: m_tm(tm)
	, m_sink(sink)
	, m_do_send(do_send)
	, m_write_pending(false)
	, m_ack_seq(0)
	, m_head_seq(0)
	, m_ack_timer(0)
{
	
}

void flow_recv::on_packet(seq_t seq, timestamp_t stamp, const char* data, size_t len)
{
	LOG_DEBUG("recv SEQ(%u, %u, %u)", uint32_t(seq), uint32_t(len), uint32_t(stamp)); 
	// Validate packet is sensible, ignore if not
	if (seq + len <= m_ack_seq ||  // Data is too old
		seq > m_head_seq + WINDOW) { // Data is too new
		// Send an ACK with current numbers + early exit
		LOG_DEBUG("   data out of range, ACKING");
		send_now(stamp);
		return;
	}
	// Determine if we are out of order
	bool ooo = (seq != m_ack_seq);
	// Add data to buffer
	m_pkt_buf[seq] = std::string(data, len);
	// See if we can move ack forward
	if (seq <= m_ack_seq) {
		// Must have some new data, since seq + len > ack and seq <= ack
		for(auto it = m_pkt_buf.lower_bound(seq); it != m_pkt_buf.end(); ++it) {
			// If we are past the area of relevance, stop 
			if (it->first > m_ack_seq) {
				break;
			}
			// Otherwise, maybe extend ack
			m_ack_seq = std::max(m_ack_seq, it->first + it->second.size());
		}
	}
	LOG_DEBUG("   ooo = %d, seq = %u, ack_seq = %u", ooo, uint32_t(seq), uint32_t(m_ack_seq));
	// Try to write data fast if not already pending
	if (m_head_seq < m_ack_seq && !m_write_pending) {
		start_write();
	}
	// Decide if we want to ack this packet
	if (m_ack_timer || ooo) {
		LOG_DEBUG("   sending ACK");
		send_now(stamp);
	} else {
		LOG_DEBUG("   setting timer");
		set_ack_timer();
	}
}

void flow_recv::start_write()
{
	if (m_err) {
		return; 
	}
	// Find the earliest
	auto it = m_pkt_buf.begin();
	// While it's before head, pop it
	while(it->first + it->second.size() <= m_head_seq) {
		m_pkt_buf.erase(it);
		it = m_pkt_buf.begin();
	}
	// Try to write some data, skipping first part if needed
	size_t skip = m_head_seq - it->first;
	const char* buf = it->second.data() + skip;
	size_t len = it->second.size() - skip;
	// Write it out
	LOG_DEBUG("   starting write: head_seq = %u, len = %u", uint32_t(m_head_seq), uint32_t(len));
	m_write_pending = true;
	m_sink.async_write_some(boost::asio::buffer(buf, len),
		[this](const error_code& err, size_t len) {
			write_complete(err, len);
		}
	);
}

void flow_recv::write_complete(const error_code& err, size_t len)
{
	m_write_pending = false;
	if (err) {
		LOG_WARN("TODO: write errored: err = %s", err.message().c_str());
		m_err = err;
		exit(1);
		return;
	}
	LOG_DEBUG("write complete: head_seq = %u, len = %u", uint32_t(m_head_seq), uint32_t(len));
	m_head_seq += len;
	if (m_head_seq < m_ack_seq) {
		start_write();
	}
}

void flow_recv::send_now(timestamp_t stamp) 
{
	if (m_ack_timer) {
		m_tm.cancel(m_ack_timer);
	}
	m_do_send(m_ack_seq, m_head_seq + WINDOW - m_ack_seq, stamp);
}

void flow_recv::set_ack_timer() 
{
	m_ack_timer = m_tm.add(now() + ACK_DELAY, [this]() { 
		m_ack_timer = 0;
		send_now(timestamp_t()); 
	});
}

flow_send::flow_send(timer_mgr& tm, tcp_socket& source, const send_func_t& do_send)
	: m_tm(tm)
	, m_source(source)
	, m_do_send(do_send)
	, m_read_pending(false)
	, m_send_seq(0)
	, m_ack_seq(0)
	, m_window(WINDOW)
	, m_cwnd(2*MSS)
	, m_sst(WINDOW)
	, m_dup_acks(0)
	, m_in_recover(false)
	, m_recover_seq(0)
	, m_rtt_avg(MAX_RTO)
	, m_rtt_dev(MAX_RTO)
	, m_rto(MAX_RTO)
	, m_send_timer(0)
	, m_in_flight(new char[WINDOW + 1])
	, m_fhead(0)
	, m_ftail(0)
{
	start_read();
}

void flow_send::on_ack(seq_t ack, size_t window, const duration* rtt)
{
	LOG_DEBUG("recv ACK (%u, %u)", uint32_t(ack), uint32_t(window));
	LOG_DEBUG("    cwnd = %u, sst = %u", uint32_t(m_cwnd), uint32_t(m_sst));
	if (rtt != NULL) {
		m_rtt_avg = m_rtt_avg * 7 / 8 + *rtt / 8;
		duration rtt_err = *rtt - m_rtt_avg;
		if (rtt_err < duration(0)) {
			rtt_err = -rtt_err;
		}
        	m_rtt_dev = m_rtt_dev * 7 / 8 + rtt_err / 8;
	}
	if (ack > m_send_seq) {
		// Hmm, TODO: examine this edge case more carefully
		LOG_DEBUG("    ACK seq is from the future");
		ack = m_send_seq;
	}
	if (ack < m_ack_seq) {
		// Ack is old, ignore
		LOG_DEBUG("    Ignoring old ACK");
		return;
	}
	if (ack == m_ack_seq) {
		// Ack is a dup
		LOG_DEBUG("    ACK is a DUP");
		m_dup_acks++;
		if (!m_in_recover && m_dup_acks == 3) {
			// Start fast recovery
			m_sst = std::max(flight_size()/2, 2*MSS);
			m_cwnd = m_sst + 3*MSS;
			m_recover_seq = m_send_seq;
			m_in_recover = true;
			LOG_DEBUG("    Entering recovery mode, sst = %u, cwnd = %u, flight_size = %u", 
				uint32_t(m_sst), uint32_t(m_cwnd), uint32_t(flight_size()));
			// Resend packet
			resend_head();
		} else if (m_in_recover) {
			m_cwnd += MSS;
			start_read();
		}
		return;
	}			
	// New ACK
	LOG_DEBUG("    ACK is new");
	m_dup_acks = 0;
	dequeue_in_flight(ack - m_ack_seq);
	// Cancel any timers + restart based on now
	if (m_send_timer) {
		m_tm.cancel(m_send_timer);
		m_send_timer = 0;
	}
	m_rto = m_rtt_avg + 2 * m_rtt_dev;
	// Handle recovery mode
	if (m_in_recover) {
		LOG_DEBUG("    In recovery mode");
		// Are we still in recover mode
		if (ack < m_recover_seq) {
			// Yes, adjust cwnd
			m_cwnd += MSS;
			m_cwnd -= (ack - m_ack_seq);
			m_ack_seq = ack;
			// Resend packet
			resend_head();
			start_timer();
			return;
		} else {
			m_cwnd = std::min(m_sst, flight_size() + MSS);
			m_in_recover = false;
		}
	}
	// Update congestion window
	LOG_DEBUG("    Updating ack seq");
	m_ack_seq = ack;
	m_window = window;
	if (m_cwnd < m_sst) {
		m_cwnd += MSS;
	} else {
		m_cwnd += std::max(size_t(1), MSS*MSS/m_cwnd);
	}
	start_timer();
	start_read();					
}

void flow_send::start_read()
{
	if (m_read_pending) {
		return; // Read already pending
	}
	if (m_err) {
		return; // Got an error, done
	}
	if (std::min(m_cwnd, m_window) < m_send_seq - m_ack_seq + MSS) {
		return; // No room in window
	}
	m_read_pending = true;
	m_source.async_read_some(boost::asio::buffer(m_read_buf, MSS), 
		[this](const error_code& err, size_t len) {
			read_complete(err, len);
		});
}

void flow_send::read_complete(const error_code& err, size_t len)
{
	m_read_pending = false;
	if (err) {
		m_err = err;
                LOG_WARN("TODO: read errored: err = %s", err.message().c_str());
		exit(1);
                return;
        }
	enqueue_in_flight(m_read_buf, len);
	start_timer();
	m_do_send(m_send_seq, m_read_buf, len);
	m_send_seq += len;
	start_read();
}

void flow_send::on_timeout()
{
	LOG_DEBUG("send timeout");
	m_send_timer = 0;
	// Update flow control goo
	m_sst = std::max(2*MSS, flight_size()/2);
	m_cwnd = 2*MSS;
	m_rto *= 2;
	// Resend the packet + restart timer
	resend_head();
	start_timer();
}

void flow_send::start_timer()
{
	if (m_send_timer) {
		return;
	}
	if (m_rto < MIN_RTO) {
		m_rto = MIN_RTO;
	}
	if (m_rto > MAX_RTO) {
		m_rto = MAX_RTO;
	}
	if (m_send_seq != m_ack_seq) {
		LOG_DEBUG("adding timer, %u ms from now", uint32_t(
			std::chrono::duration_cast<std::chrono::milliseconds>(m_rto).count()));
		m_send_timer = m_tm.add(now() + m_rto, [this]() { on_timeout(); });
	}
}

void flow_send::resend_head()
{
	size_t len = std::min(MSS, flight_size());
	get_flight_head(m_resend_buf, len); 
	m_do_send(m_ack_seq, m_resend_buf, len);
}

size_t flow_send::flight_size()
{
	if (m_ftail >= m_fhead) {
		return m_ftail - m_fhead;
	} else {
		return m_ftail + 1 + WINDOW - m_fhead;
	}
}

void flow_send::dequeue_in_flight(size_t len)
{
	m_fhead += len;
	m_fhead %= (WINDOW + 1);
}

void flow_send::enqueue_in_flight(const char* buf, size_t len)
{
	size_t fp = std::min(len, 1 + WINDOW - m_ftail);
	memcpy(m_in_flight + m_ftail, buf, fp);
	if (fp != len) {
		memcpy(m_in_flight, buf + fp, len - fp);
	}
	m_ftail += len;
	m_ftail %= (WINDOW + 1);
}

void flow_send::get_flight_head(char* buf, size_t len)
{
	size_t fp = std::min(len, 1 + WINDOW - m_fhead);
	memcpy(buf, m_in_flight + m_fhead, fp);
	if (fp != len) {
		memcpy(buf + fp, m_in_flight, len - fp);
	}
}

udp_flow_mgr::udp_flow_mgr(timer_mgr& tm, udp_port& udp, tcp_socket& tcp, udp_endpoint remote)
	: m_tm(tm)
	, m_udp(udp)
	, m_tcp(tcp)
	, m_remote(remote)
	, m_send(tm, tcp, [this](seq_t seq, const char* buf, size_t len) { send_seq(seq, buf, len); })
	, m_recv(tm, tcp, [this](seq_t ack, size_t window, timestamp_t stamp) { send_ack(ack, window, stamp); }) 
{
	m_udp.add_protocol([this, remote](const udp_endpoint& src, const char* buf, size_t len) -> bool {
		if (src != remote) {
			LOG_DEBUG("Invalid remote address");
			return false;
		}
		return on_packet(buf, len);
	});
	do_keepalive();
}

struct ack_header {
	uint32_t type;
	uint32_t ack;
	uint32_t window;
	uint32_t timestamp;
};

struct seq_header {
	uint32_t type;
	uint32_t seq;
	uint32_t timestamp; 
};

void udp_flow_mgr::send_ack(seq_t ack, size_t window, timestamp_t stamp)
{
	// Push back keepalive
	m_tm.cancel(m_keepalive);
	m_keepalive = m_tm.add(now() + KEEP_ALIVE, [this]() { do_keepalive(); });
	// Send ack
	ack_header hdr;
	hdr.type = htonl(0);
	hdr.ack = htonl(uint32_t(ack));
	hdr.window = htonl(uint32_t(window));
	hdr.timestamp = htonl(uint32_t(stamp));
	LOG_DEBUG("send ACK (%u, %u, %u)", uint32_t(ack), uint32_t(window), uint32_t(stamp));
	m_udp.send(m_remote, (const char*) &hdr, sizeof(hdr));
}

void udp_flow_mgr::send_seq(seq_t seq, const char* buf, size_t len)
{
	// Push back keepalive
	m_tm.cancel(m_keepalive);
	m_keepalive = m_tm.add(now() + KEEP_ALIVE, [this]() { do_keepalive(); });
	// TODO: Fix pointless memcpy here
	char pbuf[sizeof(seq_header) + MSS];
	seq_header& hdr = *((seq_header*) pbuf);
	hdr.type = htonl(1);
	hdr.seq = htonl(uint32_t(seq));
	hdr.timestamp = htonl(now_us_wrap());
	if (hdr.timestamp == 0) { hdr.timestamp = htonl(1); }
	memcpy(pbuf + sizeof(seq_header), buf, len);
	LOG_DEBUG("send SEQ (%u, %u, %u)", uint32_t(seq), uint32_t(len), htonl(hdr.timestamp));
	m_udp.send(m_remote, pbuf, sizeof(hdr) + len);
}

bool udp_flow_mgr::on_packet(const char* buffer, size_t size)
{
	static int count = 0;
	//if (count++ > 5) { exit(1); }
	if (size < 4) {
		return false;
	}
	uint32_t type = ntohl(*((const uint32_t*) buffer));
	if (type == 0) {
		if (size < sizeof(ack_header)) {
			return false;
		}
		const ack_header& hdr = *((const ack_header*) buffer);
		duration d = std::chrono::microseconds(uint32_t(now_us_wrap() - ntohl(hdr.timestamp)));
		m_send.on_ack(
			seq_t(ntohl(hdr.ack)),
			size_t(ntohl(hdr.window)),
			(hdr.timestamp == 0 ? NULL : &d));
		return true;
	} else if (type == 1) {
		if (size < sizeof(seq_header)) {
			return false;
		}
		if (size > sizeof(seq_header) + MSS) {
			return false;
		}
		size_t len = size - sizeof(seq_header);
		const seq_header& hdr = *((const seq_header*) buffer);
		m_recv.on_packet(
			seq_t(ntohl(hdr.seq)),
			ntohl(hdr.timestamp),
			buffer + sizeof(seq_header),
			len);	
	}
	return false;
}

void udp_flow_mgr::do_keepalive() {
	LOG_DEBUG("Sending keepalive");
	m_udp.send(m_remote, "KEEP", 4);
	m_keepalive =m_tm.add(now() + KEEP_ALIVE, [this]() { do_keepalive(); });
}

/*
int main(int argc, char* argv[]) {
	try {
		if (argc != 5) {
			fprintf(stderr, "Usage: <tcp_port> <upd_port> <remote_host> <remote_port>\n");
			return 1;
		}
		io_service ios;

		tcp_endpoint tcp_ep = tcp_resolve(ios, "127.0.0.1", argv[1]);
		udp_endpoint udp_ep = udp_resolve(ios, argv[3], argv[4]);
		boost::asio::ip::tcp::socket tcp(ios);
		tcp.connect(tcp_ep);

		timer_mgr tm(ios); 
		udp_port udp(ios, atoi(argv[2]));
		udp_flow_mgr fm(tm, udp, tcp, udp_ep);
		ios.run();
	}	
	catch (std::exception& e) {
		fprintf(stderr, "Exception: %s\n", e.what());
	}
}
*/
