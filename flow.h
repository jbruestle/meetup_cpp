
#include "time.h"
#include "udp.h"
#include <boost/operators.hpp>

typedef boost::asio::ip::tcp::socket tcp_socket;

// Timestamps are simple for now
typedef uint32_t timestamp_t;
// 32 bit sequence # that support wrapping
class seq_t 
	: boost::addable<seq_t, size_t>
	, boost::less_than_comparable<seq_t>
	, boost::equality_comparable<seq_t>
	, boost::equivalent<seq_t>
{
public:
	explicit seq_t(uint32_t x) : m_value(x) {}
	explicit operator uint32_t() const { return m_value; }
	seq_t& operator+=(size_t x) { m_value += x; return *this; }
	size_t operator-(const seq_t& rhs) const { return size_t(m_value - rhs.m_value); }
	bool operator<(const seq_t rhs) const {
		return uint32_t(rhs.m_value - m_value - 1) <= 0x7fffffff;
	}
private:
	uint32_t m_value;
};

static const duration ACK_DELAY = 20_msec;
static const duration MIN_RTO = 50_msec;
static const duration MAX_RTO = 1000_msec;
static const size_t WINDOW = 1024*1024;
static const size_t MSS = 1024;


class flow_recv 
{
public:
	typedef std::function<void (seq_t ack, size_t window, timestamp_t stamp)> send_func_t;
	flow_recv(timer_mgr& tm, tcp_socket& sink, const send_func_t& do_send);
	// Called when a packet arrives, returns true if true if we
	// need to generate an ACK immediately
	void on_packet(seq_t seq, timestamp_t stamp, const char* data, size_t len);
	// Check error code
	const boost::system::error_code& get_error() const { return m_err; }
private:
	// Start a write
	void start_write();	
	// Write complete
	void write_complete(const boost::system::error_code& err, size_t len);
	// Send an ACK now
	void send_now(timestamp_t stamp);
	// Set ACK timer
	void set_ack_timer();

	// Timers and sink
	timer_mgr& m_tm;
	tcp_socket& m_sink;
	// Where to send packets
	send_func_t m_do_send;
	// Is there a write currently pending
	bool m_write_pending;
	// Error state
	boost::system::error_code m_err;
	// Current ack seq number
	seq_t m_ack_seq;
	// Current 'head' of unwritten data
	seq_t m_head_seq;
	// Buffer of packets
	std::map<seq_t, std::string> m_pkt_buf;
	// ACK timer
	timer_id m_ack_timer;
};

class flow_send
{
public:
	typedef std::function<void (seq_t seq, const char* buf, size_t len)> send_func_t;
	// Make a new flow_send
	flow_send(timer_mgr& tm, tcp_socket& source, const send_func_t& do_send);
	// Called when an ACK packet arrives
	void on_ack(seq_t ack, size_t window, const duration* rtt);
	// Check error code
	const boost::system::error_code& get_error() const { return m_err; }
private:
	// Start a read
	void start_read();	
	// read complete
	void read_complete(const boost::system::error_code& err, size_t len);
	// Call to handle a hard timeout
	void on_timeout();
	// Start a timer if needed
	void start_timer();
	// Resend head packet
	void resend_head();
	// Compute size of in-flight ring buffer
	size_t flight_size();
	// Pops some bytes from in-flight
	void dequeue_in_flight(size_t len);
	// Push some data to in-flight
	void enqueue_in_flight(const char* buf, size_t len);
	// Get the first len bytes of in-flight
	void get_flight_head(char* out, size_t len);
	// Timers + source
	timer_mgr& m_tm;
	tcp_socket& m_source;
	// Where to send packets
	send_func_t m_do_send;
	// Is a read from source pending
	bool m_read_pending;
	// Error state
	boost::system::error_code m_err;
	// Highest sequence send + 1
	seq_t m_send_seq;
	// Highest sequence acked
	seq_t m_ack_seq;
	// Receiver window, based on ack_seq
	size_t m_window;
	// Congestion window, base on ack_seq
	size_t m_cwnd;
	// Slow start threshold
	size_t m_sst;
	// New-reno state
	size_t m_dup_acks;
	bool m_in_recover;
	seq_t m_recover_seq;
	// Round trip data in microseconds
	duration m_rtt_avg;
	duration m_rtt_dev;
	duration m_rto;
	// RTO timer
	timer_id m_send_timer;
	// Buffer of in flight packets
	char *m_in_flight;
	uint32_t m_fhead;
	uint32_t m_ftail;
	// Read + write buffers for packets
	char m_read_buf[MSS];
	char m_resend_buf[MSS];
};

class udp_flow_mgr
{
public:
	udp_flow_mgr(timer_mgr& mgr, udp_port& udp, tcp_socket& tcp, endpoint remote);
private:
	bool on_packet(const char* buffer, size_t size);
	void send_ack(seq_t ack, size_t window, timestamp_t stamp);
	void send_seq(seq_t seq, const char* buf, size_t len);
	timer_mgr& m_tm;
	udp_port& m_udp;
	tcp_socket& m_tcp;
	endpoint m_remote;
	flow_send m_send;
	flow_recv m_recv;
};
	
