
#pragma once

#include "udp.h"
#include "time.h"
#include "flow.h"
#include <queue>

enum class ptype : char
{
	probe = 0,
	probe_ack = 1,
	data = 2,
	data_ack = 3,
};

struct __attribute__ ((__packed__)) conn_hdr 
{ 
	char magic;
	ptype type;
	uint8_t s_time;
	uint8_t r_time;
	uint32_t s_token;
	uint32_t r_token;
};

class conn_mgr; 

class conn
{
	friend class conn_mgr;
public:
	// Constructor public to make emplace work
	conn(conn_mgr& mgr, const udp_endpoint& who, const conn_hdr& hdr);

private:
	void reset(const conn_hdr& hdr);
	void on_packet(const conn_hdr &hdr, const char* data, size_t len);
	void send_seq(seq_t seq, const char* buf, size_t len);
	void send_ack(seq_t ack, size_t window, timestamp_t stamp);
	void do_keep_alive();
	void do_kill_remote();
	void socket_error(const error_code& error);
	bool process_packet(const conn_hdr &hdr, const char* data, size_t len);
	void start_connect();
	void on_connect(const error_code& error);

	enum class state {
		starting,
		running,
		time_wait,
	};

	struct pkt_queue_entry {
		pkt_queue_entry(const conn_hdr &_hdr, const char* _data, size_t _len) 
			: hdr(_hdr)
			, data(new char[_len])
			, len(_len)
		{
			memcpy(data, _data, len);
		}
		~pkt_queue_entry() { delete data; }
		conn_hdr hdr;
		char* data;
		size_t len;
	};

	conn_mgr& m_mgr;
	udp_endpoint m_who;
	state m_state;
	uint8_t m_time;
	uint32_t m_token;
	uint32_t m_down_time;
	timer_id m_local_connect;
	timer_id m_keep_alive;
	timer_id m_kill_remote;
	int m_num_up;
	std::unique_ptr<tcp_socket> m_socket;
	std::unique_ptr<flow_recv> m_recv;
	std::unique_ptr<flow_send> m_send;
	std::queue<pkt_queue_entry> m_queue;
};

class conn_mgr
{
	friend class conn;
public:
	conn_mgr(timer_mgr& tm, udp_port& udp, uint16_t tcp_port, size_t goal_conns = 8);
	void send_probe(const udp_endpoint& remote);

private:
	uint32_t make_token(const udp_endpoint& who, uint32_t time);
	void send_packet(const udp_endpoint& dest, size_t len);
	void on_packet(const udp_endpoint& src, const char* buf, size_t len);

	timer_mgr& m_tm;
	udp_port& m_udp;
	uint16_t m_tcp_port;
	size_t m_goal_conns;
	size_t m_max_conns;
	size_t m_cur_conns;
	std::map<udp_endpoint, conn> m_state;
	unsigned char m_secret[16];
	char m_send_buf[2048];
};
