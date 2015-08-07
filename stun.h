#pragma once

#include "udp.h"
#include "time.h"

class stun_mgr
{
public:
	enum stun_state { state_down, state_cone, state_symmetric };
	typedef std::function<void(stun_state, const udp_endpoint&)> state_handler_t;
	// Call handler when state changes
	stun_mgr(timer_mgr& tm, udp_port& udp, const state_handler_t& handler);

private:
	void send_packet();
	void resolve_done(const error_code& ec, udp_resolver::iterator it);
	void on_incoming(const udp_endpoint& who, const char* buf, size_t len);
	void on_timeout();
	void process_samples();
	
	timer_mgr& m_tm;
	udp_port& m_udp;
	state_handler_t m_handler;
	stun_state m_state;
	udp_endpoint m_external;
	udp_resolver m_resolver;
	uint8_t m_tx_id[12];
	timer_id m_timeout;
	size_t m_next_server;
	size_t m_error_count;
	std::vector<udp_endpoint> m_samples;
};

