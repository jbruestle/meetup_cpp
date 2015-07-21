
#pragma once

#include "udp.h"
#include "time.h"
#include "bencode.h"

class dht_rpc
{
public:
	typedef std::function<void (const bencode_t&)> success_handler_t;
	typedef std::function<void ()> failure_handler_t;
	typedef std::function<bencode_t (const bencode_t&)> query_handler_t;
	dht_rpc(timer_mgr& tm, udp_port& udp);
	void send_request(const endpoint& who, const std::string& rtype, const bencode_t& args, 
		const success_handler_t& on_success, const failure_handler_t& on_failure);
private:
	bool on_incoming(const endpoint& who, const char* buf, size_t len);
	void on_query(const endpoint& who, be_map& query);
	void on_response(const endpoint& who, const std::string& type, be_map& resp);
	void on_timeout(timer_id tid);
	timer_mgr& m_tm;
	udp_port& m_udp;
	uint16_t m_next_tid;
	struct pending_t {
		success_handler_t on_success;
		failure_handler_t on_failure;
		timer_id timer;
	};
	std::map<uint16_t, pending_t> m_pending;
};


