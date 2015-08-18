
#include "dht.h"
#include "stun.h"
#include "conn.h"

class meetup
{
public:
	meetup(const std::string& where, uint16_t local_port);
	void run(); 

private:
	void on_stun_state(stun_mgr::stun_state s, const udp_endpoint& ep);
	void connect_timer();
	void inbound_timer();
	udp_endpoint pick_random(const std::map<udp_endpoint, int>& peers, bool remove_recent);

	std::string m_where;
	io_service m_ios;
	timer_mgr m_tm;
	udp_port m_udp;
	stun_mgr m_stun;
	dht m_dht;
	size_t m_group_qid;
	size_t m_incoming_qid;
	udp_endpoint m_outgoing_addr;
	size_t m_outgoing_qid;
	hash_id m_where_id;
	timer_id m_connect_timer;
	timer_id m_inbound_timer;
	conn_mgr m_conn_mgr;
	std::map<udp_endpoint, time_point> m_recent;
};
