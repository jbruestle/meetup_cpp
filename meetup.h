
#include "dht.h"

class meetup
{
public:
	meetup(const std::string& where, uint16_t local_port);
	void run(); 

private:
	void on_dht_state(bool what);
	void connect_timer();
	void inbound_timer();
	udp_endpoint pick_random(const std::map<udp_endpoint, int>& peers);

	std::string m_where;
	io_service m_ios;
	timer_mgr m_tm;
	udp_port m_udp;
	dht m_dht;
	size_t m_group_qid;
	size_t m_incoming_qid;
	udp_endpoint m_outgoing_addr;
	size_t m_outgoing_qid;
	hash_id m_where_id;
	timer_id m_connect_timer;
	timer_id m_inbound_timer;
};
