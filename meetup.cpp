
#include "meetup.h"

static const auto k_group_publish_rate = 1_min;
static const auto k_incoming_dht_rate = 5_sec;
static const auto k_connect_out_rate = 3_sec;
static const auto k_incoming_hello_rate = 3_sec;

#define LOG_TOPIC LT_MAIN

meetup::meetup(const std::string& where, uint16_t local_port) 
	: m_where(where)
	, m_tm(m_ios)
	, m_udp(m_ios, 6881)
	, m_stun(m_tm, m_udp, [this](stun_mgr::stun_state s, const udp_endpoint& ep) { on_stun_state(s, ep); })
	, m_dht(m_tm, m_udp)
	, m_group_qid(0)
	, m_incoming_qid(0)
	, m_outgoing_qid(0)
	, m_where_id(hash_id::hash_of(where))
	, m_connect_timer(0)
{
        m_dht.add_bootstrap(udp_resolve(m_ios, "dht.transmissionbt.com", "6881"));
        m_dht.add_bootstrap(udp_resolve(m_ios, "router.utorrent.com", "6881"));
        m_dht.add_bootstrap(udp_resolve(m_ios, "router.bittorrent.com", "6881"));
	m_udp.add_protocol([this](const udp_endpoint& src, const char* buf, size_t len) -> bool {
		if (len == 5 && memcmp(buf, "HELLO", 5) == 0) {
			LOG_INFO("Got hello from %s", to_string(src).c_str());
			return true;
		}
		return false;
	});
}

void meetup::run() 
{
	LOG_INFO("Running");
	m_ios.run();
}

void meetup::on_stun_state(stun_mgr::stun_state s, const udp_endpoint& ep) 
{	
	LOG_INFO("Got new STUN state: %d, %s", s, to_string(ep).c_str());
	if (s != stun_mgr::state_down) {
		m_dht.set_external(ep);
		if (!m_group_qid) {
			// Start group if it's not going
			LOG_INFO("Starting group DHT entry");
			m_group_qid = m_dht.run_query(m_where_id, k_group_publish_rate);
		}
		m_dht.set_publish(m_group_qid, (s == stun_mgr::state_cone));
		// Start connect timer if it's not already running
		if (!m_connect_timer) {
			m_connect_timer = m_tm.add(now() + k_connect_out_rate, [this]() { connect_timer(); });
		}
		// Stop any exiting incoming stuff
		if (m_inbound_timer) {
			m_tm.cancel(m_inbound_timer);
			m_inbound_timer = 0;
		}
		if (m_incoming_qid) {
			m_dht.cancel_query(m_incoming_qid);
			m_incoming_qid = 0;
		}
		// If we are cone, start incoming
		if (s == stun_mgr::state_cone) {
			LOG_INFO("Starting Incoming DHT entry");
			std::string incoming_str = m_where_id.to_string() + ep.address().to_string();
			m_incoming_qid = m_dht.run_query(hash_id::hash_of(incoming_str), k_incoming_dht_rate);
			m_inbound_timer = m_tm.add(now() + k_incoming_hello_rate, [this]() { inbound_timer(); });
		}
	} else {
		LOG_INFO("Shutting down DHT entries");
		m_tm.cancel(m_connect_timer);
		m_tm.cancel(m_inbound_timer);
		m_connect_timer = m_inbound_timer = 0;
		m_group_qid = m_incoming_qid = m_outgoing_qid = 0;
		m_dht.stop_all();
	}
}

void meetup::connect_timer()
{
	if (!m_outgoing_qid) {
		auto peers = m_dht.check_query(m_group_qid);
		if (peers.size()) {
			m_outgoing_addr = pick_random(peers);
			LOG_INFO("Starting search for %s", to_string(m_outgoing_addr).c_str());
			std::string outgoing_str = m_where_id.to_string() + m_outgoing_addr.address().to_string();
			m_outgoing_qid = m_dht.run_query(hash_id::hash_of(outgoing_str), 1_min);
			m_dht.set_publish(m_outgoing_qid, true);
			m_dht.set_ready_handler(m_outgoing_qid, [this]() {
				LOG_INFO("Finished search for %s", to_string(m_outgoing_addr).c_str());
				size_t out_qid = m_outgoing_qid;
				m_outgoing_qid = 0;
				// This might destroy this lambda?
				m_dht.cancel_query(out_qid);
			});
		} else {
			LOG_INFO("No peers found for outbound");
		}
	}
	if (m_outgoing_qid) {
		LOG_INFO("Sending hello to %s", to_string(m_outgoing_addr).c_str());
		m_udp.send(m_outgoing_addr, "HELLO", 5);
	}
	m_connect_timer = m_tm.add(now() + k_connect_out_rate, [this]() { connect_timer(); });
}

void meetup::inbound_timer() 
{
	auto peers = m_dht.check_query(m_incoming_qid);
	if (peers.size()) {
		udp_endpoint who = pick_random(peers);
		LOG_INFO("Sending hello via incoming to %s", to_string(who).c_str());
		m_udp.send(who, "HELLO", 5);
	} else {
		LOG_INFO("No peers found for inbound");
	}
	m_inbound_timer = m_tm.add(now() + k_incoming_hello_rate, [this]() { inbound_timer(); });
}

udp_endpoint meetup::pick_random(const std::map<udp_endpoint, int>& peers)
{
	size_t i = random() % peers.size();
	for(const auto& kvp : peers) {
		if (i == 0) {
			return peers.begin()->first;
		}
		i--;
	}
	throw std::runtime_error("Logic error in pick_random");
}

int main(int argc, char* argv[])
{
	try {
		runtime_assert(argc >= 2);
		meetup m(argv[1], 1234);
		m.run();
	}
	catch(const std::exception& e) {
		LOG_ERROR("Caught unhandled exception: %s", e.what());
	}
}

