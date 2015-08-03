
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
	, m_dht(m_tm, m_udp)
	, m_group_qid(0)
	, m_incoming_qid(0)
	, m_outgoing_qid(0)
	, m_where_id(hash_id::hash_of(where))
	, m_connect_timer(0)
{
	m_dht.set_state_handler([this](bool x) { on_dht_state(x); });
        m_dht.add_bootstrap("dht.transmissionbt.com", 6881);
        m_dht.add_bootstrap("router.utorrent.com", 6881);
        m_dht.add_bootstrap("router.bittorrent.com", 6881);
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

void meetup::on_dht_state(bool up) 
{
	if (up) {
		LOG_INFO("DHT started");
		m_group_qid = m_dht.run_query(hash_id::hash_of(m_where), true, k_group_publish_rate);
		std::string incoming_str = m_where_id.to_string() + m_dht.external().to_string();
		m_incoming_qid = m_dht.run_query(hash_id::hash_of(incoming_str), false, k_incoming_dht_rate);
		m_connect_timer = m_tm.add(now() + k_connect_out_rate, [this]() { connect_timer(); });
		m_inbound_timer = m_tm.add(now() + k_incoming_hello_rate, [this]() { inbound_timer(); });
	} else {
		LOG_INFO("DHT failed");
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
			m_outgoing_qid = m_dht.run_query(hash_id::hash_of(outgoing_str), true, 1_min);
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
	auto peers = m_dht.check_query(m_group_qid);
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
	// TODO: Something real
	return peers.begin()->first;
}

int main()
{
	meetup m("Hello World", 1234);
	m.run();
}

