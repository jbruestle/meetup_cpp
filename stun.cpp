
#include "stun.h"
#include "utils.h"

#define LOG_TOPIC LT_STUN

static const uint32_t k_magic_cookie = 0x2112A442;
static const duration k_stun_timeout = 2_sec;
static const duration k_short_send_delay = 100_ms;
static const duration k_long_send_delay = 30_sec;
static const size_t k_samples = 3;
static const size_t k_errors = 5;

static const std::vector<std::pair<std::string, std::string>> k_public_stun = {
	{ "stun.l.google.com", "19302" },
	{ "stun.ekiga.net", "3478" },
	{ "stun4.l.google.com", "19302" },
	{ "stun.ideasip.com", "3478" },
	{ "stun1.l.google.com", "19302" },
	{ "stun.iptel.org", "3478" },
	{ "stun.schlund.de", "3478" },
	{ "stun2.l.google.com", "19302" },
	{ "stun.voiparound.com", "3478" },
	{ "stun.voipbuster.com", "3478" },
	{ "stun3.l.google.com", "19302" },
	{ "stun.voipstunt.com", "3478" },
	{ "stun.voxgratia.org", "3478" },
};

struct stun_header
{
	uint16_t msg_type;
	uint16_t msg_len;
	uint32_t magic_cookie;
	uint8_t tx_id[12];
};

stun_mgr::stun_mgr(timer_mgr& tm, udp_port& udp, const state_handler_t& handler)
	: m_tm(tm)
	, m_udp(udp)
	, m_handler(handler)
	, m_state(state_down)
	, m_resolver(tm.get_ios())
	, m_timeout(0)
	, m_next_server(0) //random() % k_public_stun.size())
	, m_error_count(0)
{
	memset(m_tx_id, 0, 12);
	m_udp.add_protocol([this](const udp_endpoint& src, const char* buf, size_t len) -> bool {
		if (len < sizeof(stun_header) || buf[0] != 0x01) { 
			return false; 
		}
		on_incoming(src, buf, len);
		return true;
	});
	send_packet();
}

void stun_mgr::send_packet()
{
	// Ok, first we need to do a resolve
	// Pick a server and kick next forward
	auto spair = k_public_stun[m_next_server];
	m_next_server++;
	m_next_server %= k_public_stun.size();
	LOG_DEBUG("Resolving %s:%s", spair.first.c_str(), spair.second.c_str());
	// Prepare the query
	udp_resolver::query query(
		boost::asio::ip::udp::v4(), 
		spair.first,
		spair.second
		);
	// Set up timer
	m_timeout = m_tm.add(now() + k_stun_timeout, [this]() { on_timeout(); });
	// Send it
	m_resolver.async_resolve(query, [this](const error_code& ec, udp_resolver::iterator it) {
		resolve_done(ec, it);
	});
}

void stun_mgr::resolve_done(const error_code& ec, udp_resolver::iterator it)
{
	if (ec) {
		return; // Timer will resend
	}
	// Get endpoint
	udp_endpoint ep = *it;

	// Send the actual packet	
	stun_header p;
	p.msg_type = htons(0x0001);
	p.msg_len = htons(0);
	p.magic_cookie = htonl(k_magic_cookie);
	p.tx_id[0] = 'M'; // Use this is a flag that I am expecting a packet
	for(size_t i = 1; i < 12; i++) {
		p.tx_id[i] = random();  
	}
	memcpy(m_tx_id, p.tx_id, 12);
	char* obuf = (char*) &p;
	LOG_INFO("Sending STUN packet to %s", to_string(ep).c_str());
	// hexdump(std::string(obuf, 20)).c_str());
	m_udp.send(ep, obuf, 20);
}

void stun_mgr::on_incoming(const udp_endpoint& who, const char* buf, size_t len)
{
	// Print it!
	LOG_DEBUG("Got a packet from %s\n%s", to_string(who).c_str(),
		 hexdump(std::string(buf, len)).c_str());
	// Extract header
	const stun_header* p = (const stun_header*) buf;
	// If I'm not expecting this packet, ignore it
	if (m_tx_id[0] != 'M' || memcmp(m_tx_id, p->tx_id, 12) != 0) {
		LOG_INFO("Unexpected packet or mismatched attribute");
		return;
	}
	// Now we seek our attribute
	bool found = false;
	size_t off = sizeof(stun_header);
	udp_endpoint ep;
	while(off + 4 <= len) {
		uint16_t attr_type = ntohs(*((uint16_t*) (buf + off)));
		uint16_t attr_len = ntohs(*((uint16_t*) (buf + off + 2)));
		uint16_t padded_len = ((attr_len + 3) / 4) * 4;
		if (off + 4 + padded_len > len) {
			LOG_WARN("Short length attribute on stun response, dropping");
			return;
		}
		if (attr_type != 0x0001 && attr_type != 0x0020) {
			LOG_DEBUG("Got attribute of type %d, ignoring", attr_type);
			off += 4 + padded_len;
			continue;
		}
		if (attr_len != 8 || buf[off + 5] != 0x01) {
			LOG_WARN("Attribute isn't expected length of 8 bytes for IPV4, or family is wrong");
			return;
		}
		uint16_t port = ntohs(*((uint16_t*) (buf + off + 6))); 
		uint32_t ip = ntohl(*((uint32_t*) (buf + off + 8))); 
		if (attr_type == 0x0020) {
			port ^= k_magic_cookie >> 16;
			ip ^= k_magic_cookie;
		}
		ip_address_v4 bip(ip);
		ep = udp_endpoint(bip, port);
		found = true;
		break;
	}
	if (!found) {
		// Basically early returns causes timer to end up firing
		return;
	}
	// Stop the timer
	m_tm.cancel(m_timeout);
	m_timeout = 0;

	// Clear errors
	m_error_count = 0;

	LOG_INFO("Got STUN response from %s: %s", to_string(who).c_str(), to_string(ep).c_str());
	// Now do the state update
	if (m_samples.size() < k_samples) {
		LOG_DEBUG("Adding to samples");
		// Scanning, add samples
		m_samples.push_back(ep);
		if (m_samples.size() == k_samples) {
			process_samples();
		}
	} else {
		LOG_DEBUG("Checking for invalidation");
		if (m_state == state_cone && ep != m_external) {
			LOG_DEBUG("Invalidation due to cone mismatch");
			// Get new samples on possible state change
			m_samples.clear();
		} else if (m_state == state_symmetric && ep.address() != m_external.address()) {
			LOG_DEBUG("Invalidation due to IP mismatch");
			// Get new samples on possible state change
			m_samples.clear();
		}
	}
	// Pick duration
	duration wait_time = (m_samples.size() == k_samples ? k_long_send_delay : k_short_send_delay);
	m_timeout = m_tm.add(now() + wait_time, [this]() { m_timeout = 0; send_packet(); });
}

void stun_mgr::on_timeout()
{
	// Zero myself out
	m_timeout = 0;
	// Either resolve or send timed out, kill resolve for safety
	m_resolver.cancel();
	// Update state goo
	m_error_count++;
	LOG_INFO("Timeout, error count = %lu", m_error_count);
	if (m_error_count >= k_errors) {
		if (m_state != state_down) {
			LOG_INFO("Too many errors, going down");
			m_samples.clear();
			m_state = state_down;
			m_external = udp_endpoint();
			m_handler(m_state, m_external);
		}
	}
	// Prep a new packet to send		
	duration wait_time = (m_error_count >= k_errors ? k_long_send_delay : k_short_send_delay);
	m_timeout = m_tm.add(now() + wait_time, [this]() { m_timeout = 0; send_packet(); });
}

void stun_mgr::process_samples()
{
	LOG_DEBUG("Processing samples");
	std::map<ip_address, size_t> by_ip;
	std::map<udp_endpoint, size_t> by_ep;
	for(const udp_endpoint& ep : m_samples) {
		by_ip[ep.address()]++;
		by_ep[ep]++;
	}
	bool ip_quorum = false;
	bool ep_quorum = false;
	udp_endpoint choice;
	for(const auto& kvp : by_ip) {
		if (kvp.second >= k_samples/2 + 1) {
			ip_quorum = true;
			choice = udp_endpoint(kvp.first, 0);
		}
	}
	for(const auto& kvp : by_ep) {
		if (kvp.second >= k_samples/2 + 1) {
			ep_quorum = true;
			choice = kvp.first;
		}
	}
	LOG_DEBUG("ip_quorum = %d, ep_quorum = %d", ip_quorum, ep_quorum);
	if (!ip_quorum) {
		LOG_WARN("No agreement on external IP by STUN servers, this is strange");
		// This shouldn't really happen, just stay in sample mode + try again
		m_samples.clear();
		return;
	}
	stun_state state = (ep_quorum ? state_cone : state_symmetric);
	LOG_INFO("New STUN State = %d, choice = %s", state, to_string(choice).c_str());
	if (state != m_state || m_external != choice) {
		LOG_DEBUG("State differs, doing update");
		m_state = state;
		m_external = choice;
		m_handler(m_state, m_external);
	}
}			

/*
int main() 
{
	srandom(time(0));
	g_log_level[LT_STUN] = LL_DEBUG;
	io_service ios;
	timer_mgr tm(ios);
	udp_port udp(ios, 5000);
	stun_mgr sm(tm, udp, [](stun_mgr::stun_state state, const udp_endpoint& ep) {
		LOG_DEBUG("State = %d, ep = %s", state, to_string(ep).c_str());
	});
	ios.run();
}
*/
 

