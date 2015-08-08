
#include "dht.h"
#include "utils.h"
#include <boost/crc.hpp>
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/sha.h>

#define LOG_TOPIC LT_DHT 

static const auto k_send_delay = 20_ms;
static const auto k_min_bootstrap_delay = 1000_ms;
static const auto k_request_timeout = 1500_ms;
static const auto k_good_time_min = 5_min;
static const auto k_good_time_slop = 15_min;
static const size_t k_goal_nodes = 6;
static const size_t k_max_nodes = 40;
static const size_t k_failed_nodes = 20;
static const size_t k_top_good = 10;
static const auto k_min_bootstrap_timeout = 1_sec;
static const auto k_max_bootstrap_timeout = 3_min;
static const auto k_bootstrap_check_timeout = 3_min;

hash_id hash_id::random()
{
	hash_id r;
	for(size_t i = 0; i < 20; i++) {
		r.m_buf[i] = ::random();
	}
	return r;
}

hash_id hash_id::hash_of(const std::string& data)
{
	hash_id r;
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, data.data(), data.size());
	SHA1_Final(r.m_buf, &ctx);
	return r;
}

hash_id::hash_id(const char* data)
{
	memcpy(m_buf, data, 20);
}

hash_id::hash_id(const ip_address& addr) {
	uint8_t* ip = 0;
        
        const static uint8_t v4mask[] = { 0x03, 0x0f, 0x3f, 0xff };
        const static uint8_t v6mask[] = { 0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff };
        boost::uint8_t const* mask = 0;
        int num_octets = 0;

        ip_address_v4::bytes_type b4;
        ip_address_v6::bytes_type b6;
        if (addr.is_v6()) {
                b6 = addr.to_v6().to_bytes();
                ip = &b6[0];
                num_octets = 8;
                mask = v6mask;
        }
        else {
                b4 = addr.to_v4().to_bytes();
                ip = &b4[0];
                num_octets = 4;
                mask = v4mask;
        }

        for (int i = 0; i < num_octets; ++i)
                ip[i] &= mask[i];

	uint32_t r = ::random() & 0xff;
        m_buf[0] |= (r & 0x7) << 5;

        boost::crc_optimal<32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, true, true> crc;
        crc.process_block(ip, ip + num_octets);
        uint32_t c = crc.checksum();

        m_buf[0] = (c >> 24) & 0xff;
        m_buf[1] = (c >> 16) & 0xff;
        m_buf[2] = ((c >> 8) & 0xf8) | (::random() & 0x7);

        for (int i = 3; i < 19; ++i) m_buf[i] = ::random() & 0xff;
        m_buf[19] = r & 0xff;
}

std::string hash_id::pack() const
{
	return std::string((char *) m_buf, 20);
}

std::string hash_id::to_string() const 
{
	std::string r;
	for(size_t i = 0; i < 20; i++) {
		r += "0123456789ABCDEF"[uint8_t(m_buf[i]) >> 4];
		r += "0123456789ABCDEF"[uint8_t(m_buf[i]) & 0x0f];
	}
	return r;
}

size_t hash_id::shared_bits(const hash_id& rhs) const
{
	size_t shared = 0;
	for(size_t i = 0; i < 20; i++) {
		uint8_t x = m_buf[i] ^ rhs.m_buf[i];
		if (x == 0) {
			shared += 8;
			continue;
		}
		if (x & 0xf0) {
			x >>= 4;
		} else {
			shared += 4;
		}
		if (x & 0x0c) {
			x >>= 2;
		} else {
			shared += 2;
		}
		if (!(x & 0x02)) {
			shared += 1;
		}
		break;
	}
	return shared;
}

hash_id hash_id::randomize(size_t depth) const
{
	hash_id out;
	memcpy(out.m_buf, m_buf, 20);
	size_t half_byte = depth / 8;
	uint8_t rand_mask = (1 << (8 - (depth - half_byte))) - 1;
	out.m_buf[half_byte] = (::random() & rand_mask) | (m_buf[half_byte] & (~rand_mask));
	for(size_t i = half_byte + 1; i < 20; i++) {
		out.m_buf[i] = ::random();
	}
	return out;
}

bool hash_id::operator<(const hash_id& rhs) const
{
	return memcmp(m_buf, rhs.m_buf, 20) < 0;
}

bool hash_id::operator==(const hash_id& rhs) const
{
	return memcmp(m_buf, rhs.m_buf, 20) == 0;
}

dht_rpc::dht_rpc(timer_mgr& tm, udp_port& udp)
	: m_tm(tm)
	, m_udp(udp)
{
	m_udp.add_protocol([this](const udp_endpoint& who, const char* buf, size_t len) -> bool {
		return on_incoming(who, buf, len);
	});
}

std::string dht_rpc::send_request(const udp_endpoint& who, const std::string& rtype, const be_map& args,
		const success_handler_t& on_success, const failure_handler_t& on_failure)
{
	// Make a random unused tx_id
	std::string tx_id = "0000";
	do {
		*((uint32_t *) tx_id.data()) = random();
	} while(m_pending.count(tx_id));
	LOG_DEBUG("Send to %s: type=%s, txid=%s", 
		to_string(who).c_str(), rtype.c_str(), hexify(tx_id).c_str());
	// Add it to pending, with proper data
	pending_t& pend = m_pending[tx_id];
	pend.who = who;
	pend.qtype = rtype;
	pend.on_success = on_success;
	pend.on_failure = on_failure;
	// Kick off timer
	pend.timer = m_tm.add(now() + k_request_timeout, [this, tx_id]() { on_timeout(tx_id); });
	// Prepare request
	be_map req;
	std::string tstr(2, 0);
	req["y"] = "q";
	req["ro"] = 1;
	req["q"] = rtype;
	req["t"] = tx_id;
	req["a"] = args;
	std::string coded = bencode(req); 
	// Send it
	m_udp.send(who, coded.data(), coded.size());
	return tx_id; 
}

void dht_rpc::cancel_request(const std::string& tx_id)
{
	auto it = m_pending.find(tx_id);
	if (it == m_pending.end()) { return; }
	m_tm.cancel(it->second.timer);
	m_pending.erase(it);
}

bool dht_rpc::on_incoming(const udp_endpoint& who, const char* buf, size_t len)
{
	if (len == 0 || buf[0] != 'd') {
		return false;
	}
	try {
		be_map m = boost::get<be_map>(bdecode(std::string(buf, len)));
		std::string type = boost::get<std::string>(m["y"]);
		if (type == "q") {
			on_query(who, m);
			return true;
		} else if (type == "r" || type == "e") {
			on_response(who, type, m);
			return true;
		}
		LOG_DEBUG("Recv from %s: Error, invalid 'y' entry: %s",  
			to_string(who).c_str(),
			cleanify(type).c_str());
	} catch(const std::exception& e) {
		LOG_DEBUG("Recv from %s: Error, invalid bencode, not a dict, or no 'y' entry", 
			to_string(who).c_str());
	}
	return true;
}

void dht_rpc::on_query(const udp_endpoint& who, be_map& query)
{
	bool did_log = false;
	be_map resp;
	try {
		std::string qtype = boost::get<std::string>(query["q"]);
		std::string tx_id = boost::get<std::string>(query["t"]);
		resp["t"] = tx_id;
		be_map args = boost::get<be_map>(query["a"]);
		auto it = m_handlers.find(qtype);
		if (it == m_handlers.end()) {
			LOG_DEBUG("Recv from %s: Query for unhandled type: %s",
				to_string(who).c_str(),
				cleanify(qtype).c_str());
			did_log = true;
			throw std::runtime_error("Unknown handler: " + qtype);
		}
		LOG_DEBUG("Recv from %s: Query, type=%s, tx_id=%s",
                                to_string(who).c_str(),
                                cleanify(qtype).c_str(),
				hexify(tx_id).c_str());
		be_map out = it->second(args);
		resp["y"] = "r";
		resp["r"] = out;
	} catch(const std::exception& e) {
		if (!did_log) {
			LOG_DEBUG("Recv from %s: Error, query has missing or invalid 'q', 'a', or 't'",
				to_string(who).c_str());
		}
		resp["y"] = "e";
		be_vec err;
		err.push_back(201);
		err.push_back(e.what());
		resp["e"] = err;
	}
	std::string coded = bencode(resp);
	m_udp.send(who, coded.data(), coded.size());
}

void dht_rpc::on_response(const udp_endpoint& who, const std::string& type, be_map& resp)
{
	// Get tx_id + args
	std::string tx_id;
	try {
		tx_id = boost::get<std::string>(resp["t"]);
		runtime_assert(m_pending.count(tx_id));
	} catch (const std::exception& e) {
		LOG_DEBUG("Recv from %s: Error, response has missing or unassigned tx_id: %s",
                                to_string(who).c_str(), hexify(tx_id).c_str());
		return;
	}
	// Load pending transaction
	pending_t p = m_pending[tx_id];

	// Remove it from the set + cancel the timer
	m_pending.erase(tx_id);
	m_tm.cancel(p.timer);

	if (type == "e") {
		std::string e;
		if (resp.count("e")) {
			e = bencode(resp["e"]);
		}
		LOG_DEBUG("Recv from %s: Error, remote err for tx_id=%s, qtype=%s: %s",
                                to_string(who).c_str(), hexify(tx_id).c_str(), 
				p.qtype.c_str(), cleanify(e).c_str());
		p.on_failure(tx_id);
		return;
	}
		
	be_map args;
	try {
		args = boost::get<be_map>(resp["r"]);
	} catch (const std::exception& e) {
		LOG_DEBUG("Recv from %s: Error, invalid 'r' in response tx_id=%s, qtype=%s",
                                to_string(who).c_str(), hexify(tx_id).c_str(), p.qtype.c_str());
		p.on_failure(tx_id);
		return;
	}
	// Make sure it's in the table + from the proper source
	if (p.who != who) {
		LOG_DEBUG("Recv from %s: Error, response has invalid source, tx_id=%s, qtype=%s, osrc=%s",
                                to_string(who).c_str(), hexify(tx_id).c_str(), 
				p.qtype.c_str(), to_string(p.who).c_str());
		p.on_failure(tx_id);
		return;
	}
	LOG_DEBUG("Recv from %s: Response, tx_id=%s, qtype=%s", 
		to_string(who).c_str(), hexify(tx_id).c_str(), p.qtype.c_str());
	// Send response to client
	p.on_success(tx_id, args, resp);
}

void dht_rpc::on_timeout(const std::string& tx_id)
{
	pending_t p = m_pending[tx_id];
	m_pending.erase(tx_id);
	LOG_DEBUG("Timeout from %s: tx_id=%s, qtype=%s", 
		to_string(p.who).c_str(), hexify(tx_id).c_str(), p.qtype.c_str());
	p.on_failure(tx_id);
}

dht_node::dht_node(const udp_endpoint& _addr, const hash_id& _nid, int _depth)
	: addr(_addr)
	, nid(_nid)
	, depth(_depth)
	, rand_key(random())
	, responses(0)
	, errors(0)
	, stale_timer(0)
{}

bool ptr_less::operator()(const dht_node_ptr& a, const dht_node_ptr& b) const
{
	if (a->depth != b->depth) {
		return b->depth < a->depth;
	}
	if (a->responses != b->responses) {
		return b->responses < a->responses;
	}
	if (a->rand_key != b->rand_key) {
		return a->rand_key < b->rand_key;
	}
	return a->addr < b->addr;
}

dht_bucket::dht_bucket(dht_location& location, size_t depth)
	: m_location(location)
	, m_depth(depth)
{
}

void dht_bucket::on_node(const udp_endpoint& addr, const hash_id& nid)
{
	LOG_DEBUG("Level %lu, adding node %s", m_depth, to_string(addr).c_str());
	if (m_all.count(addr)) {
		return;
	}
	dht_node_ptr p = std::make_shared<dht_node>(addr, nid, m_depth);
	m_all[p->addr] = p;
	m_potential.insert(p);
	if (m_all.size() > k_max_nodes) {
		dht_node_ptr r = *m_potential.rbegin();
		m_all.erase(r->addr);
		m_potential.erase(r);
	} else {
		m_location.m_node_count++;
	}
}

bool dht_bucket::try_send()
{
	if (m_good.size() + m_pending.size() / 2 >= k_goal_nodes || m_potential.size() == 0) {
		return false;
	}
	dht_node_ptr p = *m_potential.begin();
	m_potential.erase(p);
	be_map params = {
		{ "id" , m_location.m_dht.m_nid.pack() },
		{ "target" , m_location.m_tid.randomize(m_depth + 10).pack() },
	};
	m_pending.insert(m_location.m_dht.m_rpc.send_request(p->addr, "get", params,
		[this, p](const std::string& tx_id, be_map& m, be_map& b) { on_get_success(tx_id, p, m); },
		[this, p](const std::string& tx_id) { on_failure(tx_id, p); }
	));
	return true;
}

bool dht_bucket::print() const
{
	if (m_all.size() == 0) { return false; }
	for (const dht_node_ptr& p : m_good) {
		printf("    %s:%d -> %s\n", 
			p->addr.address().to_string().c_str(),
			p->addr.port(),
			p->nid.to_string().c_str());
	}
	printf("    Plus %d potential nodes + %d pending nodes\n", (int) m_potential.size(), (int) m_pending.size());
	return true;
}

void dht_bucket::cancel()
{
	for(const std::string& tx_id : m_pending) {
		m_location.m_dht.m_rpc.cancel_request(tx_id);
	}
	for(dht_node_ptr p : m_good) {
		m_location.m_dht.m_tm.cancel(p->stale_timer);
	}
}


void dht_bucket::on_get_success(const std::string& tx_id, const dht_node_ptr& p, be_map& resp)
{
	try {
		std::string id = boost::get<std::string>(resp["id"]);
		if (id.size() != 20) {
			throw std::runtime_error("Invalid node id");
		}
		hash_id nid(id.data());
		if (nid != p->nid) {
			throw std::runtime_error("mismatched id");
		}
		if (resp.count("nodes")) {
			std::string nodes = boost::get<std::string>(resp["nodes"]);		
			if (nodes.size() % 26 != 0) {
				throw std::runtime_error("invalid nodes");
			}
			m_location.m_dht.process_nodes(nodes);
		}
	} catch(const std::exception& e) {
		LOG_DEBUG("Failue decoding get: %s", e.what());
		on_failure(tx_id, p);
		return;
	}
	m_pending.erase(tx_id);
	p->responses++;
	p->stale_timer = m_location.m_dht.m_tm.add(
		now() + k_good_time_min + (random() % 10000) * k_good_time_slop / 10000,
		[this, p]() {
			on_good_timeout(p);
		});
	m_good.insert(p);
	m_location.on_good_up(p);
}

void dht_bucket::on_failure(const std::string& tx_id, const dht_node_ptr& p)
{
	m_pending.erase(tx_id);
	p->errors++;
	if (p->errors >= 3 || p->responses == 0) {
		m_failures.push(p->addr);
		if (m_failures.size() > k_failed_nodes) {
			m_all.erase(m_failures.front());
			m_failures.pop();
		}
		m_location.m_node_count--;
	} else {
		m_potential.insert(p);
	}
	m_location.start_timer();
}

void dht_bucket::on_good_timeout(const dht_node_ptr& p)
{
	p->stale_timer = 0;
	m_good.erase(p);
	m_location.on_good_down(p);
	m_potential.insert(p);
	m_location.start_timer();
}

dht_location::dht_location(dht& dht, const hash_id& tid, const duration& peer_delay)
	: m_dht(dht)
	, m_tid(tid)
	, m_publish(false)
	, m_peer_delay(peer_delay)
	, m_send_timer(0)
	, m_node_count(0)
	, m_is_ready(false)
	, m_peer_timer(0)
{
	for(size_t i = 0; i < 160; i++) {
		m_buckets.emplace_back(*this, i);
	}
	start_timer();
	std::vector<udp_endpoint> bootstraps = m_dht.m_bootstraps;
	for(const udp_endpoint& ep : bootstraps) {
		send_bootstrap(ep);
	}
	m_last_bootstrap = now();
}

dht_location::~dht_location()
{
	LOG_DEBUG("Destroying DHT location");
}

void dht_location::set_ready_handler(const std::function<void ()>& on_ready)
{
	m_on_ready = on_ready;
}

void dht_location::set_publish(bool publish)
{
	m_publish = publish;
}

void dht_location::on_node(const udp_endpoint& addr, const hash_id& nid)
{
	size_t shared = nid.shared_bits(m_tid);
	if (shared == 160) {
		return;
	}
	m_buckets[shared].on_node(addr, nid);
	start_timer();
}

void dht_location::print() const
{
	printf("Location: %s\n", m_tid.to_string().c_str());
	for(int i = 0; i < 160; i++) {
		if (m_buckets[i].m_all.size() != 0) {
			printf("  Bucket %d:\n", i);
			m_buckets[i].print();
		}
	}
}

std::map<udp_endpoint, int> dht_location::get_peers() const
{
	std::map<udp_endpoint, int> r;
	for(const auto& kvp : m_good) {
		for(const auto& ep : kvp.second.what) {
			r[ep]++;
		}
	}
	return r;
}

void dht_location::cancel()
{
	LOG_DEBUG("Cancelling DHT location");
	for(int i = 0; i < 160; i++) {
		m_buckets[i].cancel();
	}
	for(const std::string& tx_id : m_pending) {
		m_dht.m_rpc.cancel_request(tx_id);
	}
	if (m_send_timer) {
		m_dht.m_tm.cancel(m_send_timer);
	}
	if (m_peer_timer) {
		m_dht.m_tm.cancel(m_peer_timer);
	}
}

void dht_location::start_timer()
{
	if (m_send_timer == 0) {
		m_send_timer = m_dht.m_tm.add(now(), [this]() { on_timer(); });
	}
}

void dht_location::on_timer() 
{
	m_send_timer = 0;
	bool sent = false;
	bool at_bottom = true;
	int bottom_level = -1;
	int valid_levels = 0;
	int valid_nodes = 0;

	for(int i = 159; i >= 0; i--) {
		if (m_buckets[i].m_all.size() == 0) continue;
		if (m_buckets[i].try_send()) {
			LOG_DEBUG("Location %s, sending level %d", m_tid.to_string().c_str(), i);
			sent = true;
			break;
		}
		if (at_bottom && m_buckets[i].m_pending.size() == 0) {
			if (bottom_level == -1) { bottom_level = i; }
			valid_levels++;
			valid_nodes += m_buckets[i].m_good.size(); 
		} else {
			at_bottom = false;
		}
	}
	LOG_DEBUG("Valid levels = %d, valid_nodes = %d, bottom_level = %d",
		valid_levels, valid_nodes, bottom_level);
	if (!sent && m_node_count < 100) {
		std::vector<udp_endpoint> bootstraps = m_dht.m_bootstraps;
		if (now() - m_last_bootstrap > k_min_bootstrap_delay) {
			send_bootstrap(bootstraps[random() % bootstraps.size()]);
		} 
		sent = true;  // Keep timer going
	}
	if (sent) {
		m_send_timer = m_dht.m_tm.add(now() + k_send_delay, [this]() { on_timer(); });
	}
	bool is_valid = valid_levels >= 3 && valid_nodes >= 10 && bottom_level > 15;
	if (m_is_ready == false && is_valid) {
		//print();
		on_ready();
	}
}

void dht_location::send_bootstrap(const udp_endpoint& ep)
{
	m_last_bootstrap = now();
	be_map params = {
		{ "id" , m_dht.m_nid.pack() },
		{ "target" , m_tid.randomize(30).pack() },
	};
	m_pending.insert(
		m_dht.m_rpc.send_request(ep, "find_node", params,
		[this](const std::string& tx_id, be_map& m, be_map& b) { 
			m_pending.erase(tx_id);
			on_bootstrap(m); 
		},
		[this](const std::string& tx_id) { m_pending.erase(tx_id); }
	));
}

void dht_location::on_bootstrap(be_map& resp)
{
	try {
		std::string nodes = boost::get<std::string>(resp["nodes"]);		
		if (nodes.size() % 26 != 0) {
			throw std::runtime_error("invalid nodes");
		}
		m_dht.process_nodes(nodes);
	} catch(const std::exception& e) {
		// Ignore
	}
}

void dht_location::on_ready()
{
	m_is_ready = true;
	m_peer_timer = m_dht.m_tm.add(now() + m_peer_delay,
		[this]() { on_peer_timer(); });
	if (m_on_ready) {
		m_on_ready();
	}
}

void dht_location::on_good_up(dht_node_ptr p) 
{
	m_good[p];
	if (p->depth < 15) {
		return;
	}
	size_t i = 0;
	for(const auto& kvp : m_good) {
		if (++i == k_top_good) break;
		if (kvp.first == p) {
			send_get_peers(p);
			return;
		}
	}
}

void dht_location::on_good_down(dht_node_ptr p) 
{
	m_good.erase(p);
}

void dht_location::send_get_peers(dht_node_ptr p)
{
	m_good[p].pending = true;

	be_map params = {
		{ "id" , m_dht.m_nid.pack() },
		{ "info_hash" , m_tid.pack() },
	};
	m_pending.insert(
		m_dht.m_rpc.send_request(p->addr, "get_peers", params,
		[this, p](const std::string& tx_id, be_map& m, be_map& b) { 
			m_pending.erase(tx_id);
			on_get_peers(p, m); 
		},
		[this, p](const std::string& tx_id) { 
			m_pending.erase(tx_id);
			on_error(p); 
		})
	);
}

void dht_location::on_get_peers(dht_node_ptr p, be_map& resp)
{
	if (!m_good.count(p)) {
		return;
	}
	std::string token;
	std::set<udp_endpoint> peers;
	try {
		token = boost::get<std::string>(resp["token"]);
		if (resp.count("values")) {
			bencode_t vals = resp["values"]; 
			if (boost::get<std::string>(&vals)) {
				std::string peer_str = boost::get<std::string>(vals);
				if (peer_str.size() % 6 != 0) {
					throw std::runtime_error("String values not % 6");
				}
				for(size_t i = 0; i < peer_str.size() / 6; i++) {
					uint32_t ip = ntohl(*((uint32_t*) (peer_str.data() + i*6)));
					uint16_t port = ntohs(*((uint16_t*) (peer_str.data() + i*6 + 4)));
					ip_address_v4 bip(ip);
					if (bip == m_dht.m_external.address()) { continue; }
					peers.emplace(bip, port);
				}
			} else if (boost::get<be_vec>(&vals)) {
				be_vec peer_vec = boost::get<be_vec>(vals);
				for(size_t i = 0; i < peer_vec.size(); i++) {
					std::string peer = boost::get<std::string>(peer_vec[i]);
					uint32_t ip = ntohl(*((uint32_t*) (peer.data())));
					uint16_t port = ntohs(*((uint16_t*) (peer.data() + 4)));
					ip_address_v4 bip(ip);
					if (bip == m_dht.m_external.address()) { continue; }
					peers.emplace(bip, port);
				}
			} else {
				throw std::runtime_error("Values not a string or list");
			}
		}
	} catch(const std::exception& e) {
		on_error(p);
		return;
	}
	peer_info& pi = m_good[p];
	pi.pending = false;
	pi.when = now();
	pi.what = peers;
	LOG_DEBUG("Got %d peers, token = %s", (int) peers.size(), hexify(token).c_str());
	if (m_publish) {
		be_map params = {
			{ "id" , m_dht.m_nid.pack() },
			{ "info_hash" , m_tid.pack() },
			{ "port", m_dht.m_external.port() },
			{ "token", token },
		};
		m_pending.insert(
			m_dht.m_rpc.send_request(p->addr, "announce_peer", params,
				[this, p](const std::string& tx_id, be_map& m, be_map& b) { 
					LOG_DEBUG("Announce good"); 
				},
				[this, p](const std::string& tx_id) { 
					m_pending.erase(tx_id);
					LOG_DEBUG("Announce failed"); 
				})
		);
	}
}

void dht_location::on_error(dht_node_ptr p)
{
	// TODO: Maybe remove node from good here?
	if (!m_good.count(p)) {
		return;
	}
	peer_info& pi = m_good[p];
	pi.pending = false;
	pi.when = now();
}

void dht_location::on_peer_timer()
{
	dht_node_ptr which;
	time_point oldest = now();
	size_t i = 0;
	for(const auto& kvp : m_good) {
		if (++i == k_top_good) break;
		if (kvp.second.pending) continue;
		if (kvp.second.when < oldest) {
			oldest = kvp.second.when;
			which = kvp.first;
		}
	}
	if (which) {
		send_get_peers(which);
	}
	m_peer_timer = m_dht.m_tm.add(now() + m_peer_delay,
		[this]() { on_peer_timer(); });
}

dht::dht(timer_mgr& tm, udp_port& udp)
	: m_tm(tm)
	, m_rpc(tm, udp)
	, m_nid(hash_id::random())
	, m_next_query_id(1)
{
}

void dht::set_external(const udp_endpoint& ep) 
{
	m_external = ep;
	m_nid = hash_id(ep.address());
	LOG_DEBUG("New node ID = %s", m_nid.to_string().c_str());
}

void dht::add_bootstrap(const udp_endpoint& ep)
{
	m_bootstraps.push_back(ep);
}

size_t dht::run_query(const hash_id& nid, const duration& refresh_rate)
{
	m_locations[m_next_query_id] = std::make_shared<dht_location>(
		*this, nid, refresh_rate);
	return m_next_query_id++;
}

void dht::set_ready_handler(size_t which, const std::function<void()>& on_done)
{
	auto it = m_locations.find(which);
	if (it != m_locations.end()) {
		it->second->set_ready_handler(on_done);
	}
}

void dht::set_publish(size_t which, bool publish)
{
	auto it = m_locations.find(which);
	if (it != m_locations.end()) {
		it->second->set_publish(publish);
	}
}

std::map<udp_endpoint, int> dht::check_query(size_t which)
{
	std::map<udp_endpoint, int> r;
	auto it = m_locations.find(which);
	if (it != m_locations.end()) {
		r = it->second->get_peers();
	}
	return r;
}

void dht::cancel_query(size_t which)
{
	std::map<udp_endpoint, int> r;
	auto it = m_locations.find(which);
	if (it != m_locations.end()) {
		it->second->cancel();
		m_locations.erase(it);
	}
}

void dht::stop_all()
{
	while(!m_locations.empty()) {
		m_locations.begin()->second->cancel();
		m_locations.erase(m_locations.begin());
	}
}

void dht::process_nodes(const std::string& nodes)
{
	for(size_t i = 0; i < nodes.size() / 26; i++) {
		hash_id nid(nodes.data() + i*26);
		uint32_t ip = ntohl(*((uint32_t*) (nodes.data() + i*26 + 20)));
		uint16_t port = ntohs(*((uint16_t*) (nodes.data() + i*26 + 24)));
		ip_address_v4 bip(ip);
		udp_endpoint ep(bip, port);
		for(auto& kvp : m_locations) {
			if (bip == m_external.address()) {
				continue;
			}
			kvp.second->on_node(ep, nid);
		}
	}
}

/*
int main()
{
	g_log_level[LT_DHT] = LL_DEBUG;
	io_service ios;
	timer_mgr tm(ios);
	udp_port up(ios, 6881);

	auto dht_ptr = std::make_shared<dht>(tm, up);
	dht_ptr->add_bootstrap(udp_resolve(ios, "dht.transmissionbt.com", "6881"));
	dht_ptr->add_bootstrap(udp_resolve(ios, "router.utorrent.com", "6881"));
	dht_ptr->add_bootstrap(udp_resolve(ios, "router.bittorrent.com", "6881"));

	printf("W00t, up\n");
	size_t qid = dht_ptr->run_query(hash_id::hash_of("Hello"), false, 1_min);
	dht_ptr->set_ready_handler(qid, [dht_ptr, qid]() {
		LOG_DEBUG("OK: all done");
		dht_ptr->cancel_query(qid);
	});
	
	ios.run();
}
*/

