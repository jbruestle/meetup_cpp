
#include "dht.h"
#include "utils.h"

static const auto k_send_delay = 100_ms;
static const auto k_min_bootstrap_delay = 1000_ms;
static const auto k_request_timeout = 3000_ms;
static const auto k_good_time_min = 1_min;
static const auto k_good_time_slop = 15_min;
static const size_t k_goal_nodes = 6;
static const size_t k_max_nodes = 40;

node_id::node_id(const char* buf)
{
	memcpy(m_buf, buf, 20);
}

std::string node_id::pack() const
{
	return std::string((char *) m_buf, 20);
}

std::string node_id::to_string() const 
{
	std::string r;
	for(size_t i = 0; i < 20; i++) {
		r += "0123456789ABCDEF"[uint8_t(m_buf[i]) >> 4];
		r += "0123456789ABCDEF"[uint8_t(m_buf[i]) & 0x0f];
	}
	return r;
}

size_t node_id::shared_bits(const node_id& rhs) const
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

node_id node_id::randomize(size_t depth) const
{
	node_id out;
	memcpy(out.m_buf, m_buf, 20);
	size_t half_byte = depth / 8;
	uint8_t rand_mask = (1 << (8 - (depth - half_byte))) - 1;
	out.m_buf[half_byte] = (random() & rand_mask) | (m_buf[half_byte] & (~rand_mask));
	for(size_t i = half_byte + 1; i < 20; i++) {
		out.m_buf[i] = random();
	}
	return out;
}

bool node_id::operator<(const node_id& rhs) const
{
	return memcmp(m_buf, rhs.m_buf, 20) < 0;
}

bool node_id::operator==(const node_id& rhs) const
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

void dht_rpc::send_request(const udp_endpoint& who, const std::string& rtype, const be_map& args,
		const success_handler_t& on_success, const failure_handler_t& on_failure)
{
	// Make a random unused tx_id
	std::string tx_id = "0000";
	do {
		*((uint32_t *) tx_id.data()) = random();
	} while(m_pending.count(tx_id));
	LOG_DEBUG("Sending tx_id = %x", *((uint32_t *) tx_id.data()));
	// Add it to pending, with proper data
	pending_t& pend = m_pending[tx_id];
	pend.who = who;
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
		LOG_DEBUG("Packet invalid type field: %s", type.c_str());
	} catch(const std::exception& e) {
		// Ignore
		LOG_DEBUG("Invalid incoming results:\n%s", hexdump(std::string(buf, len)).c_str());
	}
	return true;
}

void dht_rpc::on_query(const udp_endpoint& who, be_map& query)
{
	be_map resp;
	try {
		std::string qtype = boost::get<std::string>(query["q"]);
		std::string tx_id = boost::get<std::string>(query["t"]);
		resp["t"] = tx_id;
		be_map args = boost::get<be_map>(query["a"]);
		auto it = m_handlers.find(qtype);
		if (it == m_handlers.end()) {
			throw std::runtime_error("Unknown handler: " + qtype);
		}
		be_map out = it->second(args);
		resp["y"] = "r";
		resp["r"] = out;
	} catch(const std::exception& e) {
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
	std::string tx_id = boost::get<std::string>(resp["t"]);
	be_map args = boost::get<be_map>(resp["r"]);
	LOG_DEBUG("Got tx_id = %x", *((uint32_t *) tx_id.data()));
	// Make sure it's in the table + from the proper source
	runtime_assert(m_pending.count(tx_id));
	pending_t p = m_pending[tx_id];
	runtime_assert(p.who == who);
	// Remove it from the set + cancel the timer
	m_pending.erase(tx_id);
	m_tm.cancel(p.timer);
	if (type == "e" || !resp.count("r")) {
		// Handle errors
		LOG_DEBUG("Node %s:%d, Failed due to a remote error: %s", 
			p.who.address().to_string().c_str(), p.who.port(),
			bencode(resp).c_str());
		p.on_failure();
		return;
	} 
	// Send response to client
	p.on_success(args);
}

void dht_rpc::on_timeout(const std::string& tx_id)
{
	LOG_DEBUG("Timeout tx_id = %x", *((uint32_t *) tx_id.data()));
	pending_t p = m_pending[tx_id];
	m_pending.erase(tx_id);
	LOG_DEBUG("Node %s:%d, Failed due to a timeout", 
		p.who.address().to_string().c_str(), p.who.port());
	p.on_failure();
}

dht_node::dht_node(const udp_endpoint& addr, const node_id& nid)
	: addr(addr)
	, nid(nid)
	, rand_key(random())
	, responses(0)
	, errors(0)
	, stale_timer(0)
{}

bool operator<(const dht_node_ptr& a, const dht_node_ptr& b)
{
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
	, m_pending(0)
{
}

void dht_bucket::on_node(const udp_endpoint& addr, const node_id& nid)
{
	if (m_all.count(addr)) {
		return;
	}
	dht_node_ptr p = std::make_shared<dht_node>(addr, nid);
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
	if (m_good.size() + m_pending >= k_goal_nodes || m_potential.size() == 0) {
		return false;
	}
	dht_node_ptr p = *m_potential.begin();
	m_potential.erase(p);
	m_pending++;
	be_map params = {
		{ "id" , m_location.m_dht.m_nid.pack() },
		{ "target" , m_location.m_tid.randomize(m_depth + 4).pack() },
	};
	LOG_DEBUG("Sending a request to %s:%d, responses=%d, errors=%d", 
		p->addr.address().to_string().c_str(),
		p->addr.port(), (int) p->responses, (int) p->errors);
	m_location.m_dht.m_rpc.send_request(p->addr, "get", params,
		[this, p](be_map& m) { on_get_success(p, m); },
		[this, p]() { on_failure(p); }
	);
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
	printf("    Plus %d potential nodes + %d pending nodes\n", (int) m_potential.size(), (int) m_pending);
	return true;
}

void dht_bucket::on_get_success(const dht_node_ptr& p, be_map& resp)
{
	try {
		std::string id = boost::get<std::string>(resp["id"]);
		if (id.size() != 20) {
			throw std::runtime_error("Invalid node id");
		}
		node_id nid(id.data());
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
		on_failure(p);
		return;
	}
	m_pending--;		
	p->responses++;
	p->stale_timer = m_location.m_dht.m_tm.add(
		now() + k_good_time_min + (random() % 10000) * k_good_time_slop / 10000,
		[this, p]() {
			on_good_timeout(p);
		});
	m_good.insert(p);
	m_location.on_good_node(p);
}

void dht_bucket::on_failure(const dht_node_ptr& p)
{
	m_pending--;
	p->errors++;
	if (p->errors >= 3 || p->responses == 0) {
		m_all.erase(p->addr);
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
	m_potential.insert(p);
	m_location.start_timer();
}

dht_location::dht_location(dht& dht, const node_id& tid)
	: m_dht(dht)
	, m_tid(tid)
	, m_send_timer(0)
	, m_node_count(0)
	, m_is_ready(false)
{
	m_dht.m_locations.insert(this);
	for(size_t i = 0; i < 160; i++) {
		m_buckets.emplace_back(*this, i);
	}
	start_timer();
	for(const udp_endpoint& ep : m_dht.m_bootstraps) {
		send_bootstrap(ep);
	}
	m_last_bootstrap = now();
}

void dht_location::on_node(const udp_endpoint& addr, const node_id& nid)
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
		printf("  Bucket %d:\n", i);
		if (!m_buckets[i].print()) break;
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
	for(int i = 0; i < 160; i++) {
		if (m_buckets[i].hungry() && m_buckets[i].try_send()) {
			sent = true;
			break;
		}
	}
	if (!sent) {
		for(int i = 159; i >= 0; i--) {
			if (m_buckets[i].try_send()) {
				sent = true;
				break;
			}
		}
	}
	if (!sent && m_node_count < 100) {
		if (now() - m_last_bootstrap > k_min_bootstrap_delay) {
			send_bootstrap(m_dht.m_bootstraps[random() % m_dht.m_bootstraps.size()]);
		} 
		sent = true;  // Keep timer going
	}
	if (sent) {
		m_send_timer = m_dht.m_tm.add(now() + k_send_delay, [this]() { on_timer(); });
	} else {
		if (m_is_ready == false && m_node_count > 6*15) {
			m_is_ready = true;
			print();
		}
	}
}

void dht_location::send_bootstrap(const udp_endpoint& ep)
{
	be_map params = {
		{ "id" , m_dht.m_nid.pack() },
		{ "target" , m_tid.randomize(30).pack() },
	};
	m_dht.m_rpc.send_request(ep, "find_node", params,
		[this](be_map& m) { on_bootstrap(m); },
		[](){}
	);
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

void dht_location::on_good_node(const dht_node_ptr& p)
{
}

dht::dht(timer_mgr& tm, udp_port& udp, const node_id& nid)
	: m_tm(tm)
	, m_rpc(tm, udp)
	, m_nid(nid)
{}

void dht::add_bootstrap(const udp_endpoint& ep)
{
	m_bootstraps.push_back(ep);
}

void dht::process_nodes(const std::string& nodes)
{
	for(size_t i = 0; i < nodes.size() / 26; i++) {
		node_id nid(nodes.data() + i*26);
		uint32_t ip = ntohl(*((uint32_t*) (nodes.data() + i*26 + 20)));
		uint16_t port = ntohs(*((uint16_t*) (nodes.data() + i*26 + 24)));
		boost::asio::ip::address_v4 bip(ip);
		udp_endpoint ep(bip, port);
		for(dht_location* l : m_locations) {
			l->on_node(ep, nid);
		}
	}
}

void dht::print() const
{
	for(dht_location* l : m_locations) {
		l->print();
	}
}

int main()
{
	io_service ios;
	timer_mgr tm(ios);
	udp_port up(ios, 6881);
	//dht_rpc rpc(tm, up);
	
	dht the_dht(tm, up, node_id("01234567890123456789"));

	the_dht.add_bootstrap(udp_resolve(ios, "dht.transmissionbt.com", "6881"));
	the_dht.add_bootstrap(udp_resolve(ios, "router.utorrent.com", "6881"));
	the_dht.add_bootstrap(udp_resolve(ios, "router.bittorrent.com", "6881"));
	
	dht_location loc(the_dht, node_id("112233445566778899"));

	/*	
	for(size_t i = 1; i <= 5; i++) {
		tm.add(now() + i * 10_sec, [&the_dht]() {
			printf("***** DOING the print ******\n");
			the_dht.print();
		});
	}
	*/

	ios.run();

	
	/*	
	udp_endpoint ep = udp_resolve(ios, "dht.transmissionbt.com", "6881");

	rpc.send_request(ep, "find_node", be_map({
		{"id" , "01234567890123456789"},
		{"target", "112233445566778899"},
	}),
		[](be_map& a) {
			printf("Success: %s\n", bencode(a).c_str());
		},
		[]() {
			printf("Error\n");
		});
	*/
}


