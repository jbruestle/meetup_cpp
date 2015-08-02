
#pragma once

#include "udp.h"
#include "time.h"
#include "bencode.h"
#include <set>
#include <boost/operators.hpp>

class hash_id : boost::totally_ordered<hash_id> { 
public:	
	// Return a random ID
	static hash_id random();
	// Construct a node-id based on the hash of some data
	explicit hash_id(const std::string& data);
	// Make a hash from ip address
	explicit hash_id(const ip_address& ip);
	// Back to std::string for packing up
	std::string pack() const;
	// Human readable std::string for printing
	std::string to_string() const;
	// Compute # of shared bits
	size_t shared_bits(const hash_id& rhs) const;
	// Randomize lower bits to increase privacy + search breadth
	hash_id randomize(size_t depth) const;
	// Ordering
	bool operator<(const hash_id& rhs) const;
	bool operator==(const hash_id& rhs) const;
private:
	hash_id() {}
	unsigned char m_buf[20];
};

// Supports bencoding + basic query timeouts, etc
// Often passes be_map& to places that would normally be const
// to allow the use of default constructed map entries
class dht_rpc
{
public:
	// Called when a query succeeds
	typedef std::function<void (be_map&, be_map&)> success_handler_t;
	// Called when a query fails
	typedef std::function<void ()> failure_handler_t;
	// Called for inbound queries
	typedef std::function<be_map (be_map&)> query_handler_t;
	// Construct a new RPC handler
	dht_rpc(timer_mgr& tm, udp_port& udp);
	// Send an outbound request
	void send_request(const udp_endpoint& who, const std::string& rtype, const be_map& args, 
		const success_handler_t& on_success, const failure_handler_t& on_failure);
	// Add a query handler
	void add_handler(const std::string& qtype, const query_handler_t& q);
private:
	bool on_incoming(const udp_endpoint& who, const char* buf, size_t len);
	void on_query(const udp_endpoint& who, be_map& query);
	void on_response(const udp_endpoint& who, const std::string& type, be_map& resp);
	void on_timeout(const std::string& tx_id);
	timer_mgr& m_tm;
	udp_port& m_udp;
	struct pending_t {
		udp_endpoint who;
		std::string qtype;
		success_handler_t on_success;
		failure_handler_t on_failure;
		timer_id timer;
	};
	std::map<std::string, pending_t> m_pending;
	std::map<std::string, query_handler_t> m_handlers;
};

struct dht_node
{
	dht_node(const udp_endpoint& addr, const hash_id& nid, int depth);

	udp_endpoint addr;
	hash_id nid;
	int depth;
	uint32_t rand_key;
	uint32_t responses;  // Total number of responses
	uint32_t errors;  // Number of errors since last valid response
	timer_id stale_timer; // When do I go stale (if good)
};
typedef std::shared_ptr<dht_node> dht_node_ptr;

class ptr_less {
public:
	bool operator()(const dht_node_ptr& a, const dht_node_ptr& b) const;
};

class dht_location;

class dht_bucket
{
public:
	// Construct a new bucket
	dht_bucket(dht_location& location, size_t depth);
	// Heard about a node
	void on_node(const udp_endpoint& addr, const hash_id& nid);
	// Try to get closer to my location, return if I sent a packet
	bool try_send();
	// Check if this bucket really needs nodes
	bool hungry() { return m_good.size() + m_pending < 2; }
	// Print
	bool print() const;
	
private:
	// Handle various callbacks
	void on_get_success(const dht_node_ptr& p, be_map& resp);
	void on_failure(const dht_node_ptr& p);
	void on_good_timeout(const dht_node_ptr& p);
	// Which location am I part of
	dht_location& m_location;
	// My depth
	size_t m_depth;
	// All nodes by endpoint address
	std::map<udp_endpoint, dht_node_ptr> m_all;
	// Nodes which are currently good, ordered by total responses
	std::set<dht_node_ptr, ptr_less> m_good;
	// Nodes which are we have never heard from, or not in a while, ordered by total responses
	std::set<dht_node_ptr, ptr_less> m_potential;
	// Number of nodes with pending requests of some sort (in neither map)
	size_t m_pending;
};

class dht;

class dht_location
{
	friend class dht_bucket;
public:
	// Make a new DHT location
	dht_location(dht& dht, const hash_id& tid, bool publish);
	// Handle a new node being found
	void on_node(const udp_endpoint& addr, const hash_id& nid);
	// Print the current state
	void print() const;
	// Get current node list
	std::map<udp_endpoint, int> get_peers() const; 

private:
	struct peer_info 
	{
		peer_info() : pending(false) {}
		bool pending;
		time_point when;
		std::set<udp_endpoint> what;
	};

	void start_timer();
	void on_timer();
	void send_bootstrap(const udp_endpoint& ep);
	void on_bootstrap(be_map& resp);
	void on_ready();
	void on_good_up(dht_node_ptr p);
	void on_good_down(dht_node_ptr p);
	void send_get_peers(dht_node_ptr p);
	void on_get_peers(dht_node_ptr p, be_map& m);
	void on_error(dht_node_ptr p);
	void on_peer_timer();

	dht& m_dht;
	hash_id m_tid;
	bool m_publish;
	timer_id m_send_timer;
	std::vector<dht_bucket> m_buckets;
	size_t m_node_count;
	time_point m_last_bootstrap;
	bool m_is_ready;
	std::map<dht_node_ptr, peer_info, ptr_less> m_good;
	timer_id m_peer_timer;
};

struct dht_bootstrap_node {
public:
	dht_bootstrap_node(dht& dht, const std::string& name, uint16_t port);
	bool is_ready() { return m_ready; }
	const ip_address& external_addr() { return m_external; }
	const udp_endpoint& endpoint() { return m_endpoint; }

private:
	void send_resolve();
	void resolve_done(const error_code& ec, udp_resolver::iterator it);
	void send_ping();
	void on_ping_resp(be_map& b);
	void on_ping_fail();

	dht& m_dht;
	std::string m_name;
	uint16_t m_port;
	bool m_ready;
	udp_endpoint m_endpoint;
	ip_address m_external;
	udp_resolver m_resolver;
	timer_id m_timer;
	time_point m_last_ping;
	duration m_timeout;
	int m_fail_count;
};

class dht
{
	friend class dht_bucket;
	friend class dht_location;
	friend class dht_bootstrap_node;
public:
	dht(timer_mgr& tm, udp_port& udp, const std::string& url);
	void add_bootstrap(const std::string& name, uint16_t port);

private:
	void try_external();
	void process_nodes(const std::string& nodes);
	std::vector<udp_endpoint> get_bootstraps();
	void bootstrap_state_change();
	void bootstrap_up(const ip_address&);
	void bootstrap_down();

	timer_mgr& m_tm;
	dht_rpc m_rpc;
	bool m_has_external;
	ip_address m_external;
	bool m_ready;
	hash_id m_network;
	hash_id m_nid;
	std::vector<std::shared_ptr<dht_bootstrap_node>> m_bootstraps;
	std::shared_ptr<dht_location> m_register;
	std::shared_ptr<dht_location> m_incoming;
};

