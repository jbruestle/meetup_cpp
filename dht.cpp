
#include "dht.h"

static const auto request_timeout = 3000_msec;

dht_rpc::dht_rpc(timer_mgr& tm, udp_port& udp)
	: m_tm(tm)
	, m_udp(udp)
	, m_next_tid(0)
{
	m_udp.add_protocol([this](const udp_endpoint& who, const char* buf, size_t len) -> bool {
		return on_incoming(who, buf, len);
	});
}

void dht_rpc::send_request(const udp_endpoint& who, const std::string& rtype, const bencode_t& args,
                const success_handler_t& on_success, const failure_handler_t& on_failure)
{
	uint16_t tid = m_next_tid++;
	pending_t& pend = m_pending[tid];
	pend.on_success = on_success;
	pend.on_failure = on_failure;
	pend.timer = m_tm.add(now() + request_timeout, [this, tid]() { on_timeout(tid); });
	be_map req;
	std::string tstr(2, 0);
	tstr[0] = tid >> 8;
	tstr[1] = tid & 0xff;
	req["y"] = "q";
	req["q"] = rtype;
	req["t"] = tstr;
	req["a"] = args;
	std::string coded = bencode(req); 
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
		LOG_DEBUG("Packet invalid type field");
	} catch(const std::exception& e) {
		// Ignore
		LOG_DEBUG("Invalid incoming result");
	}
	return true;
}

void dht_rpc::on_query(const udp_endpoint& who, be_map& query)
{
}

void dht_rpc::on_response(const udp_endpoint& who, const std::string& type, be_map& resp)
{
	std::string tid_str = boost::get<std::string>(resp["t"]);
	runtime_assert(tid_str.size() == 2);
	uint16_t tid = (static_cast<unsigned char>(tid_str[0]) << 8) + static_cast<unsigned char>(tid_str[1]);
	runtime_assert(m_pending.count(tid));
	pending_t p = m_pending[tid];
	m_pending.erase(tid);
	m_tm.cancel(p.timer);
	if (type == "e" || !resp.count("r")) {
		p.on_failure();
		return;
	} 
	p.on_success(resp["r"]);
}

void dht_rpc::on_timeout(timer_id tid)
{
	pending_t p = m_pending[tid];
	m_pending.erase(tid);
	p.on_failure();
}

/*
int main()
{
	io_service ios;
	timer_mgr tm(ios);
	udp_port up(ios, 5000);
	dht_rpc rpc(tm, up);
	udp_endpoint ep = udp_resolve("67.215.246.10", "6881");

	rpc.send_request(ep, "ping", be_map({{"id" , "01234567890123456789"}}),
		[](const bencode_t& a) {
			printf("Success: %s\n", bencode(a).c_str());
		},
		[]() {
			printf("Error\n");
		});

	ios.run();
}
*/

