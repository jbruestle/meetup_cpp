
#include "time.h"

timer_mgr::timer_mgr(io_service& ios)
	: m_ios(ios)
	, m_next_id(1)
{}


timer_id timer_mgr::add(const time_point& when, const std::function<void ()>& on_timeout)
{
	timer_id id = m_next_id++;
	auto timer = std::make_shared<deadline_timer_t>(m_ios, when);
	auto it = m_timers.emplace(id, timer).first;
	it->second->async_wait([=](const error_code& error) {
		if (m_timers.count(id)) {
			on_timeout();
		}
	});
	return id;
}

void timer_mgr::cancel(const timer_id& id)
{
	m_timers.erase(id);
}

/*
int main()
{
	io_service ios;
	timer_mgr tm(ios);
	timer_id t1 = tm.add(now() + 1000_msec, []() { printf("World\n"); });
	timer_id t2 = tm.add(now() + 750_msec, []() { printf("Cancel Me\n"); });
	timer_id t3 = tm.add(now() + 500_msec, [&]() { printf("Hello\n"); tm.cancel(t2); });
	ios.run();
}
*/

