
#pragma once

#include "types.h"
#include <chrono>

typedef std::chrono::system_clock::time_point time_point;
typedef std::chrono::system_clock::duration duration;
inline time_point now() { return std::chrono::system_clock::now(); }

inline uint32_t now_us_wrap() { 
	duration since_epoch = now().time_since_epoch();
	return uint32_t(std::chrono::duration_cast<std::chrono::microseconds>(since_epoch).count());
}

inline uint32_t now_sec() { 
	duration since_epoch = now().time_since_epoch();
	return uint32_t(std::chrono::duration_cast<std::chrono::seconds>(since_epoch).count());
}

inline time_point time_from_sec(uint32_t tp) {
	return std::chrono::system_clock::from_time_t(time_t(tp));
}
	
inline duration operator "" _min(unsigned long long int x) { return std::chrono::minutes(x); }
inline duration operator "" _sec(unsigned long long int x) { return std::chrono::seconds(x); }
inline duration operator "" _ms(unsigned long long int x) { return std::chrono::milliseconds(x); }
typedef uint32_t timer_id;

// Thank you Dave S
template<typename Clock>
struct CXX11Traits
{
	typedef typename Clock::time_point time_type;
	typedef typename Clock::duration	 duration_type;
	static time_type now() { return Clock::now(); }
	static time_type add(time_type t, duration_type d) { return t + d; }
	static duration subtract(time_type t1, time_type t2) { return t1-t2; }
	static bool less_than(time_type t1, time_type t2) { return t1 < t2; }

	static	boost::posix_time::time_duration 
	to_posix_duration(duration_type d1)
	{
		using std::chrono::duration_cast;
		auto in_sec = duration_cast<std::chrono::seconds>(d1);
		auto in_usec = duration_cast<std::chrono::microseconds>(d1 - in_sec);
		boost::posix_time::time_duration result =
			boost::posix_time::seconds(in_sec.count()) + 
			boost::posix_time::microseconds(in_usec.count());
		return result;
	}
};

typedef boost::asio::basic_deadline_timer<
	std::chrono::system_clock, 
	CXX11Traits<std::chrono::system_clock>> deadline_timer_t;

class timer_mgr
{
public:
	// Construct
	timer_mgr(io_service& ios);
	// Add a new timer and get it's ID
	timer_id add(const time_point& when, const std::function<void ()>& on_timeout);
	// Support strong cancellation, since we are single threaded
	void cancel(const timer_id& id);
	// Return a copy of the IOS
	io_service& get_ios() { return m_ios; }
private:
	io_service& m_ios;
	timer_id m_next_id;
	std::map<timer_id, std::shared_ptr<deadline_timer_t>> m_timers;
};
