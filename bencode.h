
#pragma once

#include "types.h"
#include <boost/variant.hpp>

struct invalid_bencode {};

typedef boost::make_recursive_variant<
	invalid_bencode, // Allows 'null' default construction
	int,
	std::string,
	std::vector<boost::recursive_variant_>,
	std::map<std::string, boost::recursive_variant_>
    >::type bencode_t;

typedef std::vector<bencode_t> be_vec;
typedef std::map<std::string, bencode_t> be_map;

class bencode_exception : public std::runtime_error 
{
public:
	bencode_exception(const std::string& what) 
		: std::runtime_error(what)
	{}
};

std::string bencode(const bencode_t& t);
bencode_t bdecode(const std::string& t);

