
#include "bencode.h"

class bencode_vistor : public boost::static_visitor<std::string>
{
public:
	std::string operator()(const invalid_bencode value) const { 
		throw std::runtime_error("Use of invalid becode"); 
	}
	std::string operator()(int value) const {
		return std::string("i") + std::to_string(value) + std::string("e");
	}
	std::string operator()(const std::string& value) const {
		return std::to_string(value.size()) + std::string(":") + value;		
	}
	std::string operator()(const be_vec& value) const {
		std::string r = "l";
		for(const bencode_t& x : value) {
			r += boost::apply_visitor(bencode_vistor(), x);
		}
		r += "e";
		return r;
	}
	std::string operator()(const be_map& value) const {
		std::string r = "d";
		for(const auto& kvp : value) {
			r += (*this)(kvp.first);
			r += boost::apply_visitor(bencode_vistor(), kvp.second);
		}
		r += "e";
		return r;
	}
};

std::string bencode(const bencode_t& t)
{
	return boost::apply_visitor(bencode_vistor(), t);
}

static int bdecode_int(const char* str, size_t& pos, size_t max_pos)
{
	int sign = 1;
	int val = 0;
	while(str[pos] != 'e') {
		if (str[pos] == '-') { 
			sign = -1; 
		} else if (str[pos] >= '0' && str[pos] <= '9') {
			val *= 10;
			val += str[pos] - '0';
		} else {
			throw bencode_exception("Parse error during parse of int");
		}
		pos++;
	}
	pos++;
	return sign * val;
}

static std::string bdecode_str(const char* str, size_t& pos, size_t max_pos)
{
	size_t len = 0;
	while(str[pos] >= '0' && str[pos] <= '9') {
		len *= 10;
		len += str[pos] - '0';
		pos++;
	}
	if (str[pos] != ':') {
		throw bencode_exception("Expected : after int in str");
	}
	pos++;
	if (pos + len > max_pos) {
		throw bencode_exception("String value runs past the end");
	}
	std::string r(str + pos, len);
	pos += len;
	return r;
}

bencode_t bdecode_rec(const char* str, size_t& pos, size_t max_pos)
{
	if (str[pos] == 'i') {
		pos++;
		return bencode_t(bdecode_int(str, pos, max_pos));
	} else if (str[pos] >= '0' && str[pos] <= '9') {
		return bencode_t(bdecode_str(str, pos, max_pos));
	} else if (str[pos] == 'l') {
		pos++;
		be_vec r;
		while(str[pos] != 'e') {
			r.push_back(bdecode_rec(str, pos, max_pos));
		}
		pos++;
		return bencode_t(r);
	} else if (str[pos] == 'd') {
		pos++;
		be_map r;
		while(str[pos] != 'e') {
			std::string k = bdecode_str(str, pos, max_pos);
			bencode_t v = bdecode_rec(str, pos, max_pos);
			r.emplace(k, v);
		}
		pos++;
		return bencode_t(r);
	} else {
		throw bencode_exception("Invalid type specifier");
	}
}

bencode_t bdecode(const std::string& t) 
{
	size_t pos = 0;
	return bdecode_rec(t.c_str(), pos, t.size());
}

/*
int main()
{
	bencode_t x = be_map({
		{"Hello", "World"},
		{"More", be_vec({ 1, 23, -3 }) }
	});
	printf("%s\n", bencode(x).c_str());
	bencode_t y = bdecode(bencode(x));
	printf("%s\n", bencode(y).c_str());
}
*/

