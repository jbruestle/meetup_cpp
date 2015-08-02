
#pragma once

#include <stdio.h>
#include <stdio.h>

#define LT_UDP    0
#define LT_DHT    1 
#define LT_FLOW   2

#define LT_NUM_TOPICS 3

#define LL_DEBUG  0
#define LL_INFO   1
#define LL_WARN   2  
#define LL_ERROR  3

extern int g_log_level[LT_NUM_TOPICS];
extern const char* g_topic_names[LT_NUM_TOPICS];

#define LOG(topic, level, format, ...) do { \
	if (level >= g_log_level[topic]) { \
		fprintf(stderr, "%s: " format "\n", g_topic_names[topic], ##__VA_ARGS__); \
	} \
} while(0)

// LOG_TOPIC should be #defined by the user per file

#define LOG_DEBUG(format, ...) LOG(LOG_TOPIC, LL_DEBUG, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) LOG(LOG_TOPIC, LL_INFO, format, ##__VA_ARGS__)
#define LOG_WARN(format, ...) LOG(LOG_TOPIC, LL_WARN, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) LOG(LOG_TOPIC, LL_ERROR, format, ##__VA_ARGS__)

