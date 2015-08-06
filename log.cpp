
#include "log.h"

int g_log_level[LT_NUM_TOPICS] = { LL_WARN, LL_WARN, LL_WARN, LL_WARN, LL_INFO };
const char* g_topic_names[LT_NUM_TOPICS] = { "UDP", "DHT", "FLOW", "STUN", "MAIN" };

