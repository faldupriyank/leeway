#ifndef _LEEWAY_CONFIG_H_
#define _LEEWAY_CONFIG_H_

#include "crc_cache.h"
#include "replacement_state.h"

#define PREFETCH ACCESS_PREFETCH
#define WRITEBACK ACCESS_WRITEBACK

#define NUM_TYPES ACCESS_MAX
#define LOAD ACCESS_LOAD
#define RFO STORE

uint64_t get_instr_count(uint32_t cpu_id) {
    return get_thread_inst_count(cpu_id);
}

#endif
