/*
 * @author Priyank Faldu <Priyank.Faldu@ed.ac.uk> <http://faldupriyank.com>
 *
 * Copyright 2019 The University of Edinburgh
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _LEEWAY_H_
#define _LEEWAY_H_

#include <iomanip>
#include <map>
#include <random>
#include <sstream>

// Only one of the below three options should be enabled
// INDEX_BASED_TABLE, ASSOCIATIVE_TABLE or FULL_PC

// Storage cost assumes 2-bit NRU

// 1-core :  44.25KB
// 4-core : 179.00KB
// 16384 x 1 = 16384 entry table
#define INDEX_BASED_TABLE

// 1-core :  31.25KB
// 4-core : 127.00KB
// 1024 x 4 = 4096 entry table;
//#define ASSOCIATIVE_TABLE

// Just to see the aliasing effect - not practical
//#define FULL_PC // infinite entries table

//#define STATIC_POLICIES
#ifdef STATIC_POLICIES
const int static_policies[MAXIMUM_CORES] = {0, 0, 0, 0}; // 0-->ROP_POLICY 1-->BOP_POLICY
#endif

//#define NO_BYPASS

#include "leeway_config.h"

#define MAXIMUM_CORES 4
#define MAXIMUM_SETS MAXIMUM_CORES*2048

#define NO_SIG 0
#define PREFETCH_SIG 1
#define WRITEBACK_SIG 2
#define SPECIAL_SIGS 3

enum SetRole {
    FOLLOWER_SET = 0,
    ROP_SET = 1,
    BOP_SET = 2,
    MAX_SETS = 3,
}; 

enum PolicyType {
    ROP_POLICY = 0,
    BOP_POLICY = 1,
    MAX_POLICY_TYPES = 2
};

void CheckPolicyStatus(uint32_t cpu_id);
void PrintPC();
void PrintCounters(uint32_t cpu_id);

uint32_t cores = -1;
uint32_t llc_sets = -1;
uint32_t llc_assoc = -1;
bool is_lru = false;

int32_t max_nru_bits = -1;
int32_t max_nru_val = -1;

int32_t max_ld = -1;
int32_t bypass_ld = -1;
uint32_t bypass_way = -1;

uint32_t num_sample_sets = -1;

uint64_t signature_bits = -1;
uint64_t sig_bits_without_core = -1;
uint64_t total_sig_entries = -1;
uint64_t max_sig_value = -1;

int32_t max_conservative_conf = -1;
int32_t max_aggressive_conf = -1;

default_random_engine* random_seed[MAXIMUM_CORES][MAX_POLICY_TYPES];
uniform_int_distribution<uint32_t>* random_dist[MAXIMUM_CORES][MAX_POLICY_TYPES];

int32_t misses[MAXIMUM_CORES][MAXIMUM_CORES][MAX_POLICY_TYPES];
int32_t accesses[MAXIMUM_CORES][MAXIMUM_CORES][MAX_POLICY_TYPES];
int32_t aggr_misses[MAXIMUM_CORES][MAX_POLICY_TYPES];
int32_t aggr_accesses[MAXIMUM_CORES][MAX_POLICY_TYPES];
uint32_t policy_interval_counters[MAXIMUM_CORES+1][MAX_POLICY_TYPES];

uint64_t last_cycle_count[MAXIMUM_CORES] = {0};
int32_t stat_threshold = 0;
uint32_t bypass_th[MAX_POLICY_TYPES] = {0};
uint64_t interval = 200000000;

#ifdef STATIC_POLICIES
const int static_policies[MAXIMUM_CORES] = {0, 0, 0, 0}; // 0-->ROP_POLICY 1-->BOP_POLICY
#endif

struct SetType {
    uint8_t owner;
    SetRole type;
};

struct LeewayBlock {
    // All blocks
    int32_t nru_val;
    int32_t predicted_ld;

    // Only sampler blocks
    uint64_t signature;
    int32_t current_ld;
    int32_t policy_type;

    LeewayBlock() : nru_val(max_nru_val),predicted_ld(max_nru_val), signature(0), current_ld(bypass_ld), policy_type(MAX_POLICY_TYPES) {
    }
};
LeewayBlock** sets;

SetType set_types[MAXIMUM_SETS];
PolicyType follower[MAXIMUM_CORES];
PolicyType temp_follower[MAXIMUM_CORES];

string GetPolicyStr(PolicyType p) {
    switch(p) {
        case ROP_POLICY:
            return "ROP";
            break;
        case BOP_POLICY:
            return "BOP";
            break;
        default:
            assert(0);
            return "Unknown Policy";
            break;
    }
    assert(0);
    return "Unknown Policy";
}

inline bool IsLeaderSet(uint32_t cpu, uint32_t set) {
    assert(cpu <= cores);
    assert(set < llc_sets);
    return ( (set_types[set].owner == cpu) && (set_types[set].type != FOLLOWER_SET) );
}

struct LDPT_ENTRY {
    int32_t stable_ld;
    int32_t variance_conf;
    int32_t variance_dir;
    LDPT_ENTRY() : stable_ld(max_ld), variance_conf(0), variance_dir(0) {}
};

struct Meta {
    uint32_t lru;
    uint32_t tag;
    bool valid;
    LDPT_ENTRY* ldpt_entry;
};

typedef map<uint64_t, Meta*> ldpt_t;
typedef map<uint64_t, Meta*>::iterator ldpt_it;

class LDPT {
    Meta** meta;
    ldpt_t meta_table;
    const uint32_t my_policies;
    uint32_t sets;
    uint32_t ways;
    uint64_t ldpt_hits;
    uint64_t ldpt_misses;
    int32_t* inc_threshold;
    int32_t* dec_threshold;
    uint32_t set_bits;
    uint32_t tag_bits;
    uint32_t address_bits;
    uint32_t tag_mask;
    uint32_t set_mask;
    uint32_t address_mask;
    public:
    LDPT(uint32_t _my_policies, uint32_t _sets, uint32_t _ways, uint32_t num_cores) : my_policies(_my_policies), sets(_sets), ways(_ways), ldpt_hits(0), ldpt_misses(0) {

        assert(my_policies == 2); // Only two policies are supported as of now
        inc_threshold = new int32_t[my_policies];
        dec_threshold = new int32_t[my_policies];
        assert(inc_threshold);
        assert(dec_threshold);

        if ( num_cores == 1 ) {
            max_conservative_conf = 7;
            max_aggressive_conf = 1;
        } else {
            max_conservative_conf = 7;
            max_aggressive_conf = 1;
        }
        SetThreshold(ROP_POLICY, max_aggressive_conf, max_conservative_conf);
        SetThreshold(BOP_POLICY, max_conservative_conf, max_aggressive_conf);

#if !defined INDEX_BASED_TABLE && !defined FULL_PC
        // ASSOCIATIVE_TABLE
        meta = new Meta*[sets];
        assert(meta);
        for ( uint32_t j = 0 ; j < sets ; j++ ) {
            meta[j] = new Meta[ways];
            assert(meta[j]);
            for ( uint32_t k = 0 ; k < ways ; k++ ) {
                meta[j][k].lru = k;
                meta[j][k].tag = 0;
                meta[j][k].valid = false;
                meta[j][k].ldpt_entry = new LDPT_ENTRY[my_policies];
                assert(meta[j][k].ldpt_entry);
                for ( uint32_t i = 0 ; i < my_policies; i++ ) {
                    InitMetaEntry(meta[j][k].ldpt_entry[i]);
                }
            }
        }
        set_bits = log2(sets);
        set_mask = (1 << set_bits)-1;
        address_bits = signature_bits;
        address_mask = 0;
        for ( uint32_t i = 0 ; i < address_bits; i++ ) { 
            address_mask <<= 1;
            address_mask = address_mask | 1;
        }
        tag_bits = address_bits - set_bits;
        tag_mask = (1 << tag_bits)-1;

        cout << "LDPT sets: " << sets << " assoc:" << ways << " my_policies: " << my_policies << endl;
        cout << "address_bits: " << address_bits
            << " set_bits: " << set_bits
            << " tag_bits: " << tag_bits << endl;
        cout << hex << "address_mask: " << address_mask
            << " set_mask: " << set_mask
            << " tag_mask: " << tag_mask << dec << endl;
#else
        sets = total_sig_entries;
        ways = 1;
#endif

        get_storage_state();
    }
    ~LDPT() {
#if !defined INDEX_BASED_TABLE && !defined FULL_PC
        for ( unsigned int i = 0 ; i < sets ; i++ ) {
            for ( unsigned int j = 0 ; j < ways ; j++ ) {
                for ( unsigned int k = 0 ; k < my_policies ; j++ ) {
                    delete[] meta[i][j].ldpt_entry;
                }
                delete[] meta[i];
            }
            delete[] meta;
        }
#endif
        delete[] inc_threshold;
        delete[] dec_threshold;
    }

#if !defined INDEX_BASED_TABLE && !defined FULL_PC
    uint32_t mask_address(uint32_t addr)  {
        return ( addr ) & ( address_mask);
    }
    uint32_t get_set(uint32_t addr) {
        return  ( addr ) & ( set_mask);
    }
    uint32_t get_tag(uint32_t addr) {
        return (addr >> set_bits);
    }
#endif

    void SetThreshold(PolicyType inst, int32_t inc, int32_t dec) {
        inc_threshold[inst] = inc;
        dec_threshold[inst] = dec;
        cout << "Setting threshold for my_policy : " << GetPolicyStr(inst) << " inc: " << inc_threshold[inst] << " dec: " << dec_threshold[inst] << endl;
    }

    void InitMetaEntry(LDPT_ENTRY& e) {
        e.stable_ld = max_ld;
        e.variance_conf = 0;
        e.variance_dir = 0;
    }

    void UpdateEntry(uint64_t sig, int32_t current_ld, uint32_t inst) {
        if ( inst >= my_policies ) {
            cout << " " << inst << " " << my_policies << endl;
            assert(0);
        }
        LDPT_ENTRY* entry = FindEntry(sig, inst); 
        assert(current_ld <= max_ld);
        assert(entry->stable_ld <= max_ld);
        if ( entry->stable_ld == current_ld ) {
            entry->variance_conf = 0;
        } else {
            if ( current_ld > entry->stable_ld ) {
                if ( entry->variance_dir == 1 ) {
                    entry->variance_dir = 0;
                    entry->variance_conf = 1;
                } else {
                    entry->variance_conf++;
                }
                if ( entry->variance_conf >= inc_threshold[inst] ) {
                    entry->variance_conf = 0;
                    entry->stable_ld = current_ld;
                }
            } else {
                if ( entry->variance_dir == 0 ) {
                    entry->variance_dir = 1;
                    entry->variance_conf = 1;
                } else {
                    entry->variance_conf++;
                }
                if ( entry->variance_conf >= dec_threshold[inst] ) {
                    entry->variance_conf = 0;
                    entry->stable_ld = current_ld;
                }
            }
        }
    }
    LDPT_ENTRY* FindEntry(uint64_t sig, uint32_t inst) {
        assert(sig <= max_sig_value);
        if ( inst >= my_policies ) {
            cout << " " << inst << " " << my_policies << endl;
            assert(0);
        }
#if defined INDEX_BASED_TABLE || defined FULL_PC
        ldpt_it itr;
        if ( (itr = meta_table.find(sig)) == meta_table.end() )  {
            Meta* entry = new Meta;
            assert(entry != NULL);
            for ( uint32_t i = 0 ; i < my_policies; i++ ) {
                entry->ldpt_entry = new LDPT_ENTRY[my_policies];
                assert(entry->ldpt_entry);
                InitMetaEntry(entry->ldpt_entry[i]);
            }
            meta_table.insert(pair<uint64_t, Meta*>(sig, entry));
            return &entry->ldpt_entry[inst];
        } else {
            return &itr->second->ldpt_entry[inst];
        }
#else
        uint32_t addr = mask_address(sig);
        uint32_t set_index = get_set(addr);
        uint32_t tag = get_tag(addr);
        uint32_t lru_index = -1;
        assert(set_index < sets);
        assert(set_index >= 0);
        for ( uint32_t i = 0 ; i < ways ; i++ ) {
            if ( meta[set_index][i].tag == tag && meta[set_index][i].valid) {
#ifdef EXTRA_STATS
                ldpt_hits++;
#endif
                for ( uint32_t k = 0 ; k < ways ; k++ ) {
                    if ( meta[set_index][k].lru < meta[set_index][i].lru ) {
                        meta[set_index][k].lru++;
                    }
                }
                assert(meta[set_index][i].lru < ways);
                assert(meta[set_index][i].lru >= 0);
                meta[set_index][i].lru = 0;
                return &(meta[set_index][i].ldpt_entry[inst]);
            }
            if ( meta[set_index][i].lru == (ways-1) ) {
                assert(lru_index == (static_cast<uint32_t>(-1)));
                lru_index = i;
            }
        }

        assert(lru_index >= 0);
        assert(lru_index < ways);
        for ( uint32_t i = 0 ; i < my_policies ; i++ ) {
            InitMetaEntry(meta[set_index][lru_index].ldpt_entry[i]);
        }
        for ( uint32_t i = 0 ; i < ways; i++ ) {
            if ( meta[set_index][i].lru < meta[set_index][lru_index].lru ) {
                meta[set_index][i].lru++;
            }
        }
        meta[set_index][lru_index].lru = 0;
        meta[set_index][lru_index].tag = tag;
        meta[set_index][lru_index].valid = true;
#ifdef EXTRA_STATS
        ldpt_misses++;
#endif
        return &(meta[set_index][lru_index].ldpt_entry[inst]);
#endif
    }

    inline PolicyType GetMyPolicy(bool is_leader, uint32_t cpu_id, uint32_t set_index) {
        assert(set_index < llc_sets);

        PolicyType t;
        if ( is_leader ) {
            assert(cpu_id < cores);
            t = (PolicyType)(set_types[set_index].type-1);
        } else {
            assert(cpu_id <= cores);
            t = (PolicyType)(follower[cpu_id]);
        }
        assert((t == BOP_POLICY) || (t == ROP_POLICY));
        return t;
    }

    inline PolicyType GetMyPolicy(uint32_t cpu_id, uint32_t set_index) {
        bool leader = IsLeaderSet(cpu_id, set_index);
        return GetMyPolicy(leader, cpu_id, set_index);
    }

    void display_stats() {
#ifdef EXTRA_STATS
        cout << setw(15) << "ldpt stats ..." << endl;
        cout << setw(15) << "ldpt hits:" << setw(12) << ldpt_hits << endl;
        cout << setw(15) << "ldpt misses:" << setw(12) <<  ldpt_misses << endl;
        cout << setw(15) << "ldpt hit-rate:" << setw(12) << fixed << setprecision(4) << ldpt_hits * 100.0 / (ldpt_hits + ldpt_misses) << "%" << endl;
#endif
    }

    void get_storage_state() {
        uint64_t total_entries = sets * ways;
        uint64_t meta_size;
        if (ways == 1) {
            meta_size = 0;
        } else {
            meta_size = log2(ways) + tag_bits + 1; 
        }
        uint64_t ldpt_entry_size = max_nru_bits + 1 + log2(max(max_conservative_conf+1, max_aggressive_conf+1)); 
        uint64_t ldpt_total_bits = (total_entries * ldpt_entry_size * my_policies) + (total_entries * meta_size);

        cout << endl;
        cout << setw(30) << "ldpt_sets: " << setw(20) << sets << endl;
        cout << setw(30) << "set_bits: " << setw(20) << set_bits << endl;
        cout << setw(30) << "ldpt_assoc: " << setw(20) << ways << endl;
        cout << setw(30) << "tag_bits: " << setw(20) << tag_bits << endl;
        cout << setw(30) << "ldpt_policies: " << setw(20) << MAX_POLICY_TYPES << endl;
        cout << setw(30) << "total_entries: " << setw(20) << total_entries << endl;
        cout << setw(30) << "meta_size: " << setw(20) << meta_size << endl;
        cout << setw(30) << "ldpt_entry_size: " << setw(20) << ldpt_entry_size << endl;
        cout << setw(30) << "ldpt_total_bits: " << setw(20) << ldpt_total_bits << endl;
        cout << endl;

        uint64_t cache_per_block_sampler_bits = signature_bits + 1 + max_nru_bits;
        uint64_t cache_meta_sampler_bits = num_sample_sets * llc_assoc * my_policies * cores * cache_per_block_sampler_bits;  

        cout << endl;
        cout << setw(30) << "signature_bits: " << setw(20) << signature_bits << endl;
        cout << setw(30) << "max_nru_bits: " << setw(20) << max_nru_bits << endl;
        cout << setw(30) << "cache_p_block_sampler_bits: " << setw(20) << cache_per_block_sampler_bits << endl;
        cout << setw(30) << "sampler_sets: " << setw(20) << num_sample_sets * MAX_POLICY_TYPES * cores << endl;
        cout << setw(30) << "cache_meta_sampler_bits: " << setw(20) << cache_meta_sampler_bits << endl;
        cout << endl;

        uint64_t total_cache_bits = llc_sets * llc_assoc * (max_nru_bits + max_nru_bits); 
        cout << endl;
        cout << setw(30) << "cache_sets:" << setw(20) << llc_sets << endl;
        cout << setw(30) << "cache_assoc:" << setw(20) << llc_assoc << endl;
        cout << setw(30) << "cache_predicted_ld_bits: " << setw(20) << max_nru_bits << endl;
        cout << setw(30) << "cache_state_bits:" << setw(20) << total_cache_bits << endl;
        cout << endl;

        cout << endl;
        uint64_t total_bits = total_cache_bits + cache_meta_sampler_bits + ldpt_total_bits;
        cout << setw(30) << "total_size (bits): " << setw(20) << total_bits << endl;
        cout << setw(30) << "total_size (bytes): " << setw(20) << total_bits / 8.0 << endl;
        cout << setw(30) << "total_size (KB): " << setw(20) << total_bits / (8.0 * 1024.0) << endl;
        cout << endl;
    }
};
LDPT* ldpt;

// This function assigns roles to different sets
// Every set is either a follower set or leader set for some core 
void RandomSetSelection(SetType* set_type, uint32_t num_sets, uint32_t num_cores, uint32_t num_policy_types, uint32_t num_sample_sets) {
    cout << endl << "Selecting " << num_sample_sets << " sets for " << num_cores << " cores for " << num_policy_types << " types" << " from " << num_sets << " sets " << endl; 

    assert(num_sets == llc_sets);
    assert(num_cores == cores);
    // Set defaults
    for ( uint32_t t = 0 ; t < num_cores ; t++ ) {
#ifdef STATIC_POLICIES
        follower[t] = PolicyType(static_policies[t]);
        cout << "Implementing static policy for core: " << t << " policy: " << GetPolicyStr(follower[t]) << endl;
#else
        follower[t] = ROP_POLICY;
#endif
    }
    cout << endl;
    for ( uint32_t i = 0 ; i < num_sets; i ++ ) {
        set_type[i].type = FOLLOWER_SET;
        set_type[i].owner = num_cores;
    }

    uint32_t total_num_sample_sets = num_policy_types * num_cores * num_sample_sets;
    assert(total_num_sample_sets <= num_sets);

    std::default_random_engine generator(15485863);
    std::uniform_int_distribution<uint32_t> distribution(0,num_sets-1);
    for (uint32_t next_type = 1; next_type <= num_policy_types ; next_type++) {
        for (uint32_t thread_t = 0; thread_t < num_cores ; thread_t++) {
            uint32_t remaining_num_sample_sets = num_sample_sets;
            while (remaining_num_sample_sets > 0 ) {
                int local_i = distribution(generator);
                if ( set_type[local_i].type == FOLLOWER_SET ) {
                    set_type[local_i].type = (SetRole)next_type;
                    set_type[local_i].owner = thread_t;
                    remaining_num_sample_sets--;
                } else {
                    continue;
                }
            }
        }
    }

    cout << setw(10) << "Core\\POL";
    for ( uint32_t type = 0 ; type <= num_policy_types ; type++ ) {
        if ( type == 0 ) {
            cout << setw(10) << "FOLLOWERS";
        } else {
            cout << setw(10) << GetPolicyStr((PolicyType)(type-1));
        }
    }
    cout << endl;
    uint32_t total_sets = llc_sets;
    for ( uint32_t t = 0 ; t <= num_cores ; t++ ) {
        cout << setw(8) << "CORE-" << t;
        for ( uint32_t type = 0 ; type <= num_policy_types ; type++ ) {
            int count = 0;
            for ( uint32_t s = 0 ; s < num_sets; s++ ) {
                assert(set_type[s].type >= 0 && set_type[s].type < MAX_SETS);
                assert(set_type[s].owner <= num_cores);
                if ( set_type[s].type == type && set_type[s].owner == t) {
                    count++;
                }
            }
            cout << setw(10) << count;
            total_sets = total_sets - count;
        }
        cout << endl;
    }
    assert(total_sets == 0);
    cout << endl;
}

void InitLeeway(uint32_t num_cores_l, uint32_t llc_sets_l, uint32_t llc_assoc_l, uint32_t num_sample_sets_l, int32_t bypass_way_l, bool is_lru_l, uint32_t max_nru_bits_l = 2) {

    cores = num_cores_l;
    llc_sets = llc_sets_l;
    llc_assoc = llc_assoc_l;
    is_lru = is_lru_l;
    cout << "leeway: " << (is_lru ? "lru" : "nru") << endl;
    cout << "sets: " << llc_sets << endl;
    cout << "assoc: " << llc_assoc << endl;
    assert(cores <= MAXIMUM_CORES);
    assert(llc_sets <= MAXIMUM_SETS);

    if ( is_lru ) {
        max_nru_bits = log2(llc_assoc);
        max_nru_val = llc_assoc-1;
    } else {
        max_nru_bits = max_nru_bits_l;
        max_nru_val = (pow(2,max_nru_bits))-1;
    }
    assert(static_cast<uint32_t>(max_nru_val) < llc_assoc);
    cout << "max_nru_bits: " << max_nru_bits << endl;
    cout << "max_nru_val: " << max_nru_val << endl;

    max_ld = max_nru_val-1;
    bypass_way = bypass_way_l;
    bypass_ld = -1;
    cout << "max_ld: " << max_ld << endl;
    cout << "bypass_way: " << bypass_way << endl;
    cout << "bypass_ld: " << bypass_ld << endl;

    num_sample_sets = num_sample_sets_l;
    cout << "num_sample_sets: " << num_sample_sets << endl;

    bypass_th[ROP_POLICY]=1;
    bypass_th[BOP_POLICY]=3;
    cout << "bypass_threshold_ROP: " << bypass_th[ROP_POLICY] << endl;
    cout << "bypass_threshold_BOP: " << bypass_th[BOP_POLICY] << endl;

    for ( uint32_t i = 0 ; i < cores ; i++ ) {
        for ( uint32_t j = 0 ; j < MAX_POLICY_TYPES ; j++ ) {
            random_seed[i][j] = new default_random_engine(15485863);
            assert(random_seed[i][j]);
            random_dist[i][j] = new uniform_int_distribution<uint32_t>(1, 100);
            assert(random_dist[i][j]);
        }
    }

    sets = new LeewayBlock*[llc_sets];
    assert(sets);

    stat_threshold = 100000;// this 17-bit counter is used to saturate all the miss/access counters
    cout << "stat_threshold: " << stat_threshold << endl;

#ifdef FULL_PC
    signature_bits = 63;
#else
#ifdef INDEX_BASED_TABLE
    // index-based table with 14-bit sig
    signature_bits = (cores == 1) ? 14 : 16;
#else
#ifdef ASSOCIATIVE_TABLE
    // 4-way associative table to accommodate 32K budget
    signature_bits = (cores == 1) ? 16 : 18;
#else
    // index-based table with 13-bit sig (close to 32K budget)
    signature_bits = (cores == 1) ? 13 : 15;
#endif
#endif
#endif
    sig_bits_without_core = signature_bits - log2(cores);
    total_sig_entries = (1<<signature_bits);
    max_sig_value = (1<<signature_bits)-1;
    cout << "signature_bits: " << signature_bits << endl;
    cout << "sig_bits_without_core: " << sig_bits_without_core << endl;
    cout << "total_sig_entries: " << total_sig_entries << endl;
    cout << "max_sig_value: " << max_sig_value << endl;

#if defined INDEX_BASED_TABLE  || defined FULL_PC 
    ldpt = new LDPT(MAX_POLICY_TYPES, total_sig_entries, 1, cores);
#else
#ifdef ASSOCIATIVE_TABLE
    ldpt = new LDPT(MAX_POLICY_TYPES, 1024 * cores, 4, cores);
#else
    ldpt = new LDPT(MAX_POLICY_TYPES, total_sig_entries, 1, cores);
#endif
#endif
    assert(ldpt);

    for ( uint32_t setIndex = 0 ; setIndex < llc_sets ; setIndex++ ) {
        sets[setIndex]  = new LeewayBlock[llc_assoc];
        assert(sets[setIndex]);

        for ( uint32_t way = 0 ; way < llc_assoc ; way++ ) {
            if ( is_lru ) {
                sets[setIndex][way].nru_val = way;
            } else {
                sets[setIndex][way].nru_val = max_nru_val;
            }
            sets[setIndex][way].current_ld = bypass_ld;
            sets[setIndex][way].predicted_ld = max_ld;
            sets[setIndex][way].signature = NO_SIG;
        }
    }

    for ( uint32_t i = 0 ; i < cores ; i++ ) {
        for ( uint32_t j = 0 ; j < cores ; j++ ) {
            for ( uint32_t p = 0 ; p < MAX_POLICY_TYPES ; p++ ) {
                misses[i][j][p] = 0; // where core i is the owner of a given set and leading the policy p, causing miss for core j
                accesses[i][j][p] = 0;
            }
        }
    }

    RandomSetSelection(set_types, llc_sets, cores, MAX_POLICY_TYPES, num_sample_sets);
    cout << "Structures initialized." << endl;

}

inline uint64_t PC_MASK(uint64_t pc, uint32_t suffix) { return (((uint64_t)(pc) << 2) | suffix); }

uint64_t get_sig(uint64_t PC, uint32_t cpu, uint32_t type) {
#ifdef FULL_PC
    if ( type == WRITEBACK ) {
        return WRITEBACK_SIG;
    }

    if ( type == PREFETCH ) {
        return PREFETCH_SIG;
    }

    uint64_t sig = PC;
    sig = PC_MASK(sig, cpu);
    sig = PC_MASK(sig, (type == PREFETCH) ? 1 : 0);
    return sig;

#else // FULL_PC

    if ( type == WRITEBACK ) {
        return WRITEBACK_SIG;
    }

    if ( type == PREFETCH ) {
        return PREFETCH_SIG;
    }

#ifdef NO_PC
    return 0x100+cpu;
#endif

    uint64_t sig = PC % total_sig_entries;
    sig = (cpu << sig_bits_without_core) | sig;
    if ( sig < SPECIAL_SIGS ) {
        sig += SPECIAL_SIGS;
    }
    assert(sig >= SPECIAL_SIGS);
    assert(sig <= max_sig_value);
    return sig;
#endif // FULL_PC
}

void CheckPolicyCounters(uint32_t cpu_id) {
    for ( uint32_t i = 0 ; i < cores; i++ ) {
#ifdef STATIC_POLICIES
        temp_follower[i] = (PolicyType)static_policies[i];
#else
        if ( (aggr_misses[i][ROP_POLICY] - aggr_misses[i][BOP_POLICY]) < 0 ) {
            if ( (misses[i][i][ROP_POLICY] - misses[i][i][BOP_POLICY]) < 0 ) {
                temp_follower[i] = ROP_POLICY;
            } else {
                temp_follower[i] = BOP_POLICY;
            }
        } else {
            temp_follower[i] = BOP_POLICY;
        }
#endif
    }

    for ( uint32_t i = 0 ; i < cores; i++ ) {
        cout << "Thread: " << i << " Diff: "<< setw(10) << aggr_misses[i][ROP_POLICY]-aggr_misses[i][BOP_POLICY] << " Old Policy: " << GetPolicyStr(follower[i]) << " New Policy: " << GetPolicyStr(temp_follower[i]) << endl;
        policy_interval_counters[i][follower[i]]++;
        policy_interval_counters[cores][follower[i]]++;
        follower[i] = temp_follower[i];
    }

    for ( uint32_t i = 0 ; i < cores; i++ ) {
        for ( uint32_t t = 0 ; t < MAX_POLICY_TYPES ; t++ ) {
            aggr_misses[i][t] = 0;
            aggr_accesses[i][t] = 0;
        }
        for ( uint32_t j = 0 ; j < cores; j++ ) {
            misses[i][j][ROP_POLICY] = 0;
            misses[i][j][BOP_POLICY] = 0;
            accesses[i][j][ROP_POLICY] = 0;
            accesses[i][j][BOP_POLICY] = 0;
        }
    }

    cout << setw(15) << "Cores/POL";
    for ( uint32_t j = 0 ; j < MAX_POLICY_TYPES ; j++ ) {
        cout << setw(10) << GetPolicyStr((PolicyType)j);
    }
    cout << endl;
    for ( uint32_t i = 0 ; i < cores ; i++ ) {
        cout << setw(14) << "Policy Core-" << i;
        for ( uint32_t j = 0 ; j < MAX_POLICY_TYPES ; j++ ) {
            cout << setw(10) << policy_interval_counters[i][j];
        }
        cout << endl;
    }
    cout << endl;
}

bool ShouldGiveChance(uint32_t cpu, PolicyType type) {
    uint32_t rand = (*(random_dist[cpu][type]))(*(random_seed[cpu][type]));
    return rand <= bypass_th[type];
}

uint32_t FindVictim(LeewayBlock*& blocks, uint32_t cpu) {
    uint32_t lru_way = bypass_way;
    uint32_t dead_way = bypass_way;
    while (1) {
        int32_t min_dead_predicted_ld = llc_assoc<<1;
        for ( uint32_t i = 0 ; i < llc_assoc ; i++ ) {
            if ( (blocks[i].predicted_ld < max_ld) && (blocks[i].nru_val > blocks[i].predicted_ld ) ) {
                // dead found
#if 1
                if ( blocks[i].predicted_ld < min_dead_predicted_ld ) {
                    min_dead_predicted_ld = blocks[i].predicted_ld;
                    dead_way = i;
                }
#else
                dead_way = i;
#endif
            }

            if( blocks[i].nru_val == max_nru_val ) {
                lru_way = i;
            }
        }

        if ( is_lru ) {
            assert(lru_way != bypass_way);
            if ( dead_way != bypass_way ) {
                return dead_way;
            } else {
                return lru_way;
            }
        } else {
            if ( (lru_way == bypass_way) && (dead_way == bypass_way) ) {
                for ( uint32_t i = 0 ; i < llc_assoc ; i++ ) {
                    blocks[i].nru_val++;
                    if ( blocks[i].nru_val > max_nru_val ) {
                        cout << lru_way << endl
                            << dead_way << endl
                            << bypass_way << endl;
                        for ( uint32_t i = 0 ; i < llc_assoc ; i++ ) {
                            cout << i << " " << blocks[i].nru_val << " " << blocks[i].predicted_ld << endl;
                        }
                        cout << blocks[i].nru_val << " " << max_nru_val << endl;
                        assert(0);
                    }
                }
            } else {
                if ( dead_way != bypass_way ) {
                    return dead_way;
                } else {
                    return lru_way;
                }
            }
        }
    }
}

template <typename T>
uint32_t GetLeewayVictim(uint32_t cpu, uint32_t set, const T*current_set, uint64_t PC, uint64_t paddr, uint32_t type) {

    for ( uint32_t i = 0 ; i < llc_assoc ; i++ ) {
        if ( !(current_set[i].valid) ) {
            return i;
        }
    }

    LeewayBlock*& blocks = sets[set];
    bool leader =  IsLeaderSet(cpu, set);
    PolicyType my_policy = ldpt->GetMyPolicy(leader, cpu, set); 

    uint64_t sig = get_sig(PC, cpu, type);
    if ( type == PREFETCH ) {
        my_policy = BOP_POLICY;
    } else if ( type == WRITEBACK ) {
        my_policy = BOP_POLICY;
    }

    LDPT_ENTRY* bypass_entry = ldpt->FindEntry(sig, my_policy); 
    assert(bypass_entry);

#ifndef NO_BYPASS
        if ( type != WRITEBACK ) {
            if ( (bypass_entry->stable_ld == bypass_ld) && (bypass_entry->variance_conf == 0) ) {
                // Good candidate for bypass
                if ( leader ) {
                    if ( !ShouldGiveChance(cpu, my_policy) ) {
                        return bypass_way;
                    } else {
                    }
                } else {
                    return bypass_way;
                }
            }
        }
#endif

    uint32_t victim_way = FindVictim(blocks, cpu);
    assert(victim_way < llc_assoc); 
    assert(victim_way != bypass_way);

    // Action on eviction
    if ( leader ) {
        assert(current_set[victim_way].valid);
        if ( blocks[victim_way].signature != NO_SIG ) {
            assert((blocks[victim_way].policy_type == BOP_POLICY) || (blocks[victim_way].policy_type == ROP_POLICY));
            assert(blocks[victim_way].current_ld != 1000);
            ldpt->UpdateEntry(blocks[victim_way].signature, blocks[victim_way].current_ld, blocks[victim_way].policy_type); 
        } else {
        }
    }

    return victim_way;
}

void UpdateCounters(uint32_t cpu, uint32_t set, uint32_t type, bool hit) {
    if ( set_types[set].type != FOLLOWER_SET ) {
        if ( type != WRITEBACK ) {
            if ( type != PREFETCH ) {
                PolicyType policy_of_leader = ldpt->GetMyPolicy(set_types[set].owner, set);

                int32_t& acc_count = accesses[set_types[set].owner][cpu][policy_of_leader];
                int32_t& aggr_acc_count = aggr_accesses[set_types[set].owner][policy_of_leader];
                if ( acc_count < stat_threshold ) {
                    acc_count++;
                    aggr_acc_count++;
                }

                if (!hit) {
                    assert(set_types[set].owner < cores);
                    int32_t& miss_count = misses[set_types[set].owner][cpu][policy_of_leader];
                    int32_t& aggr_miss_count = aggr_misses[set_types[set].owner][policy_of_leader];
                    if ( acc_count < stat_threshold ) {
                        miss_count++;
                        aggr_miss_count++;
                    }
                } else {
                }
            }
        }
    }
}

template <typename T>
uint32_t GetVictimInSetLeeway(uint32_t cpu, uint32_t set, const T*current_set, uint64_t PC, uint64_t paddr, uint32_t type) {
    assert(set < llc_sets);
    assert(cpu < cores);
    uint32_t vic_way = GetLeewayVictim<T>(cpu, set, current_set, PC, paddr, type);
    if ( vic_way == bypass_way ) {
        assert(type != WRITEBACK);
        UpdateCounters(cpu, set, type, false);
        CheckPolicyStatus(cpu);
    }

    return vic_way;
}

void PromoteBlock(LeewayBlock*& blocks, LeewayBlock& block) {
    if ( is_lru ) {
        assert(block.nru_val <= max_nru_val);
        for ( uint32_t i = 0 ; i < llc_assoc ; i++ ) {
            if ( blocks[i].nru_val < block.nru_val ) {
                blocks[i].nru_val++;
            }
        }
        block.nru_val = 0;
    } else {
        block.nru_val = 0;
    }
}

void UpdateLeeway(uint32_t cpu, uint32_t set, uint32_t way, uint64_t paddr, uint64_t PC, uint64_t victim_addr, uint32_t type, uint8_t hit) {
    assert(set < llc_sets);
    assert((way < llc_assoc) || (way == bypass_way));
    assert(cpu < cores);

    if ( way == bypass_way ) {
        assert(!hit);
        return;
    }

    CheckPolicyStatus(cpu);

    LeewayBlock*& blocks = sets[set];
    LeewayBlock& block = blocks[way];
    bool leader =  IsLeaderSet(cpu, set);
    PolicyType my_policy = ldpt->GetMyPolicy(leader, cpu, set);

    UpdateCounters(cpu, set, type, hit);

    if ( hit ) {
        if ( type == WRITEBACK ) {
            return;
        }
        if ( leader ) {
            block.current_ld = (block.nru_val > block.current_ld) ? block.nru_val : block.current_ld;
            if ( block.current_ld > max_ld ) {
                block.current_ld = max_ld;
            }
        }
        block.predicted_ld = (block.nru_val > block.predicted_ld) ? block.nru_val : block.predicted_ld;
        if ( block.predicted_ld > max_ld ) {
            block.predicted_ld = max_ld;
        }
        PromoteBlock(blocks, block);

    } else {
        if ( type == WRITEBACK ) {
            assert(way != bypass_way);
        }
        assert(way != bypass_way);

        uint64_t sig = get_sig(PC, cpu, type);
        if ( type == PREFETCH ) {
            my_policy = BOP_POLICY;
        } else if ( type == WRITEBACK ) {
            my_policy = BOP_POLICY;
        }

        LDPT_ENTRY* miss_entry = ldpt->FindEntry(sig, my_policy);
        assert(miss_entry);
        if ( leader ) {
            block.signature = sig; //TODO: What if this is zero
            block.current_ld = -1;
            block.policy_type = my_policy;
        } else {
            block.signature = NO_SIG;
            block.current_ld = 1000;
            block.policy_type = MAX_POLICY_TYPES;
        }

        block.predicted_ld = miss_entry->stable_ld;
        PromoteBlock(blocks, block);
    }
}

void PrintCounters(uint32_t cpu_id) {
    cout << "Current cycle count: " << get_cycle_count() << endl;
    cout << "Current inst count: " << endl;
    for ( uint32_t i = 0 ; i < cores; i++ ) {
        cout << setw(14) << "CPU-" << i << " " << setw(12) << get_instr_count(i) << endl;
    }
    cout << "Last Count: " << last_cycle_count[cpu_id] << endl;
    cout << endl;

    cout << "Misses" << endl;
    cout << setw(15) << "ROP/BOP";
    for ( uint32_t j = 0 ; j < cores; j++ ) {
        cout << setw(20) << "CORE-" << j;
    }
    cout << setw(21) << "CORE-ALL";
    cout << endl;
    for ( uint32_t i = 0 ; i < cores; i++ ) {
        cout << setw(14) << "CORE-" << i;
        for ( uint32_t j = 0 ; j < cores; j++ ) {
            std::stringstream ss;
            ss << setw(9) << misses[i][j][ROP_POLICY] << "/" << misses[i][j][BOP_POLICY];
            cout << setw(21) << ss.str();
        }

        std::stringstream ss;
        ss << setw(9) << aggr_misses[i][ROP_POLICY] << "/" << aggr_misses[i][BOP_POLICY];
        cout << setw(21) << ss.str();
        cout << endl;
    }
    cout << endl;

    cout << "Accesses" << endl;
    cout << setw(15) << "ROP/BOP";
    for ( uint32_t j = 0 ; j < cores; j++ ) {
        cout << setw(20) << "CORE-" << j;
    }
    cout << endl;
    for ( uint32_t i = 0 ; i < cores; i++ ) {
        cout << setw(14) << "CORE-" << i;
        for ( uint32_t j = 0 ; j < cores; j++ ) {
            std::stringstream ss;
            ss << setw(9) << accesses[i][j][ROP_POLICY] << "/" << accesses[i][j][BOP_POLICY];
            cout << setw(21) << ss.str();
        }
        std::stringstream ss;
        ss << setw(9) << aggr_accesses[i][ROP_POLICY] << "/" << aggr_accesses[i][BOP_POLICY];
        cout << setw(21) << ss.str();
        cout << endl;
    }
    cout << endl;

    cout << "Missrate" << endl;
    cout << setw(15) << "ROP/BOP";
    for ( uint32_t j = 0 ; j < cores; j++ ) {
        cout << setw(20) << "CORE-" << j;
    }
    cout << endl;
    for ( uint32_t i = 0 ; i < cores; i++ ) {
        cout << setw(14) << "CORE-" << i;
        for ( uint32_t j = 0 ; j < cores; j++ ) {
            std::stringstream ss;
            ss << setw(9) << misses[i][j][ROP_POLICY] * 100.0 / accesses[i][j][ROP_POLICY] << "/" << misses[i][j][BOP_POLICY] * 100.0 / accesses[i][j][BOP_POLICY];
            cout << setw(21) << ss.str();
        }
        std::stringstream ss;
        ss << setw(9) << aggr_misses[i][ROP_POLICY] * 100.0 / aggr_accesses[i][ROP_POLICY] << "/" << aggr_misses[i][BOP_POLICY] * 100.0 / aggr_accesses[i][BOP_POLICY];
        cout << setw(21) << ss.str();
        cout << endl;
    }
    cout << endl;
}

void CheckPolicyStatus(uint32_t cpu_id) {
    uint32_t cpu_id_policy = cpu_id;
    bool policy_renew = false;
    for ( uint32_t i = 0 ; i < cores ; i++ ) {
        for ( uint32_t j = 0 ; j < MAX_POLICY_TYPES ; j++ ) {
            if ( aggr_accesses[i][j] >= stat_threshold ) {
                cpu_id_policy = i;
                policy_renew = true;
            }
        }
    }
    uint64_t current_count = get_instr_count(cpu_id);
    if ( (policy_renew) || ((current_count - last_cycle_count[cpu_id]) >= interval) ) {
        PrintCounters(cpu_id);
        assert(cpu_id_policy < cores);
        CheckPolicyCounters(cpu_id_policy);
        for ( uint32_t i = 0 ; i < cores ; i++ ) {
            last_cycle_count[i] = get_instr_count(i);
        }
        cout << endl;
    }
}


void PrintLeewayStats()
{
    cout << endl;
#ifdef EXTRA_STATS
    ldpt->display_stats();
#endif
    cout << endl;
}

#endif

#if defined INDEX_BASED_TABLE && defined ASSOCIATIVE_TABLE
#error
#endif

#if defined FULL_PC && defined ASSOCIATIVE_TABLE
#error
#endif

#if defined INDEX_BASED_TABLE && defined FULL_PC
#error
#endif
