#ifndef REPL_STATE_H
#define REPL_STATE_H

#include <cstdlib>
#include <cassert>
#include "utils.h"
#include "crc_cache_defs.h"

#define get_cycle_count _Z19GetGlobalCycleCountj
#define get_thread_inst_count _Z25GetThreadInstructionCountj
extern "C" {
    extern long long int get_cycle_count (void);
    extern long long int get_thread_inst_count (UINT32);
};


// Replacement Policies Supported
typedef enum 
{
    CRC_REPL_LRU        = 0,
    CRC_REPL_RANDOM     = 1,
    CRC_REPL_CONTESTANT = 2
} ReplacemntPolicy;

// Replacement State Per Cache Line
typedef struct _LINE_REPLACEMENT_STATE
{
    UINT32  LRUstackposition;

    // CONTESTANTS: Add extra state per cache line here
    
} LINE_REPLACEMENT_STATE;


// The implementation for the cache replacement policy
class CACHE_REPLACEMENT_STATE
{

    private:
        UINT32 numsets;
        UINT32 assoc;
        UINT32 replPolicy;

        LINE_REPLACEMENT_STATE   **repl;

        COUNTER mytimer;  // tracks # of references to the cache

    // CONTESTANTS:  Add extra state for cache here

    public:

        // The constructor CAN NOT be changed
        CACHE_REPLACEMENT_STATE( UINT32 _sets, UINT32 _assoc, UINT32 _pol );

        INT32  GetVictimInSet( UINT32 tid, UINT32 setIndex, const LINE_STATE *vicSet, UINT32 assoc, Addr_t PC, Addr_t paddr, UINT32 accessType );
        void   UpdateReplacementState( UINT32 setIndex, INT32 updateWayID );

        void   SetReplacementPolicy( UINT32 _pol ) { replPolicy = _pol; } 
        void   IncrementTimer() { mytimer++; } 

        void   UpdateReplacementState( UINT32 setIndex, INT32 updateWayID, const LINE_STATE *currLine, 
                UINT32 tid, Addr_t PC, UINT32 accessType, bool cacheHit );

        ostream&   PrintStats( ostream &out);

    private:

        void   InitReplacementState();
        INT32  Get_Random_Victim( UINT32 setIndex );

        INT32  Get_LRU_Victim( UINT32 setIndex );
        void   UpdateLRU( UINT32 setIndex, INT32 updateWayID );
};


#endif
