#include "replacement_state.h"
#include "leeway.h"

CACHE_REPLACEMENT_STATE::CACHE_REPLACEMENT_STATE( UINT32 _sets, UINT32 _assoc, UINT32 _pol )
{

    numsets    = _sets;
    assoc      = _assoc;
    replPolicy = _pol;

    mytimer    = 0;
    InitReplacementState();

}

void CACHE_REPLACEMENT_STATE::InitReplacementState()
{

    std::cout << std::endl << " ************* Using: Leeway *******************" << std::endl;

    // Create the state for sets, then create the state for the ways
    repl  = new LINE_REPLACEMENT_STATE* [ numsets ];

    // ensure that we were able to create replacement state
    assert(repl);

    // Create the state for the sets
    for(UINT32 setIndex=0; setIndex<numsets; setIndex++) 
    {
        repl[ setIndex ]  = new LINE_REPLACEMENT_STATE[ assoc ];

        for(UINT32 way=0; way<assoc; way++) 
        {
            // initialize stack position (for true LRU)
            repl[ setIndex ][ way ].LRUstackposition = way;
        }
    }

    // Contestants:  ADD INITIALIZATION FOR YOUR HARDWARE HERE
    bool is_lru = 0;
#if 1
    int32_t num_threads = 1;
#else
    int32_t num_threads = 4;
#endif
    InitLeeway(num_threads, numsets, assoc, numsets/32, -1, is_lru , 2);
}

INT32 CACHE_REPLACEMENT_STATE::GetVictimInSet( UINT32 tid, UINT32 setIndex, const LINE_STATE *vicSet, UINT32 assoc,
                                               Addr_t PC, Addr_t paddr, UINT32 accessType )
{
    return GetVictimInSetLeeway<LINE_STATE>(tid, setIndex, vicSet, PC, paddr, accessType);
}

void CACHE_REPLACEMENT_STATE::UpdateReplacementState( 
    UINT32 setIndex, INT32 updateWayID, const LINE_STATE *currLine, 
    UINT32 tid, Addr_t PC, UINT32 accessType, bool cacheHit )
{
    UpdateLeeway(tid, setIndex, updateWayID, 0, PC, currLine[updateWayID].tag, accessType, cacheHit); 
}

ostream & CACHE_REPLACEMENT_STATE::PrintStats(ostream &out)
{

    out<<"=========================================================="<<endl;
    out<<"=========== Replacement Policy Statistics ================"<<endl;
    out<<"=========================================================="<<endl;
    
    PrintLeewayStats();

    return out;
}
