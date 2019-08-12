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

#include "../inc/leeway.h"

uint64_t print_after_n_heartbits = 200;
void InitReplacementState() {

    cout << "Initializing Leeway LRU ..." << endl;

    uint32_t config_number = get_config_number();
    cout << "config number: " << config_number << endl;
    switch(config_number) {
        case 1:
        case 2:
            InitLeeway(1, 2048, 16, 64, 16, 1, 2);
            break;
        case 3:
        case 4:
            print_after_n_heartbits *= 4;
            InitLeeway(4, 2048*4, 16, 64, 16, 1, 2);
            break;
        case 5:
        case 6:
            InitLeeway(1, 2048*4, 16, 64*4, 16, 1, 2);
            break;
        default:
            cout << "Unknown config number: " << config_number << endl;
            assert(0);
    }
}

uint64_t n_heartbits = 0;
void PrintStats_Heartbeat() {
    n_heartbits++;
    if ( n_heartbits >= print_after_n_heartbits ) {
        PrintStats();
        n_heartbits = 0;
    }
}

uint32_t GetVictimInSet(uint32_t cpu, uint32_t set, const BLOCK *current_set, uint64_t PC, uint64_t paddr, uint32_t type) {
    return GetVictimInSetLeeway<BLOCK>(cpu, set, current_set, PC, paddr, type);
}

void UpdateReplacementState(uint32_t cpu, uint32_t set, uint32_t way, uint64_t paddr, uint64_t PC, uint64_t victim_addr, uint32_t type, uint8_t hit) {
    UpdateLeeway(cpu, set, way, paddr, PC, victim_addr, type, hit);
}
