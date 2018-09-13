//
//  diffieHellman.hpp
//  Assignment4_DiffieHellman
//
//  Created by Mason West on 1/26/18.
//  Copyright © 2018 Mason West. All rights reserved.
//

#ifndef DHKE_hpp
#define DHKE_hpp

#include <stdio.h>
#include <array>

//

struct DiffieHellmanParticipant {
    uint64_t g;
    uint64_t n;
    uint64_t sharedKey;
    uint64_t privateKey;
    
    DiffieHellmanParticipant();
};

uint64_t computePublicKey(uint64_t g, uint64_t n, DiffieHellmanParticipant &dhke);

uint64_t computeSharedSecret(uint64_t k, DiffieHellmanParticipant &dhke);

uint64_t getSharedSecret(DiffieHellmanParticipant &dhke);

uint64_t fastExpModN(uint64_t x, uint64_t k, uint64_t n);

//uint64_t createPrivateKey();

#endif /* diffieHellman_hpp */
