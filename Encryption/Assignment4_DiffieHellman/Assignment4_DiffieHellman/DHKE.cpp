//
//  diffieHellman.cpp
//  Assignment4_DiffieHellman
//
//  Created by Mason West on 1/26/18.
//  Copyright © 2018 Mason West. All rights reserved.
//

#include "DHKE.hpp"

#include <stdlib.h>

//g^k mod n - k is the private secret key int the T equation
//g and n get passed into the method, k is randomly created
uint64_t fastExpModN(uint64_t g, uint64_t k, uint64_t n) {
    uint64_t startVal = g;
    int index = 0;
    for(int i = 63; i >= 0; i--) { //loop finds the index of first place a 1 appears in my data
        if ((k >> i) == 1) {
            index = i;
            break;
        }
    }
    for(int j = index; j >= 0; j--) {
        if(j == index) { //handles the first case where the value isn't squared
            g = g;
        } else {
//            startVal = g;
            g *= g;
            if(((k >> j) & 1ul) == 1) {
                g *= startVal;
            }
            g %= n;
        }
    }
    return g;
}

//make a constructor to initialize the struct
DiffieHellmanParticipant::DiffieHellmanParticipant() {
//    DiffieHellmanParticipant dhke;
    g = 0;
    n = 0;
    sharedKey = 0;
    privateKey = 0;
}

//T = g^S mod n
uint64_t computePublicKey(uint64_t g, uint64_t n, DiffieHellmanParticipant &dhke) {
    uint64_t publicKey;
    dhke.g = g;
    dhke.n = n;
    arc4random_buf(&dhke.privateKey, 8);
    publicKey = fastExpModN(g, dhke.privateKey, n);
    return publicKey;
}

//Sab = Tb^Sa mod n or Sab = Ta^Sb mod n
uint64_t computeSharedSecret(uint64_t k, DiffieHellmanParticipant &dhke) {
    return fastExpModN(k, dhke.privateKey, dhke.n);
}

uint64_t getSharedSecret(struct DiffieHellmanParticipant &dhke) {
    return dhke.sharedKey;
}
