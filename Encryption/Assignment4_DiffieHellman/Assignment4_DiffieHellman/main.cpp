//
//  main.cpp
//  Assignment4_DiffieHellman
//
//  Created by Mason West on 1/26/18.
//  Copyright © 2018 Mason West. All rights reserved.
//

#include "DHKE.hpp"
#include <iostream>

int main(int argc, const char * argv[]) {
    std::cout << "------------------------ testing festExpModN" << "\n";
    //(9,3,100)=, (1,1,1)=0, (7,4,2)=1, (7,5,4)=3, (2,64,100000)
    uint64_t j = 2;
    uint64_t k = 4;
    uint64_t m = 10;
    
    uint64_t out = fastExpModN(j, k, m);
    
    std::cout << "output = " << out << "\n";
    std::cout << "------------------------" << "\n";
    
    std::cout << "------------loop test------------" << "\n";
    for(int i = 1; i<11; i++) {
        uint64_t test = fastExpModN(2, i, 100);
        std::cout << test << "\n";
    }
    
    //--------
    const uint64_t g = 1907;
    const uint64_t n = 784313;
    DiffieHellmanParticipant alice = DiffieHellmanParticipant();
    DiffieHellmanParticipant bob = DiffieHellmanParticipant();
    
    std::cout << "\n";
    std::cout << "------------------------ call computePublicKey" << "\n";
    
    uint64_t alicePublicKey = computePublicKey(g, n, alice); //1907, 784313,
    uint64_t bobPublicKey = computePublicKey(g, n, bob);
    
    std::cout << "\n";
    std::cout << "------------------------ call computeSharedSecret" << "\n";
    
    alice.sharedKey = computeSharedSecret(bobPublicKey, alice);
    bob.sharedKey = computeSharedSecret(alicePublicKey, bob);
    
    //Printing the structs for error checking
    std::cout << "Alice's Sa (aka k) key = " << alice.privateKey << "\n";
    std::cout << "Bob's Sb (aka k) key = " << bob.privateKey << "\n";
    std::cout << "Alice's g key = " << alice.g << "\n";
    std::cout << "Bob's g key = " << bob.g << "\n";
    std::cout << "Alice's n key = " << alice.n << "\n";
    std::cout << "Bob's n key = " << bob.n << "\n";
    
    std::cout << "\n";
    
    std::cout << "Alice's public key = " << alicePublicKey << "\n";
    std::cout << "Bob's public key = " << bobPublicKey << "\n";
    std::cout << "Alice's shared secret key = " << alice.sharedKey << "\n";
    std::cout << "Bob's shared secret key = " << bob.sharedKey << "\n";
    std::cout << "Alice's shared secret key = " << getSharedSecret(alice) << "\n";
    std::cout << "Bob's shared secret key = " << getSharedSecret(bob) << "\n";
    
    
    return 0;
}
