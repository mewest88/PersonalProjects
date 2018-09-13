//
//  securePass.hpp
//  Assignment3_SecurePass
//
//  Created by Mason West on 1/25/18.
//  Copyright © 2018 Mason West. All rights reserved.
//

#ifndef securePass_hpp
#define securePass_hpp

#include <stdio.h>
#include <array>

// Defines the Struct
struct passInfo {
    std::array<uint8_t, 16> salt;
    std::array<uint8_t, 32> hash;
};

//Creates a random salt for the HMAC method
std::array<uint8_t, 16> createSalt();

/*
 * First, this method pads the input password with 0's at the front so all 32 bits are filled.
 * Then this runs through the HMAC equation to create a salt.
 * HMAC(K, M) = H(  K+ xor opad || H (  (K+ xor ipad) || M) )
 */

std::array<uint8_t, 32> hmac(std::array<uint8_t, 16> salt, std::string password);
    
void setUserInfo(std::string username, std::string password);

std::string compareUser(std::string username, std::string password);
        
#endif /* securePass_hpp */
