//
//  securePass.cpp
//  Assignment3_SecurePass
//
//  Created by Mason West on 1/25/18.
//  Copyright © 2018 Mason West. All rights reserved.
//

#include "securePass.hpp"

#include <iostream>
#include <array>
#include <unordered_map>
#include <CommonCrypto/CommonDigest.h>
#include <bitset>

std::array<uint8_t, 16> createSalt() {
    std::array<uint8_t, 16> salt;
    for(int i = 0; i < salt.size(); i++){
        salt[i] = arc4random();
    }
    return salt;
}

std::array<uint8_t, 32> hmac(std::array<uint8_t, 16> salt, std::string password) {
    std::array<uint8_t, 32> hash;
    uint8_t ipad = 0x36;
    uint8_t opad = 0x5C;
    //pad password if less than 32 bytes
    //pad password with 0's
    if(password.length() <= 32) { //probably don't even need the if else statement that I have created here
        long span = hash.size() - password.length();
        for(int i = 0; i < span; i++) {
            hash[i] = 0;
        }
        //        for(int i = hash.size()-password.length(); i < hash.size(); i++) {
        for(int i = 0; i < password.length(); i++) {
            hash[i + span] = password[i];
        }
    } else {
        //std::array<uint8len> tempHash;
        uint8_t tempHash[password.length()];
        //make an array of password lenght
        for(int i = 0; i < password.length(); i++) {
            tempHash[i] = password[i];
        }
        //sha it to return it of size 32
        CC_SHA256(password.data(), (int)password.size(), hash.data());
    }
    //----- begin HMAC algorithm -----
    //duplicate hash for use in two parts of equation
    std::array<uint8_t, 32> hash1;
    std::array<uint8_t, 32> hash2;
    //hash xor with ipad
    for(int i = 0; i < hash.size(); i++) {
        hash1[i] = hash[i] ^ ipad;
    }
    //concatenate salt
    std::array<uint8_t, 48> toHash1;
    for(int i = 0; i < hash1.size(); i++) {
        toHash1[i] = hash1[i];
    }
    for(int i = hash1.size(); i < toHash1.size(); i++) { //from 36 to 47
        toHash1[i] = salt[i - hash1.size()];
    }
    //SHA256 the xor and concatanated parts
    std::array<uint8_t, 32> sha1;
    CC_SHA256(toHash1.data(), (int)toHash1.size(), sha1.data());
    //hash xor with opad
    for(int i = 0; i < hash.size(); i++) {
        hash2[i] = hash[i] ^ opad;
    }
    //concatenate hash2 xor with sha1 data
    std::array<uint8_t, 64> toHash2;
    for(int i = 0; i < hash2.size(); i++) {
        toHash2[i] = hash2[i];
    }
    for(int i = hash2.size(); i < toHash2.size(); i++) {
        toHash2[i] = sha1[i - hash2.size()];
    }
    //Compute final sha256 for HMAC
    std::array<uint8_t, 32> HMAC;
    CC_SHA256(toHash2.data(), (int)toHash2.size(), HMAC.data());
    return HMAC;
}
