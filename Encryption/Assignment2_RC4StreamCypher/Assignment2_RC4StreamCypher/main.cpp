//
//  main.cpp
//  Assignment2_RC4StreamCypher
//
//  Created by Mason West on 1/18/18.
//  Copyright © 2018 Mason West. All rights reserved.
//

#include <iostream>
#include <string>
#include <array>
#include <assert.h>

//    for(uint8_t bit : s){
////        std::bitset<8> x(bit);
//        std::cout << bit << std::endl;
//    }

using block = std::array<uint8_t, 256>;

//rc4Info rc4Struct;
block encryptedBytes;

int i = 0;
int j = 0;

//block createInitialArray() {
//    block s;
//    for(int i=0; i < 256; i++) {
//        s[i] = i;
//    }
//    return s;
//}

//block createInitialKey(std::string key) {
//    block temp;
//    block s;
//    for(int i=0; i < 256; i++) {
//        s[i] = i;
//        temp[i] = key[i % key.length()];
//    }
//    return temp;
//}

block initializer(std::string key) {
    block s;
    block temp;
    for(int i=0; i < 255; i++) {
        s[i] = i;
        temp[i] = key[i % key.length()];
    }
    int j = 0;
    for(int i = 0; i < 255; i++) {
//        j = (j + s[i] + temp[i % temp.size()]) % 256; //step differs slightly
        j = (j + s[i] + temp[i]) % 256; //step differs slightly
        std::swap(s[i], s[j]);
    }
    return s;
}

void rc4(block s) {
    uint8_t byte;
    i = (i + 1) % 256; //dont need mod 256 b/c of uint8
    j = (j + s[i]) % 256;
    std::swap(s[i], s[j]);
    int t = (s[i] + s[j]) % 256;
    byte = s[t];
    encryptedBytes[i - 1] = byte;
}

std::string encrypt(std::string pass, std::string message) {
    i = 0;
    j = 0;
    std::string out;
    block s = initializer(pass); //this was in the loop below
    for(int i = 0; i < message.length(); i++) { //i < message.length()
        rc4(s);
        out += message[i] ^ encryptedBytes[i];
    }
    return out;
}

std::string decrypt(std::string pass, std::string cypherText) {
    for(int i = 0; i < cypherText.size(); i++) {
        block s = initializer(pass);
        rc4(s);
        cypherText[i] = cypherText[i % 256] ^ encryptedBytes[i];
    }
    return cypherText;
}

int main(int argc, const char * argv[]) {

    //Testing computeKey
    std::string pass = "01234567";
    std::string messageIn = "Your salary is $1000";
    std::cout << "pass in: " << pass << std::endl;
    std::cout << "message in: " << messageIn << std::endl;
//    std::cout << "Please, enter your password: ";
//    std::getline(std::cin, pass);
//    std::cout << "Please, enter your message: ";
//    std::getline(std::cin, messageIn);
    
    std::string cypherText = encrypt(pass, messageIn);
    std::cout << "cypher text out: " << std::endl;
    std::cout << cypherText << std::endl;
    
    std::string messageOut = decrypt(pass, cypherText);
    std::cout << "messageOut text out: " << std::endl;
    std::cout << messageOut << std::endl;
    
    //flip bits
    std::string M = "1000";
    std::string N = "9999";
    std::string C = encrypt(pass, messageIn);
    for(int i = 0; i < 4; i++){
        C[i + 16] = C[i + 16] ^ (N[i] ^ M[i]);
    }
    std::string messageAttackOut = decrypt(pass, C);
    std::cout << "Attacked Message Out text out: " << std::endl;
    std::cout << messageAttackOut << std::endl;
    
    return 0;
}
