//
//  main.cpp
//  Assignment3_SecurePass
//
//  Created by Mason West on 1/22/18.
//  Copyright © 2018 Mason West. All rights reserved.
//

#include "securePass.hpp"

#include <iostream>
#include <array>
#include <unordered_map>
#include <CommonCrypto/CommonDigest.h>
#include <bitset>

//hashmap with usernames as keys //https://stackoverflow.com/questions/3578083/what-is-the-best-way-to-use-a-hashmap-in-c
std::unordered_map<std::string, struct passInfo> userDatabase;

/*
 * This method takes the username and password and creates a unique salt, hashs with HMAC, and save the information in a struct
 * within a hashmap.
 */
void setUserInfo(std::string username, std::string password) {
    passInfo passwordData;
    std::array<uint8_t, 32> HMAC;
    //create salt
    std::array<uint8_t, 16> salt = createSalt();
    //hmac pass with salt
    HMAC = hmac(salt, password);
    //put salt and hmac hash in struct
    passwordData.salt = salt;
    passwordData.hash = HMAC;
    //put username and struct in hashmap
    userDatabase[username] = passwordData;
}

/*
 * This method compares an input users password with their saved information and returns if they are the same.
 * Only used in testing.
 */
std::string compareUser(std::string username, std::string password){
    std::array<uint8_t, 32> compareHMAC;
    compareHMAC = hmac(userDatabase[username].salt, password);
    
    if(userDatabase[username].hash == compareHMAC) {
        return "passwords are the same";
    } else {
        return "passwords differ";
    }
}

int main(int argc, const char * argv[]) {

    //Testing computeKey
    std::string users[] = {"user1234", "user5123", "admin", "web", "ssh", "super"}; //
    std::string passes[] = {"password", "as9845has", "@#%u923S$#@fsd2", "hiu@$hlk)(23@", "g@!;lsdf23adhs", "f$@#!;lj@#phdf23"};
     std::string passes2[] = {"pass", "as9845has", "@#%u923S$#@fsd2", "hiu@$hlk)(23@", "g@!;lsdf23adhs", "f$@#!;lj@#phdf23"}; //
    
    std::string user = "user1234";
    std::string pass = "password";
    
    //------------------------------------------------------------------------------
    //test of just the below user and pass combination
    
//    setUserInfo(user, pass);
    
//    std::string compareBool = compareUser(user, pass);
//    std::cout << "Compare result = " << compareBool << "\n";
//
//    std::array<uint8_t, 32> compareHMAC;
//    compareHMAC = hmac(userDatabase[user].salt, pass);
//    std::cout << "Compare result from hashmap = " << "\n";
//    for(int i = 0; i < 32; i++) {
//        std::cout << userDatabase[user].hash[i] << "\n";
//    }
//    std::cout << "Compare result from calculation = " << "\n";
//    for(int i = 0; i < 32; i++) {
//        std::cout << compareHMAC[i] << "\n";
//    }
    
    for(int i = 0; i < 6; i++) {
       setUserInfo(users[i], passes[i]);
    }
    std::string compareUsersOut2;
    for(int i = 0; i < 6; i++){
        compareUsersOut2 = compareUser(users[i], passes2[i]);
         std::cout << "Compare result " << i << "= " << compareUsersOut2 << "\n";
    }
    
    //------------------------------------------------------------------------------
    //test to make sure that the salt and hash were bgin set in the struct and in the hashmap
//    std::cout << "testing hashmap - print salt\n";
//    for(int i = 0; i < 16; i++) {
//        std::cout << userDatabase["user1234"].salt[i] << "\n";
//    }
    
//    std::cout << "testing hash user1234 - print hash\n";
//    for(int i = 0; i < 32; i++) {
//        std::cout << userDatabase["user1234"].hash[i] << "\n";
//    }
    
    //------------------------------------------------------------------------------
//    //this small test produced the same hash for the same sale and same password
//    std::array<uint8_t, 16> salt = createSalt();
//    std::array<uint8_t, 32> test1 = hmac(salt, "mason");
//    std::array<uint8_t, 32> test2 = hmac(salt, "mason");
//
//    std::cout << "testing hash test1 - print hash\n";
//    for(int i = 0; i < 32; i++) {
//        std::cout << test1[i] << "\n";
//    }
//
//    std::cout << "testing hash test2 - print hash\n";
//    for(int i = 0; i < 32; i++) {
//        std::cout << test2[i] << "\n";
//    }
       //------------------------------------------------------------------------------
    
    return 0;
}
