//
//  main.cpp
//  blockCypheRound2
//
//  Created by Mason West on 1/18/18.
//  Copyright © 2018 Mason West. All rights reserved.
//

#include <stdio.h>
#include <iostream>
#include <string>
#include <array>
#include <assert.h>

//Define structural elements
using block = std::array<uint8_t, 8>;
using subTable = std::array<uint8_t, 256>;

//global variable for the substitution tables
std::array<subTable, 8> subTables;
int numRotations = 16;

/*
 compute key
 */
std::array<uint8_t,8> computeKey(std::string password) {
    block key = {{0, 0, 0, 0, 0, 0, 0, 0}};
    for(int i = 0; i < password.length(); i++) {
        key[i % 8] = key[i % 8] ^ password[i];
    }
    return key;
}

/*
 Shuffles an input array
 */
subTable shuffleArray(subTable arrayIn) { //pass by reference?
    for(int i = arrayIn.size()-1; i > 0; i--){
        int random = std::rand() % i; //maybe can just mod i
        uint8_t temp = arrayIn[i];
        arrayIn[i] = arrayIn[random];
        arrayIn[random] = temp;
    }
    return arrayIn;
}

/*
 subTableMaker - makes all the subtables used in the substitution
 */
std::array<subTable, 8> subTableMaker() {
    std::array<subTable, 8> subTableGrouping;
    subTable substitution;
    for(int i=0; i < 256; i++) { //    for(int i=0; i < substitution.size(); i++) {
        substitution[i] = i;
    }
    subTable tempTable = shuffleArray(substitution); //swap this and the line below it when I want the first table in the sub list shuffled
    //    subTable tempTable = substitution;
    subTableGrouping[0] = tempTable;
    for(int i=1; i < subTableGrouping.size(); i++) {
        tempTable = shuffleArray(tempTable);
        subTableGrouping[i] = tempTable;
    }
    return subTableGrouping;
}

/*
 */
uint8_t subFWD(uint8_t blockMessagei, subTable subTablei) {
    return subTablei[blockMessagei];
}

/*
 */
block rotateLeft(block &blockMessage) {
    uint8_t temp = blockMessage[0];
    for(int i=0; i < blockMessage.size()-1; i++){
        blockMessage[i] = (blockMessage[i] << 1) | (blockMessage[i+1] >> 7);
    }
    blockMessage[blockMessage.size()-1] = (blockMessage[blockMessage.size()-1] << 1) | (temp >> 7);
    return blockMessage;
}

block stringToBlock(std::string &message) {
    block blockOut;
    for(int i=0; i < message.length(); i++){
        blockOut[i] = message[i];
    }
    return blockOut;
}

block encrypt(std::string password, std::string message) { //this method could take the password or the key, and the message.
    subTables = subTableMaker();
    block blockMessage = {{0, 0, 0, 0, 0, 0, 0, 0}};
    blockMessage = stringToBlock(message);
    block key = computeKey(password);
    
    for(int k = 0; k < numRotations; k++) {
        for(int i = 0; i < blockMessage.size(); i++) {
            blockMessage[i] = key[i % 8] ^ blockMessage[i];   //message xor'd with the key
        }
        for(int i = 0; i < 8; i++){ //sub table substitions
            blockMessage[i] = subFWD(blockMessage[i], subTables[i]);
        }
        blockMessage = rotateLeft(blockMessage); //rotate left
    }
    return blockMessage;
}

block rotateRight(block &blockMessage) {
    uint8_t temp = blockMessage[blockMessage.size()-1];
    for(int i = blockMessage.size()-1; i > 0; i--){
        blockMessage[i] = (blockMessage[i] >> 1) | (blockMessage[i-1] << 7);
    }
    blockMessage[0] = (blockMessage[0] >> 1) | (temp << 7);
    return blockMessage;
}

/*
 tableInverter - inverts the substitution table for use in the decryption
 */
std::array<subTable, 8> tableInverter(std::array<subTable, 8> &subTableGrouping) {
    std::array<subTable, 8> invSubTables;
    for(int i = 0; i < 8; i++) {
        subTable currentFWD = subTableGrouping[i];
        subTable currentBKWD = invSubTables[i];
        for(int j = 0; j < currentFWD.size(); j++){
            currentBKWD[currentFWD[j]] = j;
            assert(currentBKWD[currentFWD[j]]==j);
        }
        invSubTables[i] = currentBKWD;
    }
    return invSubTables;
}

uint8_t subRev(uint8_t blockMessagei, subTable invSubTablei) {
    return invSubTablei[blockMessagei];
}

//decrypt
block decrypt(std::string password, block blockMessage) {
    block key = computeKey(password);
    std::array<subTable, 8> invSubTables = tableInverter(subTables);
    for(int k = 0; k < numRotations; k++){
        blockMessage = rotateRight(blockMessage); //rotate right
        for(int i=0; i < blockMessage.size(); i++){  //this just says from 0 to 8
            blockMessage[i] = subRev(blockMessage[i], invSubTables[i]);
        }
        //s xor k
        for(int i = 0; i < blockMessage.size(); i++) {
            blockMessage[i] = key[i % 8] ^ blockMessage[i];   //message xor'd with the key
        }
    }
    return blockMessage;
}

int main(int argc, const char * argv[]) {
    
    //Testing computeKey
    std::string pass;
    std::string messageIn;
    
    std::cout << "Please, enter your password: ";
    std::getline(std::cin, pass);
    std::cout << "Please, enter your message: ";
    std::getline(std::cin, messageIn);
    
    block cypherText = encrypt(pass, messageIn); //encryptOld, encrypt
        std::cout << "cypher text out: " << std::endl;
        for(uint8_t bit : cypherText){
            std::cout << bit << std::endl;
        }
    block messageOut = decrypt(pass, cypherText);
    std::cout << "message out: " << std::endl;
    for(uint8_t bit : messageOut){
        std::cout << bit << std::endl;
    }
    std::cout << "failed decryption with incorrect pass: " << std::endl;
    std::string badPass = "random";
    block badMessageOut = decrypt(badPass, cypherText);
    for(uint8_t bit : badMessageOut){
        std::cout << bit << std::endl;
    }
    return 0;
}
