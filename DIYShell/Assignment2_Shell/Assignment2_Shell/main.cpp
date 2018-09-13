//
//  main.cpp
//  Assignment2_Shell
//
//  Created by Mason West on 1/29/18.
//  Copyright © 2018 Mason West. All rights reserved.
//

#include "shelpers.hpp"

#include <iostream>
#include <assert.h>
#include <string>
#include <readline/readline.h>

int main(int argc, const char * argv[]) {
    
    std::string input;
    std::vector<pid_t> zombieCheck;
    std::vector<pid_t> processes;
    
    while(getline(std::cin, input)){
        /*Get the line, pass it to getCommands, then pass it back to the main, where we will fork, clear child, and then put into the childs code. All this happens when the parent is waiting*/
        if(input == "exit") {
            exit(0);
        }
        int status;
        while(pid_t procStatus = waitpid(-1, &status, WNOHANG) > 0) {
            //remove zombie from vector // maybe close?
//            std::cout << "deleting zombie" << "\n";
            std::vector<int>::iterator position = std::find(zombieCheck.begin(), zombieCheck.end(), procStatus);
            //            if (position != zombieCheck.end()) // == myVector.end() means the element was not found
            zombieCheck.erase(position);
        }
        
        std::vector<Command> commands = getCommands(tokenize(input)); //fork, create a child, make parent wait for child -> inside child call execvp
        if(commands[0].exec == "cd") {
            std::cout << "it read cd";
            if(input.length() > 2) {
                std::cout << "its trying to do more than just cd" << "\n";
                chdir(commands[0].argv[1]);
                continue;
            } else {
                std::cout << "its trying to only home it" << "\n";
                chdir(getenv("HOME"));
                continue;
            }
        }
        for(Command command : commands) {
            int childProc = fork();
            if(command.background == true) {
                zombieCheck.push_back(childProc);
            } else {
                processes.push_back(childProc);
            }
            
            if (childProc < 0) {         // fork failed; exit
                fprintf(stderr, "fork failed\n");
                exit(-1);
            } else if (childProc == 0) { // child (new process)
                //one for loop and three if statements - for loop around - don't close until after exec and in partent and all childs have execd
                //                for(int i = 0; i < forks.size(); i++) {
                if(command.fdStdout != 1){ //if its not from the keyboard set it to the keyboard for the redirect
                    dup2(command.fdStdout, 1); //0 is read, 1 is write
                }
                if(command.fdStdin != 0){
                    dup2(command.fdStdin, 0);
                }
                int execRet = execvp(command.argv[0], const_cast<char* const*>(command.argv.data()));
                if(execRet < 0) {
                    
                }
            } else {
                // replace standard output with output part of pipe
                // close unused unput half of pipe
                if(command.fdStdin != 0){
                    close(command.fdStdin);
                }
                if(command.fdStdout != 1){
                    close(command.fdStdout);
                }
                if(command.background == false) {
                    //may need for loop for child proc here
                    waitpid(childProc, NULL, 0);
                }
            }
        }
    }
    return 0;
}
