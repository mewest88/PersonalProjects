This program consists of three files:
1. A securePass.hpp
2. A securePass.cpp
3. A main

The main is where my tests were run and tests agains the program can easily be run.

The only important thing about the main is that is where I define the hash map that holds all the user information, including the salt/hash struct.

To test, use the setUserInfo() method. It's input arguments are a std::string username and std::string password. It creates a salt, hash's the pass with HMAC, and saves all the information.

I also created a compare method that compares an input username and pass to an already saved username and pass in the system.