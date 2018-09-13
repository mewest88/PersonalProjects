# SSL Programming Secure Messaging for Systems 2

## Project Structure
This file consists of two seperate projects, each one representing the individual server.
There is a SSLProjectServer and a SSLProjectClient.
The SSLProjectServer handles the server side of the project and also has the test file that is greater then 50kb. There are also all the keys and certificate information for the server in this folder. The src folder holds all the .java files that run the server.
The SSLProjectClient handles the client side of the project and also has the output files from test the server sends over. One file is an unencrypted file sent over the socket and the other is encyrpted by the server and decrypted by the client. There are also all the keys and certificate information for the server in this folder. The src folder holds all the .java files that run the client.



Compile the program in each project with
```
javac *.java
```
To run the file, in the command line run
```
java SSLClient/SSLClientMain.java
```
or
```
java SSLServer/SSLServerMain.java
```
