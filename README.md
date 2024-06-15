# C-SSH-Bruteforce
C++ SSH Bruter, multi functionality including telegram bot outputting, honeypot logging, server details including cpu, processors, gpu, and more.

# Setup
First run these commands on the server:

Debian/Ubuntu:

apt-get update -y
apt-get install libssh-dev libcurl4-openssl-dev libjsoncpp-dev -y
apt-get install cmake make g++ -y
apt-get install curl -y

Redhat/Centos:

yum update -y 
yum install libssh-devel libcurl-devel jsoncpp-devel -y
yum install cmake make gcc-c++ -y
yum install curl -y

After installing all of the above run this command to compile and build: "g++ -o brute brute.cpp -I/usr/include/jsoncpp -L/usr/lib -lssh -lcurl -ljsoncpp -pthread"

How to run: ./brute ssh-port threads "remote-command"

Example: ./brute 22 64000 "echo hello"

NOTE: Do not exceed 64000 threads as there is only around 64000 available ports to utilize as your range is 1024 - 65535, increasing the thread count will not do anything past this number.

# Combos File
The combos file can be found under int main, you can change to any name you want. The default combo file name is combos.txt.

The format of the combos is "username:password", does not support whitespace for example:

root:root
root:rooot
