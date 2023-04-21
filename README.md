# KRY - Cryptography

# Description

The application was created as a team project for Cryptography subject on Brno University of Technology.

The application simulates peer2peer communication between 2 clients, one acting as a ```sender(clientBob.py)``` and one acting as a ```receiver(clientAlice.py)```. 
The whole communication is build on python sockets and secured with ECC system. This includes signing files with ECDSA, calculating shared key with ECDH and encrypting the communication with ECIES.
There are also implemented features to keep the files secure on local storage, e.g. encrypting the EC private key for ECDSA with key derived from password and similarly encrypting the file intended 
to be sent if the receiver is currently unavailable.

The application in this state is intended to be run on localhost however it should be possible to modify it to work on different networks simply by changing values from localhost to desired IPs on these lines
1. clientBob: https://github.com/wojnarfilip/KRY/blob/main/src/Peer2peer/clientBob.py#L45-L46
2. clientAlice: https://github.com/wojnarfilip/KRY/blob/main/src/Peer2peer/clientAlice.py#L65-L66

Whole flow of communication is Logged into ```/src/Peer2peer/Logs```. With time of the action, message explaining the action and other relevant information like algorithms used, file size or ip addreses.

Application by default sends file ```src/Peer2peer/ResourceFiles/LikeReallySecretStuff``` and then stores this file as ```src/Peer2peer/ResourceFiles/LikeReallySecretStuffReceiver```. 
Also by default if Alice is unavailable Bob will wait for 60s. Both of these can be changed with arguments when you run the app. 
To change the time use ```-wait_time {Time in s}``` and to change the file to be sent use ```-file {Path to txt file}```

# Requirements

1. You have to have python 3.10+ installed
2. You need python libraries specified in Requirements file
   1. pip install eciespy
   2. pip install tinyec
   3. pip install pycryptodome
   4. pip install ecdsa

# How to run

### First option with terminal:

1. Install all the requirements listed above
2. clone the repository with command: ```git clone https://github.com/wojnarfilip/KRY.git```
3. open 2 terminals, 1 to run clientBob (sender) and 1 to run clientAlice(receiver)
4. navigate to folder cloned from github with: ```cd KRY```
5. display current directory with command: ```pwd```
6. in both terminals export path to this directory with: ```export PYTHONPATH={directory_displayed_by_pwd}:$PYTHONPATH``` replace {directory_displayed_by_pwd} with directory displayed by pwd command above please
7. in both terminals navigate to Peer2peer folder with: ```cd src/Peer2peer```
8. in first terminal run: ```python clientBob.py``` or alternatively with arguments```python clientBob.py -wait_time {Time in s} -file {Path to txt file}``` 
9. in second terminal run: ```python clientAlice.py```
10. Alternatively change the order in which clients are ran to test different behaviours of the application.

### Alternative option with PyCharm:
1. clone the repository with command: ```git clone https://github.com/wojnarfilip/KRY.git```
2. install all the requirements listed above
3. open cloned repository with PyCharm
4. you should be able to run clientBob.py (sender) and clientAlice.py (receiver) from the PyCharm IDE
