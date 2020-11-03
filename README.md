PY-PANTHER
==========

 A lite weight ADVANCED Network enumerator and an DDOS emulator
 
 ---
 INTRODUCTION
----------------
 we are going to write a penetration-testing script, namely a DDOS script, in Python. This program will allow us to flood a server with so many reqeusts that, after a while, it won’t be able to respond anymore and it will go down.

But let me give you a big warning here! Performing a DDOS attack onto any server that is not yours or you don’t have permission to attack is highly illegal. I do not recommend the attacks on any servers other than your own and I am not responsible for what you are going to do with this script. This post is purely educational and shall help you to understand networking and programming with Python. So don’t do stupid things!

WHAT IS DDOS?

DDOS stands for Distributed Denial of Service and it is an attack where we block the ressources of a server by flooding it with requests. Usually this kind of attack is never performed alone but with the help of so-called botnets.
![PY-PANTHER](https://www.neuralnine.com/wp-content/uploads/2019/09/botnet2-1024x702.png)

In a botnet, one hacker infects many computers and servers of ordinary people, in order to use them as zombies. He uses them for a collective attack onto a server. Instead of one DDOS script, he can now run thousands of them. Sooner or later the server will be overwhelmed with the amount of requests so that it is not even able to respond to an ordinary user. For smaller and weaker servers, sometimes one attacker is enough to get it down. However, usually such an attack can be counteracted by blocking the IP-addresses of the attackers.

WHAT IS NMAP?
Nmap, short for Network Mapper, is a free, open-source tool for vulnerability scanning and network discovery. Network administrators use Nmap to identify what devices are running on their systems, discovering hosts that are available and the services they offer, finding open ports and detecting security risks.



How to use it
-------
 First unload and allow permisions.
```
git clone https://github.com/redteamacademy/ADCDGRP/pypanther.git
cd pypanther
chmod +x pypanther.py
```
If it does not work, try to install all the libraries that are located in the file **requirements.txt**
```
pip install -r requirements.txt
```
RUN
```
./pypanther.py
OR
python3 pypanther.py
```
Disclaimer
-------
This tool has been published educational purposes. we are not responsible for the use or the scope that someone may have through this project.

We are totally convinced that if we teach how vulnerable things really are, we can make the Internet a safer place.

Developer
-------
ADCD STUDENTS COCHIN & CALICUT

Happy Pentesting!
-------
We invite you, if you use this tool helps to share, collaborate. Let's make the Internet a safer place, let's report.

## License

The content of this project itself is licensed under the [Creative Commons Attribution 3.0 license](http://creativecommons.org/licenses/by/3.0/us/deed.en_US), and the underlying source code used to format and display that content is licensed under the [MIT license](http://opensource.org/licenses/mit-license.php).

Copyright, REDTEAM & STUDENTS
