## 14-742 Spring 2022
### Lab 3: Part I

Starter code files for Lab 3 Part I:
* lab3-sdn0.xml ==> simple network topology with controller, switch, and two PCs
* lab3-sdn1.xml ==> larger network topology with multiple subnets, two PCs per subnet, each switch connected to a subnet, two other switches, and a controller
* init-ovs.sh ==> shell script for configuring CORE router as OVS switch
* init_and_learn.py ==> Ryu control application to push ARP rules and support ping request/reply via PacketIn

Add to this file as you expand the contents of the repository


Starting the standard or smurf ICMP flooding attack

    - Open the attacker host terminal
    - to start the smurf attack
        <path to task2_icmp_flooding.py> True 
    - to start the standard attack
        <path to task2_icmp_flooding.py> False 
