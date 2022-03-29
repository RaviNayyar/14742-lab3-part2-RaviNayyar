#!/bin/sh

# hi, my name is ovs-init, and i'm a script that you can run to convert a CORE virtual router to an OVS switch. 
# hopefully i can be a useful script to you, as that is my purpose in this world. i can do a few different things
# for you, if you ask me nicely:
#    -- if you call me with the -h flag or with arguments that confuse me, i'll print a help message
#       that will tell you what kind of commands i can understand
#    -- if you call me with no arguments at all, i'll create an OVS bridge and connect all interfaces to it
#       though i'm only taught to work with interfaces that look like "ethX" for a number X, and i can't
#       guarantee what will happen otherwise, especially if you have interfaces that start with "eth" but have
#       something other than a number after that.  please use caution.
#    -- if you call me with the -c flag followed by two additional arguments, i'll interpret those arguments as:
#           1) an interface that you want me to connect to an SDN controller instead of the OVS bridge
#           2) the IP address of the controller that can be reached using that interface
#
# if i'm not working the way you want me to, or my functionality is broken, please contact the person who 
# created me.  his name is patrick and he works at a placed called CMU.  i don't know what a CMU is, i'm just a script.

HFLAG=
CFLAG=
if [ $# -gt 0 ]; then
    while getopts :hc: name
    do
        case $name in
        h)  HFLAG=1;;
        c)  CFLAG=1
            CVAL1=$OPTARG
            shift $(($OPTIND - 1))
            if [ $# -ne 1 ]; then
                HFLAG=1
            else
                CVAL2=$1
                shift
            fi;;
        ?)  HFLAG=1;;
        esac
    done

    if [ -z $CFLAG ]; then
        shift
    fi

    if [ $# -ne 0 ]; then
        HFLAG=1
    fi
fi

if [ ! -z $HFLAG ]; then
    echo "\e[33musage: ovs-init.sh [-h] [-c <ctrl-iface> <ctrl-ipv4-addr>]"
    echo "    -h: print this usage message and exit, ignoring everything else"
    echo "    -c: enable controller on interface <ctrl-iface> and IP <ctrl-ipv4-add>"
    echo "        <ctrl-iface>: switch interface of form ethX connected to controller"
    echo "        <ctrl-ipv4-addr>: ip address of controller connected to <ctrl-iface>\e[m"
    exit 1
fi


/etc/init.d/openvswitch-switch start </dev/null
HOSTN=$NODE_NUMBER
cp /etc/openvswitch/conf.db /etc/openvswitch/conf-$HOSTN.db

ovsdb-server --remote=punix:db-$HOSTN.sock --remote=db:Open_vSwitch,Open_vSwitch,manager_options --private-key=db:Open_vSwitch,SSL,private_key  --certificate=db:Open_vSwitch,SSL,certificate --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert --pidfile=ovsdb-server-$HOSTN.pid --detach --log-file=ovsdb-server-$HOSTN.log /etc/openvswitch/conf-$HOSTN.db
ovs-vsctl --db=unix:db-$HOSTN.sock --no-wait init
ovs-vswitchd --pidfile=ovs-vswitchd-$HOSTN.pid --detach --log-file=ovs-vswitchd-$HOSTN.log unix:db-$HOSTN.sock
ovs-vsctl --db=unix:db-$HOSTN.sock add-br br -- set bridge br fail-mode=secure

IFN=$(( `ip link show | grep " eth" | wc -l` - 1))

if [ -z $CFLAG ]; then
    echo "\e[34minitializing ovs without controller\e[m"
    CTRLN=$((IFN + 1))
else
    echo "\e[34minitializing ovs with control iface $CVAL1 and IP $CVAL2\e[m"
    CTRLN=`echo $CVAL1 | sed 's/eth//g'`
    ovs-vsctl --db=unix:db-$HOSTN.sock set-controller br tcp:$CVAL2:6653
fi
    
for i in `seq 0 $IFN`; do
    if [ $i -ne $CTRLN ]; then
        echo "\e[34madding eth$i -> br @ port $(($i + 1))\e[m"
        ovs-vsctl --db=unix:db-$HOSTN.sock add-port br eth$i -- set interface eth$i ofport_request=$(($i + 1))
    fi
done

