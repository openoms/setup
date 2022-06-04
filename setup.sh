# This script setup the environment needed for VPN usage on lightning network nodes
# Use with care

## collect and set some environment vars
echo "Checking setup..."

lndConf="null"
setup="null"
host=$(hostname)

if [ "$host" = "myNode" ] || [ -f /mnt/hdd/mynode/lnd/lnd.conf ]
then
    lndConf="/mnt/hdd/mynode/lnd/lnd.conf"
    setup="myNode"
elif [ "$host" = "umbrel" ] || [ -f /home/umbrel/umbrel/lnd/lnd.conf ]
then
    lndConf="/home/umbrel/umbrel/lnd/lnd.conf"
    setup="Umbrel"
elif [ "$host" = "raspiblitz" ] || [ -f /mnt/hdd/lnd/lnd.conf ]
then
    lndConf="/mnt/hdd/lnd/lnd.conf"
    setup="RaspiBlitz"
elif [ -f /data/lnd/lnd.conf ]
then
    lndConf="/data/lnd/lnd.conf"
    setup="RaspiBolt"
elif [ -f /embassy-data/package-data/volumes/lnd/data/main/lnd.conf ]
then
    lndConf="/embassy-data/package-data/volumes/lnd/data/main/lnd.conf"
    setup="Start9/EmbassyOS"
else
    echo "Type and enter path to lnd.conf and press Enter:"
    read lndConf
    if [ -f $lndConf ]; then
        echo "> file found"
        setup="custom"
    else
        echo "File not found. Please try again."
        exit 1
    fi
fi
echo "> Setup: $setup"
echo "> LNDDir: $lndConf";echo

sleep 2

echo "Checking and installing requirements...";echo

# check cgroup-tools
echo "Checking cgroup-tools..."
checkcgroup=$(cgcreate -h | grep -c Usage)
if [ $checkcgroup -eq 0 ]; then
    echo "Installing cgroup-tools...";echo
    sudo apt install -y cgroup-tools > /dev/null;echo
    echo "> cgroup-tools installed";echo
else
    echo "> cgroup-tools found";echo
fi

sleep 2

# check nftables
echo "Checking nftables installation..."
checknft=$(sudo nft -v | grep -c nftables)
if [ $checknft -eq 0 ]; then
    echo "Installing nftables...";echo
    sudo apt install -y nftables > /dev/null;echo
    echo "> nftables installed";echo
else
    echo "> nftables found";echo
fi

sleep 2

# check wireguard
echo "Checking wireguard installation..."
checkwg=$(sudo wg -v | grep -c wireguard-tools)
if [ ! -f /etc/wireguard ] && [ $checkwg -eq 0 ];then
    echo "Installing wireguard...";echo
    sudo apt install -y wireguard > /dev/null;echo
    echo "> wireguard installed";echo
else
    echo "> wireguard found";echo
fi

echo "Checking WireGuard config file, setting up split-tunneling..."
sleep 2

# check for downloaded lndHybridMode.conf, exit if not available
# get current directory
directory=$(dirname -- $(readlink -fn -- "$0"))
if [ -f $directory/lndHybridMode.conf ];then
   echo "> lndHybridMode.conf found, proceeding... ";echo
   sudo cp $directory/lndHybridMode.conf /etc/wireguard/
   echo "> lndHybridMode.conf moved to /etc/wireguard/";echo
else
   echo "> /opt/lndHybridMode.conf VPN config file not found. Please put your config file in the same directory as this script!";echo
   exit 1
fi


# setup split-tunneling
# create file
echo "#!/bin/sh
set -e
dir_netcls=\"/sys/fs/cgroup/net_cls\"
torsplitting=\"/sys/fs/cgroup/net_cls/tor_splitting\"
#modprobe cls_cgroup
if [ ! -d \"\$dir_netcls\" ]; then
  mkdir \$dir_netcls
  mount -t cgroup -o net_cls none \$dir_netcls
  echo \"> Successfully added cgroup net_cls subsystem\"
fi
if [ ! -d \"\$torsplitting\" ]; then
  mkdir /sys/fs/cgroup/net_cls/tor_splitting
  echo 1118498  > /sys/fs/cgroup/net_cls/tor_splitting/net_cls.classid
  echo \"> Successfully added Mark for net_cls subsystem\"
else
  echo \"> Mark for net_cls subsystem already present\"
fi
# add Tor pid(s) to cgroup
sudo pgrep -x tor | sudo xargs -I % sh -c 'echo % > /sys/fs/cgroup/net_cls/tor_splitting/tasks' > /dev/null
count=\$(sudo cat /sys/fs/cgroup/net_cls/tor_splitting/tasks | wc -l)
if [ \$count -eq 0 ];then
  echo \"> ERR: no pids added to file\"
  exit 1
else
  echo \"> ${count} Tor process(es) successfully excluded\";echo
fi
" > /etc/wireguard/splitting.sh

# run it
if [ -f /etc/wireguard/splitting.sh ];then
    echo "> splitting.sh created, executing...";
    # run
    sudo chmod +x /etc/wireguard/splitting.sh
    sudo su -c '/etc/wireguard/splitting.sh'
    echo "> Split-tunneling successfully executed";echo
    echo "Excluding Tor process(es) from VPN traffic..."
else
    echo "> ERR: splitting.sh execution failed";echo
    exit 1
fi

sleep 2

# add cronjob
echo "Creating cronjob..."
#echo "pgrep -x tor | xargs -I % sh -c 'echo % > /sys/fs/cgroup/net_cls/tor_splitting/tasks'" > /etc/wireguard/split.sh
#sudo chmod +x /etc/wireguard/split.sh
sudo su - -c 'crontab -l > /root/newcron'
sudo su - -c 'echo "*/5 * * * * /etc/wireguard/splitting.sh 2>&1 | /usr/bin/logger -t vpn_splitter " >> /root/newcron'
sudo su - -c 'crontab /root/newcron'
sudo su - -c 'rm /root/newcron'

echo "> cronjob added to system";echo

sleep 2

## LND configuration
# backup lnd.conf first (just in case)
backupConf=$lndConf".bak"
echo "Backing up lnd.conf..."
sudo cp $lndConf $backupConf
sudo chown $USER:$USER $backupConf
if [ -f $backupConf ];then
    echo "> Copied lnd.conf to lnd.conf.bak";echo
else
    echo "> Backup failed"
    exit 1
fi

sleep 2

# setup LND
echo "Applying changes to lnd.conf: enabling hybrid mode..."

# keep LND's default p2p port
lndInternalPort="9735"
vpnExternalIP=$(sudo grep "Endpoint" /etc/wireguard/lndHybridMode.conf | awk '{ print $3 }' | cut -d ":" -f1)
# TODO: get VPN forwarded port
vpnExternalPort=""

# add to [Application Options], if not already present
lineNumber=$(grep -n "\[Application Options\]" $lndConf | cut -d ":" -f1)
if [ "${lineNumber}" != "" ]; then
    lineNumber="$(($lineNumber+1))"
    checklisten=$(grep -c "listen=0.0.0.0:${lndInternalPort}" $lndConf)
    if [ $checklisten -eq 0 ]; then
       sed -i "${lineNumber}ilisten=0.0.0.0:${lndInternalPort}" $lndConf
       echo "> listen parameter set"
    else
       echo "> listen parameter is already set"
    fi

    checkexternalip=$(grep -c "externalip=" $lndConf)
    if [ $checkexternalip -eq 0 ]; then
       # "externalip=" not found, insert
       sed -i "${lineNumber}iexternalip=${vpnExternalIP}:${vpnExternalPort}" $lndConf
       echo "> externalip parameter set"
    else
       # "externalip=" found, remove and insert
       # get linenumbers
       lines=$(grep -n "externalip=" $lndConf | cut -d ":" -f1 | xargs | sed 's/ /;/g')
       removeString="'"$lines"d'"
       sed $removeString $lndConf
       echo "> externalip entries removed"
       # set new externalip entry
       sed -i "${lineNumber}iexternalip=${vpnExternalIP}:${vpnExternalPort}" $lndConf
       echo "> externalip parameter(s) set"
    fi
fi

# remove unnecessary entries: externalhosts=
# check if "externalhosts" is set
checkexternalhosts=$(grep -c "externalhosts=" $lndConf)
if [ $checkexternalhosts -gt 0 ]; then
   linesHosts=$(grep -n "externalhosts=" $lndConf | cut -d ":" -f1 | xargs | sed 's/ /;/g')
   removeStrings="'"$linesHosts"d'"
   sed $removeStrings $lndConf
   echo "> externalhosts parameter(s) removed"
fi


checkstreamisolation=$(grep -c "tor.streamisolation" $lndConf)
if [ $checkstreamisolation -gt 0 ];then
    sed -i 's/tor.streamisolation=true/tor.streamisolation=false/g' $lndConf
    echo "> tor.streamisolation switched to false"
else
    echo "tor.streamisolation=false" | sudo tee -a $lndConf
    echo "> tor.streamisolation set"
fi

checkskipproxy=$(grep -c "tor.skip-proxy-for-clearnet-targets" $lndConf)
if [ $checkskipproxy -gt 0 ];then
    sed -i 's/tor.skip-proxy-for-clearnet-targets=false/tor.skip-proxy-for-clearnet-targets=true/g' $lndConf
    echo "> tor.skip-proxy-for-clearnet-targets switched to true"
else
    echo "tor.skip-proxy-for-clearnet-targets=true" | sudo tee -a $lndConf
    echo "> tor.skip-proxy-for-clearnet-targets set"
fi
echo "> lnd.conf modifications applied.";echo

sleep 2

## UFW firewall configuration
echo "Checking for firewalls and adjusting settings if applicable...";
checkufw=$(ufw version | grep -c Canonical)
if [ $checkufw -eq 1 ];then
   ufw disable
   ufw allow $vpnExternalPort
   ufw --force enable
   echo "> ufw detected. VPN port rule added";echo
else
   echo "> ufw not detected";echo
fi

sleep 2

## create and enable wireguard service
echo "Initializing the service...";echo
kickoffs='✅Yes ⛔️Cancel'
PS3='Should we go ahead and autostart Wireguard at node boot? '

select kickoff in $kickoffs
do
   if [ $kickoff == '⛔️Cancel' ]
   then
      echo;echo "Please start up wireguard manually: wg-quick up lndHybridMode"
      echo "or enable systemd service with: sudo systemctl enable wg-quick@lndHybridMode";echo
      break
      exit 1
   else
     echo;echo "Alright, let's go 🚀";echo
     systemctl enable wg-quick@lndHybridMode > /dev/null
     echo "> wireguard systemd service enabled and started";echo
  fi
break
done

echo "VPN setup completed!"

# the end
exit 0
