set +eax

sudo apt remove resolvconf
sudo cp /etc/resolv.conf /etc/resolv.conf.backup
sudo rm -rf /etc/resolv.conf
sudo cp ~/resolv.conf /etc/resolv.conf
