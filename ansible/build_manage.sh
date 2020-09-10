set +eax

echo "[STARTING SETUP OF THE TOOLS]"

sudo apt -y update
sudo apt -y install build-essential
sudo apt -y install speedtest-cli iperf3

mkdir -p ~/tmp
cd ~/tmp || exit
wget https://golang.org/dl/go1.14.6.linux-amd64.tar.gz

sudo tar -xvf go1.14.6.linux-amd64.tar.gz
sudo mv go /usr/local

cd $HOME || exit
mkdir -p $HOME/go

echo "export GOROOT=/usr/local/go" >> ~/.profile
echo "export GOPATH=$HOME/go" >> ~/.profile
echo "export PATH=$GOPATH/bin:$GOROOT/bin:$PATH" >> ~/.profile

echo "[COMPLETED SETUP OF THE TOOLS]"
