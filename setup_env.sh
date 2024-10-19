sudo apt update
sudo apt upgrade -y

# network testing tools (curl, nmap, and other stuff)
sudo apt install -y iperf iperf3 nmap hping3 net-tools

# Openssh Server
sudo apt install -y openssh-server

# Install Python
sudo apt install -y build-essential git python3-pip python3-dev python3-setuptools
# Install packages required for developing threat detection algorithms
pip3 install numpy scipy pandas scikit-learn matplotlib

# Install Mininet
git clone https://github.com/mininet/mininet.git
cd mininet
sudo ./util/install.sh -a

# Test Mininet
sudo mn --test pingall

cd ~/

# Install Ryu SDN Controller
git clone https://github.com/faucetsdn/ryu.git
cd ryu
sudo pip3 install .

# Verify the installation
ryu-manager --version

cd ~/