# sdn-security
SDN project for CS-460: Security Laboratory

## VM Setting
- Operating System: **Ubuntu 20.04**
  VM image:
  - AMD64: https://releases.ubuntu.com/focal/
  - ARM64 (For Apple M-series chips): https://cdimage.ubuntu.com/releases/focal/release/
- Type: Linux
- Version: Ubuntu **20.04 (64-bit)**
- RAM Allocation: Allocate 4096 MB (4 GB) or more
- Storage Allocation: Create a virtual hard disk with at least 30 GB of storage
- Processors: Assign at least 2 CPU cores for better performance
- Network Adapter: NAT and Host-Only Adapter (for internet access and host-VM communication)
- Display Settings (Optional)
  - Video Memory: Set to 128 MB.
  - Graphics Controller: Choose VMSVGA.
  - Enable 3D Acceleration: Optionally check this for improved graphics performance.

### Setup Mininet & Ryu Controller
```
bash setup_env.sh
```

### Setup Zsh (Optional)
```
bash setup_zsh.sh
```

## Test Environment Setup
To start Mininet with Ryu Controller, open 2 terminals, specify port 6653 for Mininet & Ryu Controller to listen on

1. Run Mininet on the 1st terminal
```
sudo -E mn --controller=remote,ip=127.0.0.1,port=6653 --switch=ovs,protocols=OpenFlow13 --topo=single,3
```

2. Run Ryu Controller to bring up the virtual switch on the 2nd terminal
```
ryu-manager --verbose --ofp-tcp-listen-port 6653 ~/sdn-security/src/simple_switch_13.py
```

3. Try some commands to test if the network is reachable for all the hosts (h1, h2, and h3) in Mininet.
For example:
```
p1 ping p2
p1 ping p3
p3 ping p2
pingall
```

## Test DoS attack detection & mitigation
In the mininet, open a new terminal with host `h3 (10.0.0.3)`
```
mininet> xterm h3
```

Launch the DoS attack in `h3` terminal against `h1 (10.0.0.1)`
```
hping3 -S --flood -p 80 10.0.0.1
```

You should see something like the below in Ryu Controller:
```
DoS attack detected from 10.0.0.3 (packets in last interval: 268947)
Installing drop rule for IP 10.0.0.3

...

Drop packets from previous recorded malicious IP: 10.0.0.3 (packets in last interval: 6386467)
```
