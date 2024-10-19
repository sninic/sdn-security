# sdn-security-project
SDN project for CS-460: Security Laboratory

## VM Setting
- Operating System: Ubuntu 20.04
- Type: Linux
- Version: Ubuntu **20.04** (64-bit)
- RAM Allocation: Allocate 4096 MB (4 GB) or more
- Storage Allocation: Create a virtual hard disk with at least 30 GB of storage
- Processors: Assign at least 2 CPU cores for better performance
- Network Adapter: NAT and Host-Only Adapter (for internet access and host-VM communication)
- Display Settings (Optional)
  - Video Memory: Set to 128 MB.
  - Graphics Controller: Choose VMSVGA.
  - Enable 3D Acceleration: Optionally check this for improved graphics performance.

## Test Environment Setup
To start Mininet with Ryu Controller, open 2 terminals, specify port 6653 for Mininet & Ryu Controller to listen on

1. Run Mininet on the 1st terminal
```
sudo mn --controller=remote,ip=127.0.0.1,port=6653 --switch=ovs,protocols=OpenFlow13 --topo=single,3
```

2. Run Ryu Controller to bring up the virtual switch on the 2nd terminal
```
ryu-manager --verbose --ofp-tcp-listen-port 6653 ~/sdn-security-project/src/simple_switch_13.py
```

3. Try some commands to test if the network is reachable for all the hosts (h1, h2, and h3) in Mininet
For example:
```
p1 ping p2
p1 ping p3
p3 ping p2
pingall
```
