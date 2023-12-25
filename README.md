> Working in progress

# HIDS Demo

> A simple HIDS demo using Golang

## Features

### Process Monitoring

Live process monitoring, including process creation, process termination, process command line arguments, etc. With the rule engine, you can define your own rules to detect suspicious processes.

![Process Monitoring](http://pic.timlzh.com/i/2023/12/24/nvsjbs-2.png)  

### Network Monitoring

Using `pcap` to capture network packets, and then parse the packets to get the network connection information. With the rule engine, you can define your own rules to detect suspicious network connections.

![Process Monitoring](http://pic.timlzh.com/i/2023/12/24/qq9rkl-2.png)  

### File System Monitoring

With the help of [fsnotify](https://github.com/fsnotify/fsnotify), this demo can monitor the changes in specified directories and files. Including creation, deletion, modification, change in permissions, etc.

![File System Monitoring](http://pic.timlzh.com/i/2023/12/25/porx27-2.png)  

## Working Principle

See [HIDS Introduction](HIDS-Introduction.md)

## Usage

```bash
git clone https://github.com/timlzh/hids-demo
cd hids-demo
cp config.yaml.example config.yaml # You may need to modify config.yaml according to your own needs

go build
sudo ./hids-demo
```

## TODO

- [x] Process Monitoring
- [x] Network Monitoring
- [x] File System Monitoring
- [ ] File Integrity Monitoring Using Hash
- [ ] WebUI for rule management
- [ ] WebUI for alert management
