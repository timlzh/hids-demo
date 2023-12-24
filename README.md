> Working in progress

# HIDS Demo

> A simple HIDS demo using Golang

## Working Principle

See [HIDS-Introduction](HIDS-Introduction.md)

## Usage

```bash
git clone https://github.com/timlzh/hids-demo
cd hids-demo
cp config.yaml.example config.yaml # You may need to modify the config.yaml

go build
sudo ./hids-demo
```

## TODO

- [x] Process Monitoring
- [x] Network Monitoring
- [ ] File Integrity Monitoring
- [ ] WebUI for rule management
- [ ] WebUI for alert management
