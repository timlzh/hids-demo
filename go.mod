module hids

go 1.21.3

replace github.com/fananchong/gopcap => github.com/akrennmair/gopcap v0.0.0-20150728160502-00e11033259a

require (
	github.com/sirupsen/logrus v1.9.3
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/gorm v1.25.2-0.20230530020048-26663ab9bf55
)

require (
	github.com/go-sql-driver/mysql v1.7.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/mattn/go-sqlite3 v1.14.17 // indirect
)

require (
	github.com/akrennmair/gopcap v0.0.0-20150728160502-00e11033259a
	github.com/google/gopacket v1.1.19
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
	gorm.io/driver/mysql v1.5.2
	gorm.io/driver/sqlite v1.5.3
)
