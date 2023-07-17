<h1 align="center">
  <img src="./res/NetGATE.svg" alt="Clash" width="200">
  <br>OpenNG<br>
</h1>


OpenNG is a network ingress manager.   
It is a highly configurable, extensible network ingress manager designed for homelab    
It currently supports linux, windows, macos  
*Live restart is not supported in windows*


## Features
- TCP PORT MUX  
	- Supported Protocols
		- TLS
		- HTTP1 HTTP2
		- RDP
		- SSH
		- PROXYPROTOCOL
	- the feature enables to serve multi-protocols on one port
- Simple Auth
	- the feature provides simple but strong protection for exposing internal services like qbitorrent, router management, msft rdp, your own services and etc.
	- supports http
		- regexp match for path and host
		- flexible configuration
		- delicate web auth page
		- support tmp auth
	- supports any tcp protocol
		- it can block any unwanted tcp connection in a certain protocol like rdp
	- Dingding Realtime Log Pushing and Managing
- HTTP Reserve Proxy
	- support websocket without any configuration
	- support h2
- TLS
	- supports sni, alpn and multi-certificates
- Logging
	- supports udp logging output
		- with a analyzer, we can turn the log data structed to write to influxdb  


### Tools To Generate Password Hash
We use bcrypt to hash the password

```go
package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func main() {
	var password string
	fmt.Print("Enter password: ")
	fmt.Scanln(&password)

	hash, _ := HashPassword(password)

	fmt.Println("Hash:    ", hash)
}
```


