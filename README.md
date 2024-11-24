<h1 align="center">
  <img src="./res/NetGATE.svg" alt="Clash" width="200">
  <br>OpenNG<br>
</h1>


OpenNG is a network ingress manager.   
It is a highly configurable, extensible network ingress manager designed for labs.  
It currently supports linux, windows, macos  

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
	- the feature provides simple but strong protection for exposing internal http services like qbitorrent, router management, your own services and etc.
		- regexp match for path and host
		- flexible configuration
		- delicate web auth page
	- partially support ldap as auth backend 
- HTTP Virtual Host & Reserve Proxy
	- support websocket without any configuration
	- support h2
	- compliant for most IPMI html5 consoles
- HTTP Forward Proxy
	- support http proxy basic auth
- Socks5 Proxy
  - support socks5 proxy
- SSH Virtual Host
	- high compatibility with all backend ssh features
		- can use with vscode, etc.
	- only allow pubkey auth
	- support a custom banner and random quote memes
- TLS
	- supports sni, alpn and multi-certificates
- IP Filter & Host Filter
	- support ip range
	- support host regexp for white list
- Logging
	- supports udp logging output
		- with a analyzer, we can turn the log data structed to write to influxdb  
- DNS Server


## Installation
You can find the *(not that)latest* OpenNG release on the [release page](https://github.com/mrhaoxx/OpenNG/releases). But a release is not made so often. So I recommend you to **build it yourself**.

We provide a up-to-date docker image on [dockerhub](https://hub.docker.com/r/mrhaoxx/ng), which is built by github actions from the latest main branch. I highly recommend you to **use the docker image**.

### Build from source
```bash
git clone https://github.com/mrhaoxx/OpenNG
cd OpenNG
bash build.sh
```

### Docker
```bash
docker run -it -v /path/to/config.yaml:/config.yaml --network host mrhaoxx/ng:main
```

## Configuration
OpenNG currently uses only one yaml as configuration file.  
The yaml file is divided into several sections.

You can find the structure of the configuration file in the [builtin.go](./ui/builtin.go).  
The `_builtin_refs_assertions` holds all structure of the configuration file.  

A simple example of the configuration file is as follows:
```yaml
version: 5

Config:
  Logger:
    EnableSSELogger: true
    Verbose: true

Services:
  - name: tls
    kind: builtin::tls
    spec:
      certificates:
        - CertFile: /cert/fullchain.cer
          KeyFile: /cert/example.com.key

  - name: fauth
    kind: builtin::auth::backend::file
    spec:
      users:
        - name: user
          PasswordHash: # Gen you password hash with the tool below
          AllowForwardProxy: true
          SSHAuthorizedKeys:
            - ssh pubkey (ssh authoried_keys format)

  - name: policyd
    kind: builtin::auth::policyd
    spec:
      Policies:
        - name: Public
          Allowance: true
          Users: [ "" ]
          Hosts:
            - $dref{http:proxier.spec.hosts.pub.hosts}...

        - name: Private
          Allowance: true
          Users: ["user"]

        - name: Refuse
          Allowance: false
          Users: [""]
          Hosts:
            - "*"
      backends:
        - $ptr{fauth}

  - name: auth
    kind: builtin::auth::manager
    spec:
      backends:
        - $ptr{policyd}
        
  - name: http:proxier
    kind: builtin::http::reverseproxier
    spec:
      hosts:
        - name: router
          hosts: [router.example.com]
          backend: https://192.168.1.1
          TlsSkipVerify: true
          MaxConnsPerHost: 8
 		- name: pub
          hosts: ["*.example.com", "example.com"]
          backend: https://a-backend-host

  - name: http:stdforward
    kind: builtin::http::forwardproxier

  - name: http:midware
    kind: builtin::http::midware
    spec:
      cgis: 
        - logi: $ptr{policyd}
      forward: # forward proxy
        - logi: $ptr{policyd}
          name: auth
        - logi: $ptr{http:stdforward}
          name: stdfwd

  - name: sshrp
    kind: builtin::ssh::reverseproxier
    spec:
      hosts:
        - name: backend-1  # default
          HostName: sshhost1
        - name: backend-2
          HostName: sshhost2

      privatekeys:  $dref{ssh.spec.privatekeys}
  - name: ssh
    kind: builtin::ssh::midware
    spec:
      services:
        - name: reverseproxy
          logi: $ptr{sshrp} 
      privatekeys: |
	  	Fill your private key (PEM Encoding) here

      banner: |
         Authorized access only!
          Your IP: %h
      policyd: $ptr{policyd}

  - name: tcp:det
    kind: builtin::tcp::det
    spec:
      protocols:
        [tls,ssh,rdp,http,proxyprotocol]
      timeout: 3000000000 # 3s
      timeoutprotocol: TIMEOUT

  - name: tcp:securehttp
    kind: builtin::tcp::securehttp

  - name: tcp:controller
    kind: builtin::tcp::controller
    spec:
        services:
          "": 
           - logi: $ptr{tcp:det}
             name: det 
          TLS: 
          #  - logi: $ptr{hif}
          #    name: hif
           - logi: $ptr{tls}
             name: tls 
           - logi: $ptr{tcp:det}
             name: det
          TLS HTTP2:  
           - logi: $ptr{http:midware}
             name: http 
          TLS HTTP1: 
           - logi: $ptr{http:midware}
             name: http 
          HTTP1: 
        #    - logi: $ptr{tcp:securehttp}
        #      name: http 
		## Use the above line if you want to redirect all http to https
           - logi: $ptr{http:midware}
             name: http 
          SSH: 
           - name: ssh
             logi: $ptr{ssh}
          TIMEOUT:
           - name: ssh
             logi: $ptr{ssh}



  - name: ui
    kind: builtin::webui
    spec:
      httpmidware: $ptr{http:midware}
      tcpcontroller: $ptr{tcp:controller}

  - kind: builtin::http::midware::addservice
    name: bi
    spec:
      midware: $ptr{http:midware}
      services:
        - logi: $ptr{auth}
          name: auth
        - name: ui
          logi: $ptr{ui}
          hosts:
            - netgate.example.com
        - logi: $ptr{http:proxier}
          name: prx

  - kind: builtin::tcp::listen
    spec:
        AddressBindings:
          - 0.0.0.0:4430
          - 0.0.0.0:4431
        ptr: $ptr{tcp:controller}



```


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


