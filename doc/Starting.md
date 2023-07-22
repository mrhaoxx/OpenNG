## This document helps you configure the OpenNG Server

let's start from simple.  
if you want to build just a http reserve proxy to your internal network.  
use the following template and it's done.

```yaml
version: 4

TLS:
  Certificates:
    - CertFile: /path/to/certfile.cer
      KeyFile: /path/to/keyfile.key

TCP:
  Controller:
    AddressBindings:
      - <Binding for tcp server> # listen tcp socket
    Binds:                    
      "": [det]
      TLS: [tls,det]
      TLS HTTP2: [http] 
      TLS HTTP1: [http]
      HTTP1: [rdtls]

HTTP:
  Midware:
    Binds:
      - Id: Proxier

  Proxier:
    Hosts:
    - Name: backend1
      Hosts: ["one.example.com","two.example.com"] 
      Backend: https://<to_backend_1> 
      TlsSkipVerify: true 
    - Name: backend2
      Hosts: ["*.example.com"] # allow wildcard domain
      Backend: https://<to_backend_2> 
    - Name: backend3
      Hosts: ["3rd.example.net"] 
      Backend: http://<to_backend_3>
      TlsSkipVerify: false 
    - Name: default 
      Hosts: ["*"] 
      Backend: http://<catch_other_backend>

```
if you want to provide rdp in the same port.it's also simple.
```yaml

TCP:
  Controller:
    AddressBindings:
      - <Binding for tcp server> # listen tcp socket
    Binds:                    
      "": [det]
      TLS: [tls,det]
      TLS HTTP2: [http] 
      TLS HTTP1: [http]
      HTTP1: [rdtls]
      RDP: [proxier]
  Proxier:
    Routes:
      - Name: rdp
        Backend: <windows server>:3389
        Protocol: RDP


```
just change the tcp section and it will proxy all rdp connections from ```<Binding for tcp server> ``` to ```<windows server>:3389```  
currently,it supports only tcp

if you want to add a auth layer for your internal services, just add the following context
```yaml
Auth:
  Users:
    - Username: userA
      PasswordHash: <Bcrypted Password>
    - Username: userB
      PasswordHash: <Bcrypted Password>

  Policies:

    - Name: PolicyA
      Users: [""] # not logged in
      Allowance: yes # permit
      Hosts:
        - $backend1
      Paths:
        - /
        - /pathA/.*
        - /pathB/.*
        - <regexp path>
    - Name: Public
      Allowance: yes
      Users: [ "" ]
      Hosts:
        - "www.example.com"
        - "www.example.net"
        - $backend2
    - Name: Private
      Allowance: yes
      Users: ["userA"]
    - Name: Refuse # Refuse all that hits no policy above
      Allowance: no
      Users: [""]
```

and change ```HTTP.Midware``` section to
```yaml
HTTP:
  Midware:
    Binds:
      - Id: Auth
      - Id: Proxier
```

and its done