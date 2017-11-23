
# Note

Dns2tcp is a tool for relaying TCP connections over DNS. There is only
a simple identification mecanism but no encryption : DNS encapsulation
must be considered as an unsecure and anonymous transport
layer. Resources should be public external services like ssh,
ssltunnel ...  


## Examples


### Client:


View list of available connection.
```sh
	$ dns2tcpc -z dns2tcp.hsc.fr -k <my-key>  <dns_server>
	Available connection(s) :
	        ssh-gw
	        ssh6-home
	        ssl-tunnel
	$
```
Line based connection to a remote ssl-tunnel host :
```sh
	$ dns2tcpc -r ssl-tunnel -l 4430 -k <my-key> -z dns2tcp._hsc.fr <dns_server>
	listening on port 4430
	...
	
```
File configuration :
```sh
	$ cat > ~/.dns2tcprc << EOF
	
	domain = dns2tcp.hsc.fr
	resource = ssl-tunnel
	local_port = 4430
	debug_level = 1
	key = whateveryouwant
	server = the_dns_server # or scan /etc/resolv.conf
	EOF
	$ dns2tcpc
```

### Server :

File configuration :

```sh
	$ cat > ~/.dns2tcpdrc << EOF
	
	listen = x.x.x.x
	port = 53
	user = nobody
	key = whateveryouwant
	chroot = /var/empty/dns2tcp/
	domain = dns2tcp.hsc.fr
	resources = ssh:127.0.0.1:22 ,          smtp:127.0.0.1:25,
	                pop3:10.0.0.1:110, ssh2:[fe80::1664]:22
	
	EOF
	$ ./dns2tcpd -F -d 1

```

# Known Bugs

DNS desynchronisation
dns2tcpd server not supported on Windows

