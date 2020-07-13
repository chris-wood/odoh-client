# odoh-client
Oblivious DoH client

This is a command line interface as a client for performing oblivious dns-over-https queries.

### Current Support:

- [x] DoH Query : `odoh-client doh --domain www.cloudflare.com. --dnsType AAAA`
- [x] oDoH Query: `odoh-client odoh --domain www.cloudflare.com. --dnsType AAAA --key 01234567890123456789012345678912 --target 1.1.1.1`
- [x] oDoH Query via Proxy: `odoh-client odoh --domain www.cloudflare.com --dnsType AAAA --key 01234567890123456789012345678912 --target 1.1.1.1 --use-proxy true --proxy sampleproxy.service.hosted.net[:port]`

The current implementation for oDoH uses a dummy Public Key stub on the target server which provides the public key to 
the client. In the ideal implementation, this will be obtained after performing DNSSEC validation + HTTPSSVC.

The explicit query for the public key of a target server without validation can be obtained by performing 
`odoh-client get-publickey --ip 1.1.1.1[:port]`

For the `proxy` usage, the client treats the `target` as the hostname and port of the intended target to which the proxy
needs to forward the ODOH message and obtain a response from. The client then uses the `key` to decrypt the obtained 
response from the Oblivious Target.

### Tests

| GCP Instances | Link                                           | Active  |
|---------------|------------------------------------------------|---------|
| Target Server | odoh-target-dot-odoh-target.wm.r.appspot.com   | &check; |
| Proxy Server  | odoh-proxy-dot-odoh-target.wm.r.appspot.com    | &check; |

#### DOH Query to target

```sh
./odoh-client doh --domain www.apple.com. --target odoh-target-dot-odoh-target.wm.r.appspot.com --dnstype AAAA
```


#### ODOH Query to target

```sh
./odoh-client odoh --domain www.cloudflare.com. --dnstype AAAA --target odoh-target-dot-odoh-target.wm.r.appspot.com --key 01234567890123456789012345678912
```

#### ODOH Query to target via a proxy

```sh
./odoh-client odoh --domain www.cloudflare.com. --dnstype AAAA --target odoh-target-dot-odoh-target.wm.r.appspot.com --key 01234567890123456789012345678912 --proxy odoh-proxy-dot-odoh-target.wm.r.appspot.com
```

#### Get Public Key of a target

```sh
./odoh-client get-publickey --ip odoh-target-dot-odoh-target.wm.r.appspot.com
```
