# odoh-client
Oblivious DoH client

This is a command line interface as a client for performing oblivious dns-over-https queries.

### Current Support:

- [x] DoH Query : `odoh-client doh --domain www.cloudflare.com. --dnsType AAAA`
- [x] oDoH Query: `odoh-client odoh --domain www.cloudflare.com. --dnsType AAAA --key 01234567890123456789012345678912 --target 1.1.1.1`

The current implementation for oDoH uses a dummy Public Key stub on the target server which provides the public key to 
the client. In the ideal implementation, this will be obtained after performing DNSSEC validation + HTTPSSVC.

The explicit query for the public key of a target server without validation can be obtained by performing 
`odoh-client get-publickey --ip 1.1.1.1[:port]`
