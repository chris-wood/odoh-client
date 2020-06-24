# odoh-client
Oblivious DoH client

This is a command line interface as a client for performing oblivious dns-over-https queries.

### Current Support:

- [x] DoH Query : `odoh-client doh --domain www.cloudflare.com. --dnsType AAAA`
- [ ] oDoH Query: `odoh-client odoh --domain www.cloudflare.com. --dnsType AAAA --keyID 0123`

# Testing

Locally, using curl:

~~~
$ curl -v "http://localhost:8080/dns-query?dns=YXBwbGUuY29t"
$ curl -v -H "Content-Type:application/dns-message" -X POST -d "YXBwbGUuY29t" "http://localhost:8080/dns-query"
$ curl -v -H "Content-Type:application/dns-message" -X POST --data-binary "@/Volumes/src/oss/go/src/github.com/chris-wood/odoh-client/out" "http://localhost:8080/dns-query"
~~~

("YXBwbGUuY29t" is the base64url-encoding of "apple.com".)

After deployment, using a version of curl with DoH [https://curl.haxx.se/download.html#MacOSX]:

~~~
$ /usr/local/opt/curl/bin/curl -v --doh-url https://odoh-target-dot-odoh-254517.appspot.com/dns-query https://apple.com
$ /usr/local/opt/curl/bin/curl -v -H "Content-Type:application/oblivious-dns-message" -X POST "https://odoh-proxy-dot-odoh-254517.appspot.com/dns-query/proxy"
~~~