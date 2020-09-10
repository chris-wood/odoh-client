set +eax

./odoh-client odoh --domain www.github.com. --dnstype AAAA --target odoh-target-dot-odoh-target.wm.r.appspot.com --proxy odoh-proxy-dot-odoh-target.wm.r.appspot.com
./odoh-client odoh --domain www.github.com. --dnstype AAAA --target odoh-target-rs.crypto-team.workers.dev --proxy odoh-proxy-dot-odoh-target.wm.r.appspot.com
./odoh-client odoh --domain www.github.com. --dnstype AAAA --target odoh-target-rs.crypto-team.workers.dev --proxy odoh-rs-proxy.crypto-team.workers.dev
./odoh-client odoh --domain www.github.com. --dnstype AAAA --target odoh-target-dot-odoh-target.wm.r.appspot.com --proxy odoh-rs-proxy.crypto-team.workers.dev