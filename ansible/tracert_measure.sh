set +eax

HOST+=("alpha-odoh-rs-proxy.research.cloudflare.com" "odoh-proxy-dot-odoh-target.wm.r.appspot.com" "odoh-target-rs.crypto-team.workers.dev" "odoh-target-dot-odoh-target.wm.r.appspot.com")

len=${#HOST[@]}
for (( i=0; i<$len; i++)); do
  queryHost=${HOST[i]}
  num=$(traceroute $queryHost | wc -l);
  echo "$queryHost : $((num-1))"
done
