set -eax

region+=("us-central1" "us-east1" "us-east4" "us-west1" "us-west2" "us-west3" "us-west4" "northamerica-northeast1" "southamerica-east1")
zones+=("us-central1-a" "us-east1-b" "us-east4-a" "us-west1-a" "us-west2-a" "us-west3-a" "us-west4-a" "northamerica-northeast1-a" "southamerica-east1-a")
machineType="n1-standard-1"

# Project setup information
projectName="odoh-target"
subnetCreation="default"
networkTier="PREMIUM"
metadataKeyInformation="ssh-keys=sudheesh:algorithm publickeyvalue= easyidentifiername@company.com"
maintenancePolicy="MIGRATE"
serviceAccount="1021268938009-compute@developer.gserviceaccount.com"
gcpScopes="https://www.googleapis.com/auth/devstorage.read_only,https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring.write,https://www.googleapis.com/auth/servicecontrol,https://www.googleapis.com/auth/service.management.readonly,https://www.googleapis.com/auth/trace.append"
firewallPreconfiguredTags="http-server,https-server"
operatingSystemImage="ubuntu-2004-focal-v20200720"
imageProject="ubuntu-os-cloud"
diskSize="50GB"
diskType="pd-standard"


len=${#region[@]}
for (( i=0; i<$len; i++ )); do
  clientNumber=$(($i+1))
  constructedName="client-"${clientNumber}"-"${region[$i]}
  echo "[RUNNING] Creating The Client "${constructedName}" in "${region[$i]};
  keyString="${metadataKeyInformation}"
  gcloud beta compute --project=${projectName} instances create ${constructedName} \
    --zone=${zones[$i]} \
    --machine-type=${machineType} \
    --subnet=${subnetCreation} \
    --network-tier=${networkTier} \
    --metadata="${keyString}" \
    --maintenance-policy=${maintenancePolicy} \
    --service-account=${serviceAccount} \
    --scopes=${gcpScopes} \
    --tags=${firewallPreconfiguredTags} \
    --image=${operatingSystemImage} \
    --image-project=${imageProject} \
    --boot-disk-size=${diskSize} \
    --boot-disk-type=${diskType} \
    --boot-disk-device-name=${constructedName} \
    --no-shielded-secure-boot \
    --shielded-vtpm \
    --shielded-integrity-monitoring \
    --reservation-affinity=any
  echo "[DONE   ] Finished Successfully creating the client "${constructedName};
done

gcloud compute instances list
