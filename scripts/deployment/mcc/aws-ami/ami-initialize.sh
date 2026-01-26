#!/bin/bash

set -eo pipefail

DEFAULT_ONPREM_DNS=$(TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` && curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-hostname)
ONPREM_DNS="${ONPREM_DNS:-$DEFAULT_ONPREM_DNS}"
ROLE=$(TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` && curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/)
HTTPS_ENABLED="${HTTPS_ENABLED:-false}"


DEFAULT_HOME_REGION=$(TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` && curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
HOME_REGION="${HOME_REGION:-$DEFAULT_HOME_REGION}"
LOG_PATH="${LOG_PATH:-/var/log/maestro-init.log}"
ERROR_LOG_PATH="${ERROR_LOG_PATH:-/var/log/maestro-init.log}"

HELM_REPOSITORY="${HELM_REPOSITORY:-https://charts-repository.s3.eu-west-1.amazonaws.com/mcc/}"
HELM_RELEASE_NAME="${HELM_RELEASE_NAME:-maestro}"

DOCKER_VERSION="${DOCKER_VERSION:-5:27.1.1-1~debian.12~bookworm}"
MINIKUBE_VERSION="${MINIKUBE_VERSION:-v1.33.1}"
KUBERNETES_VERSION="${KUBERNETES_VERSION:-v1.30.0}"
KUBECTL_VERSION="${KUBECTL_VERSION:-v1.30.3}"
HELM_VERSION="${HELM_VERSION:-3.15.4-1}"
EFS_DNS="$EFS_FILE_SYSTEM_ID.efs.$HOME_REGION.amazonaws.com"
EFS_UTILS_VERSION_TAG="${EFS_UTILS_VERSION_TAG:-v2.4.0}"

LM_API_LINK="${LM_API_LINK:-https://lm.syndicate.team}"

FIRST_USER="${FIRST_USER:-$(getent passwd 1000 | cut -d : -f 1)}"
MAESTRO_WORKING_DIR=$( getent passwd "$FIRST_USER" | cut -d: -f6 )
DO_NOT_ACTIVATE_LICENSE="${DO_NOT_ACTIVATE_LICENSE:-}"
APPLICATIONS_DATA_PATH='/var/lib/docker/volumes/maestro/_data/data'

# profiles
SPRING_PROFILES=""
STORAGE_PROFILE="${STORAGE_PROFILE:-local}"
MONGO_PROFILE="${MONGO_PROFILE:-local}"
VAULT_PROFILE="${VAULT_PROFILE:-local}"
RABBITMQ_PROFILE="${RABBITMQ_PROFILE:-local}"

SPRING_PROFILES+="ftlFromClasspath\,deployedInAws"
if [[ $RABBITMQ_PROFILE == "external"  ||  $MONGO_PROFILE == "external"  ||  $STORAGE_PROFILE == "external"  ||  $VAULT_PROFILE == "external" ]]; then
    SSM_CREDENTIALS_DATA=$(aws ssm get-parameter --name "Maestro.cloud.credentials" --region $HOME_REGION --with-decryption | jq -r '.Parameter.Value')
    MODULAR_API_SECRET_KEY="$(echo $SSM_CREDENTIALS_DATA | jq -r '.MODULAR_API_SECRET_KEY // empty')"
    MODULAR_SDK_ACCESS_KEY="$(echo $SSM_CREDENTIALS_DATA | jq -r '.MODULAR_SDK_ACCESS_KEY // empty')"
    MODULAR_SDK_SECRET_KEY="$(echo $SSM_CREDENTIALS_DATA | jq -r '.MODULAR_SDK_SECRET_KEY // empty')"
    ENVIRONMENT="$(echo $SSM_CREDENTIALS_DATA | jq -r '.ENVIRONMENT // empty')"
    DATALAKE_BUCKET="$(echo $SSM_CREDENTIALS_DATA | jq -r '.DATALAKE_BUCKET // empty')"
    DATALAKE_BUCKET_SOURCE_REGION="${DATALAKE_BUCKET_SOURCE_REGION:-eu-central-1}"
    MODULAR_MAESTRO_USER="$(echo $SSM_CREDENTIALS_DATA | jq -r '.MODULAR_MAESTRO_USER // empty')"
    MODULAR_REPORT_BUCKET="$(echo $SSM_CREDENTIALS_DATA | jq -r '.MODULAR_REPORT_BUCKET // empty')"
    DEPLOY_TARGET_BUCKET="$(echo $SSM_CREDENTIALS_DATA | jq -r '.DEPLOY_TARGET_BUCKET // empty')"
    MODULAR_BUCKET="$(echo $SSM_CREDENTIALS_DATA | jq -r '.MODULAR_BUCKET // empty')"
fi

if [[ $MONGO_PROFILE == "external" ]]; then
    MONGO_USERNAME=$(echo $SSM_CREDENTIALS_DATA | jq -r '.MONGO_USERNAME')
    MONGO_PASSWORD=$(echo $SSM_CREDENTIALS_DATA | jq -r '.MONGO_PASSWORD')
    MONGO_HOST=$(echo $SSM_CREDENTIALS_DATA | jq -r '.MONGO_HOST')
    MONGO_PORT=$(echo $SSM_CREDENTIALS_DATA | jq -r '.MONGO_PORT')
    MONGO_URI=$(echo $SSM_CREDENTIALS_DATA | jq -r '.MONGO_URI')
    MONGO_OPERATION_URI=$(echo $SSM_CREDENTIALS_DATA | jq -r '.MONGO_OPERATION_URI')
    MONGO_BILLING_URI=$(echo $SSM_CREDENTIALS_DATA | jq -r '.MONGO_BILLING_URI')
    SPRING_PROFILES+="\,mongoDBForUIServer\,configurationFromDBServerConfig"
else
    SPRING_PROFILES+="\,mongoDBForUIServer\,configurationFromProperties"
fi
if [[ $RABBITMQ_PROFILE == "external" ]]; then
    RABBITMQ_USERNAME=$(echo $SSM_CREDENTIALS_DATA | jq -r '.RABBITMQ_USERNAME')
    RABBITMQ_PASSWORD=$(echo $SSM_CREDENTIALS_DATA | jq -r '.RABBITMQ_PASSWORD')
    RABBITMQ_HOST=$(echo $SSM_CREDENTIALS_DATA | jq -r '.RABBITMQ_HOST')
    RABBITMQ_PORT=$(echo $SSM_CREDENTIALS_DATA | jq -r '.RABBITMQ_PORT')
    RABBITMQ_VHOST=$(echo $SSM_CREDENTIALS_DATA | jq -r '.RABBITMQ_VHOST')
    RABBITMQ_URI=$(echo $SSM_CREDENTIALS_DATA | jq -r '.RABBITMQ_URI')
fi
if [[ $STORAGE_PROFILE == "external" ]]; then
    SPRING_PROFILES+="\,s3"
    M3_UI_SDK_PATH=$(echo $SSM_CREDENTIALS_DATA | jq -r '.M3_UI_SDK_PATH')
    M3_UI_SDK_BUCKET=$(echo $SSM_CREDENTIALS_DATA | jq -r '.M3_UI_SDK_BUCKET')
else
    SPRING_PROFILES+="\,minio"
fi
if [[ $VAULT_PROFILE == "external" ]]; then
    SPRING_PROFILES+="\,ssm"
else
    SPRING_PROFILES+="\,vault"
fi
if [[ $CONNECT_EXTERNAL_GRAYLOG == "true" ]]; then
    INSTANCE_HOSTNAME_FOR_GRAYLOG=$(echo $SSM_CREDENTIALS_DATA | jq -r '.INSTANCE_HOSTNAME_FOR_GRAYLOG')
    GRAYLOG_HOST=$(echo $SSM_CREDENTIALS_DATA | jq -r '.GRAYLOG_HOST')
    SPRING_PROFILES+="\,graylog"
fi

log() { echo "[INFO] $(date) $1" >> "$LOG_PATH"; }
log_err() { echo "[ERROR] $(date) $1" >> "$ERROR_LOG_PATH"; }
get_imds_token () {
  local duration="${1:-10}"
  curl -sf -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: $duration"
}
get_from_metadata() { curl -sf -H "X-aws-ec2-metadata-token: $(get_imds_token)" "http://169.254.169.254/latest$1"; }
identity_document() { get_from_metadata "/dynamic/instance-identity/document"; }
document_signature() { get_from_metadata "/dynamic/instance-identity/signature" | tr -d '\n'; }
region() { get_from_metadata "/dynamic/instance-identity/document" | jq -r ".region"; }
request_to_lm() { curl -sf -X POST -d "{\"signature\":\"$(document_signature)\",\"document\":\"$(identity_document | base64 -w 0)\"}" "$LM_API_LINK/marketplace/maestro/init"; }
generate_password() {
  chars="20"
  typ='-base64'
  if [ "$1" == "sdk" ]; then
    local length=32
    local password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c $((length - 3)))
    password+=$(tr -dc 'a-z' < /dev/urandom | head -c 1)
    password+=$(tr -dc 'A-Z' < /dev/urandom | head -c 1)
    password+=$(tr -dc '0-9' < /dev/urandom | head -c 1)
    password=$(echo "$password" | fold -w1 | shuf | tr -d '\n')
    echo "$password"
  else
    if [ -n "$1" ]; then
      chars="$1"
    fi
    if [ -n "$2" ]; then
      typ="$2"
    fi
    # Default behavior with openssl
    openssl rand "$typ" "$chars"
  fi
}
minikube_ip(){ sudo su "$FIRST_USER" -c "minikube ip --profile maestro"; }
enable_minikube_service() {
  sudo tee /etc/systemd/system/maestro-minikube.service <<EOF > /dev/null
[Unit]
Description=Maestro Cloud Control minikube start up
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/bin/minikube start --profile maestro --force --interactive=false
ExecStop=/usr/bin/minikube stop --profile maestro
User=$FIRST_USER
Group=$FIRST_USER
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl enable maestro-minikube.service
}
upgrade_and_install_packages() {
  sudo sed -i "/#\$nrconf{restart} = 'i';/s/.*/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
  sudo sed -i "s/#\$nrconf{kernelhints} = -1;/\$nrconf{kernelhints} = -1;/g" /etc/needrestart/needrestart.conf
  sudo apt clean
  sudo apt autoclean
  sudo DEBIAN_FRONTEND=noninteractive apt --fix-broken install -y
  sudo DEBIAN_FRONTEND=noninteractive apt update -y
  sudo DEBIAN_FRONTEND=noninteractive apt upgrade -y
  sudo DEBIAN_FRONTEND=noninteractive apt install -y jq curl python3-pip locales-all nginx pipx unzip
}
install_docker() {
  # Add Docker's official GPG key: from https://docs.docker.com/engine/install/debian/
  sudo DEBIAN_FRONTEND=noninteractive apt install -y ca-certificates curl
  sudo install -m 0755 -d /etc/apt/keyrings
  sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  sudo chmod a+r /etc/apt/keyrings/docker.asc
  # Add git apt repo
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo DEBIAN_FRONTEND=noninteractive apt update -y
    sudo DEBIAN_FRONTEND=noninteractive apt install -y docker-ce docker-ce-cli containerd.io
}
install_minikube() {
  curl -LO "https://storage.googleapis.com/minikube/releases/$1/minikube_latest_$(dpkg --print-architecture).deb"
  sudo dpkg -i "minikube_latest_$(dpkg --print-architecture).deb" && rm "minikube_latest_$(dpkg --print-architecture).deb"
}
install_kubectl() {
  curl -LO "https://dl.k8s.io/release/$1/bin/linux/$(dpkg --print-architecture)/kubectl"
  curl -LO "https://dl.k8s.io/release/$1/bin/linux/$(dpkg --print-architecture)/kubectl.sha256"
  echo "$(cat kubectl.sha256) kubectl" | sha256sum --check || exit 1
  sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl && rm kubectl kubectl.sha256
}
install_helm() {
  sudo DEBIAN_FRONTEND=noninteractive  apt install curl gpg apt-transport-https --yes
  curl -fsSL https://packages.buildkite.com/helm-linux/helm-debian/gpgkey | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://packages.buildkite.com/helm-linux/helm-debian/any/ any main" | sudo tee /etc/apt/sources.list.d/helm-stable-debian.list
  sudo DEBIAN_FRONTEND=noninteractive  apt update -y
  sudo DEBIAN_FRONTEND=noninteractive  apt install helm="$1" --allow-downgrades -y
}
install_efs_utils() {
  sudo DEBIAN_FRONTEND=noninteractive  apt update -y
    sudo DEBIAN_FRONTEND=noninteractive  apt install -y build-essential nfs-common libssl-dev pkg-config stunnel4 golang cmake perl gcc g++
    if [ ! -d "efs-utils" ] ; then
        git clone https://github.com/aws/efs-utils.git efs-utils
    else
        echo "[INFO] Skipping clone, efs-utils already exists"
    fi
    cd efs-utils
    git checkout "$EFS_UTILS_VERSION_TAG"
    sudo bash -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    sudo bash -c "source /root/.cargo/env && ./build-deb.sh"
    sudo cp build/amazon-efs-utils*.*.deb $MAESTRO_WORKING_DIR/
    cd $MAESTRO_WORKING_DIR
    sudo rm -rf efs-utils
    sudo dpkg -i amazon-efs-utils*.*.deb
}
nginx_conf() {
  cat <<EOF
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
worker_rlimit_nofile 8192;
events {
    worker_connections 4096;
}
http {
    access_log off;
    server_tokens off;
    gzip on;
    gzip_min_length 10240;
    gzip_disable msie6;
    gzip_types application/json;

    client_body_timeout 5s;
    client_header_timeout 5s;
    limit_req_zone \$binary_remote_addr zone=req_per_ip:10m rate=30r/s;
    limit_req_status 429;

    include /etc/nginx/mime.types;
    include /etc/nginx/sites-enabled/*;
}
EOF
}
nginx_minio_api_conf() {
  cat <<EOF
server {
    listen 9000;
    ignore_invalid_headers off;
    client_max_body_size 0;
    proxy_buffering off;
    proxy_request_buffering off;
    location / {
        include /etc/nginx/proxy_params;
        proxy_connect_timeout 300;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        chunked_transfer_encoding off;
        proxy_pass http://$(minikube_ip):32102;
   }
}
EOF
}
nginx_minio_api_https_conf() {
  cat <<EOF
server {
    listen 9000 ssl;
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ignore_invalid_headers off;
    client_max_body_size 0;
    proxy_buffering off;
    proxy_request_buffering off;
    location / {
        include /etc/nginx/proxy_params;
        proxy_connect_timeout 300;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        chunked_transfer_encoding off;
        proxy_pass https://$(minikube_ip):32102;
   }
}
EOF
}
nginx_minio_console_conf() {
  cat <<EOF
server {
    listen 9001;
    ignore_invalid_headers off;
    client_max_body_size 0;
    proxy_buffering off;
    proxy_request_buffering off;
    location / {
        include /etc/nginx/proxy_params;
        proxy_set_header X-NginX-Proxy true;
        real_ip_header X-Real-IP;
        proxy_connect_timeout 300;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        chunked_transfer_encoding off;
        proxy_pass http://$(minikube_ip):32103;
   }
}
EOF
}
nginx_minio_console_https_conf() {
  cat <<EOF
server {
    listen 9001 ssl;
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ignore_invalid_headers off;
    client_max_body_size 0;
    proxy_buffering off;
    proxy_request_buffering off;
    location / {
        include /etc/nginx/proxy_params;
        proxy_set_header X-NginX-Proxy true;
        real_ip_header X-Real-IP;
        proxy_connect_timeout 300;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        chunked_transfer_encoding off;
        proxy_pass https://$(minikube_ip):32103;
   }
}
EOF
}
nginx_vault_conf() {
  # Debugging
  cat <<EOF
server {
    listen 8200;
    location / {
        include /etc/nginx/proxy_params;
        proxy_pass http://$(minikube_ip):32100;
    }
}
EOF
}
nginx_modular_api_conf() {
  cat <<EOF
server {
    listen 8085;
    location / {
        include /etc/nginx/proxy_params;
        proxy_redirect off;
        proxy_pass http://$(minikube_ip):32105;
        limit_req zone=req_per_ip burst=5 nodelay;
    }
}
EOF
}
nginx_rabbitmq_conf() {
  cat <<EOF
server {
    listen 15672;
    ignore_invalid_headers off;
    client_max_body_size 0;
    proxy_buffering off;
    proxy_request_buffering off;
    location / {
        include /etc/nginx/proxy_params;
        proxy_connect_timeout 300;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        chunked_transfer_encoding off;
        proxy_pass http://$(minikube_ip):31672;
   }
}
EOF
}
nginx_maestro_conf() {
  cat <<EOF
server {
    listen 80;
    location = /minioapi/static/DEV/sdk.js {
        rewrite /minioapi(.*) \$1 break;
        proxy_pass http://$(minikube_ip):32190;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location ~* ^/maestro/api/.*\.(js|css|png)$ {
        proxy_pass http://$(minikube_ip):32180;
        proxy_redirect     off;
        proxy_set_header   Host             \$host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
    }
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|woff|woff2|ttf|svg|eot)$ {
        proxy_pass http://$(minikube_ip):32300;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location /cli {
        proxy_pass http://$(minikube_ip):32102/m3-cli-bucket;
        proxy_redirect     off;
        proxy_set_header   Host             \$host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
    }
    location / {
        proxy_pass http://$(minikube_ip):32300;
        proxy_redirect     off;
        proxy_set_header   Host             \$http_host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        try_files \$uri \$uri/ /index.html;
    }
    location /minio {
        proxy_pass http://$(minikube_ip):32102;
        proxy_redirect     off;
        proxy_set_header   Host             \$host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
    }
    location /minioapi {
        rewrite /minioapi(.*) \$1 break;
        proxy_pass http://$(minikube_ip):32190;
        proxy_redirect     off;
        proxy_set_header   Host             \$host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
    }
    location /vault {
        proxy_pass http://$(minikube_ip):32100;
        proxy_redirect     off;
        proxy_set_header   Host             \$host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
    }
    location /maestro/api {
        proxy_pass http://$(minikube_ip):32180/maestro/api;
        proxy_redirect     off;
        proxy_set_header   Host             \$host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
    }
}
EOF
}

nginx_maestro_https_conf() {
  cat <<EOF
server {
    listen 80 default_server;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    server_name $ONPREM_DNS;
    listen 443 ssl;
    ssl_certificate /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    location = /minioapi/static/DEV/sdk.js {
        rewrite /minioapi(.*) \$1 break;
        proxy_pass http://$(minikube_ip):32190;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location ~* ^/maestro/api/.*\.(js|css|png)$ {
        proxy_pass http://$(minikube_ip):32180;
        proxy_redirect     off;
        proxy_set_header   Host             \$host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
    }
    location /cli {
        proxy_pass https://192.168.49.2:32102/m3-cli-bucket;
        proxy_redirect     off;
        proxy_set_header   Host             \$host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
    }
    location ~* ^/content/.*\.(png|svg)$ {
        rewrite ^/content/(.*)$ /m3-public-s3-content/content/\$1 break;
        proxy_pass https://$(minikube_ip):32102;
        proxy_redirect     off;
        proxy_set_header   Host             \$host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
    }
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|woff|woff2|ttf|svg|eot)$ {
        proxy_pass http://$(minikube_ip):32300;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location / {
        proxy_pass http://$(minikube_ip):32300;
        proxy_redirect     off;
        proxy_set_header   Host             \$http_host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        try_files \$uri \$uri/ /index.html;
    }
    location /integration {
        proxy_pass http://$(minikube_ip):32105;
        proxy_redirect off;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_send_timeout 60s;
        proxy_read_timeout 300s;
        proxy_cache off;
        proxy_intercept_errors off;
    }
    location /minioapi {
        rewrite /minioapi(.*) \$1 break;
        proxy_pass http://$(minikube_ip):32190;
        proxy_redirect     off;
        proxy_set_header   Host             \$host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
    }
    location /maestro/api {
        proxy_pass http://$(minikube_ip):32180/maestro/api;
        proxy_redirect     off;
        proxy_set_header   Host             \$host;
        proxy_set_header   X-Real-IP        \$remote_addr;
        proxy_set_header   X-Forwarded-For  \$proxy_add_x_forwarded_for;
    }
}
EOF
}

minio_m3_cli_bucket_access_policy() {
  cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "*"
                ]
            },
            "Action": [
                "s3:GetObject"
            ],
            "Resource": [
                "arn:aws:s3:::m3-cli-bucket/*"
            ]
        }
    ]
}
EOF
}

sudo -u "$FIRST_USER" mkdir -p "$(getent passwd "$FIRST_USER" | cut -d: -f6)/.local/bin" || true


log "Script is executed on behalf of $(id)"
log "The first run. Configuring Maestro Cloud Control for user $FIRST_USER"

if [ -z "$DO_NOT_ACTIVATE_LICENSE" ]; then
  log "Going to make request to license manager"
  if ! lm_response="$(request_to_lm)"; then
    log_err "Unsuccessful response from the license manager"
    exit 1
  fi
  lm_response=$(jq --indent 0 '.items[0]' <<<"$lm_response")
  log "License information was received"
else
  log "Skipping license activation step"
  lm_response=""
fi

# Prerequisite
log "Upgrading system and installing some necessary packages"
upgrade_and_install_packages

log "Installing docker $DOCKER_VERSION"
install_docker "$DOCKER_VERSION"

log "Adding user $FIRST_USER to docker group"
sudo groupadd docker || true
sudo usermod -aG docker "$FIRST_USER" || true


log "Installing minikube $MINIKUBE_VERSION"
install_minikube "$MINIKUBE_VERSION"

log "Installing kubectl $KUBECTL_VERSION"
install_kubectl "$KUBECTL_VERSION"

log "Installing helm $HELM_VERSION"
install_helm "$HELM_VERSION"

log "Installing efs-utils"
install_efs_utils

log "Mount provided EFS: $EFS_FILE_SYSTEM_ID"

# Setup credentials
MONGO_USERNAME="${MONGO_USERNAME:-admin}"
MONGO_PASSWORD="${MONGO_PASSWORD:-$(generate_password 30 -hex)}"
RABBITMQ_USERNAME="${RABBITMQ_USERNAME:-rabbitmquser}"
RABBITMQ_PASSWORD="${RABBITMQ_PASSWORD:-$(generate_password 16 -hex)}"
RABBITMQ_URI="${RABBITMQ_URI:-"amqp://${RABBITMQ_USERNAME}:${RABBITMQ_PASSWORD}@rabbitmq:5672/local_vhost"}"
MONGO_URI="${MONGO_URI:-"mongodb://${MONGO_USERNAME}:${MONGO_PASSWORD}@mongo:27017/M3OnPremises"}"
MONGO_BILLING_URI="${MONGO_BILLING_URI:-"mongodb://${MONGO_USERNAME}:${MONGO_PASSWORD}@mongo:27017/M3Billing"}"
MONGO_OPERATION_URI="${MONGO_OPERATION_URI:-"mongodb://${MONGO_USERNAME}:${MONGO_PASSWORD}@mongo:27017/M3Operation"}"
MODULAR_API_SECRET_KEY="${MODULAR_API_SECRET_KEY:-$(generate_password 16 -hex)}"
MODULAR_SDK_ACCESS_KEY="${MODULAR_SDK_ACCESS_KEY:-$(generate_password 16 -hex)}"
MODULAR_SDK_SECRET_KEY="${MODULAR_SDK_SECRET_KEY:-$(generate_password sdk)}"
ENVIRONMENT="${ENVIRONMENT:-MCC}"
if [[ $HTTPS_ENABLED == "true" ]]; then
    HTTP_PROTOCOL="https"
fi
HTTP_PROTOCOL="${HTTP_PROTOCOL:-http}"

log "Starting minikube and installing helm releases on behalf of $FIRST_USER"
sudo su - "$FIRST_USER" <<EOF
set -e
minikube start --driver=docker --container-runtime=containerd -n 1 --force --interactive=false --memory=max --cpus=max --profile maestro --kubernetes-version=$KUBERNETES_VERSION
minikube profile maestro
minikube stop

sudo mkdir -p $APPLICATIONS_DATA_PATH
sudo mount -t efs -o tls $EFS_DNS:/ $APPLICATIONS_DATA_PATH

minikube start --driver=docker --container-runtime=containerd -n 1 --force --interactive=false --memory=max --cpus=max --profile maestro --kubernetes-version=$KUBERNETES_VERSION
minikube profile maestro

if [[ $IS_NEW_DEPLOYMENT == "true" ]]; then
    kubectl create secret generic minio-secret --from-literal=username=miniouser --from-literal=password=$(generate_password 20 -hex)
    kubectl create secret generic rabbitmq-secret --from-literal=username=$RABBITMQ_USERNAME --from-literal=password=$RABBITMQ_PASSWORD
    kubectl create secret generic rabbitmq-secret-uri --from-literal=uri=$RABBITMQ_URI
    kubectl create secret generic mongo-secret --from-literal=username=$MONGO_USERNAME --from-literal=password=$MONGO_PASSWORD
    kubectl create secret generic mongo-secret-uri --from-literal=uri=$MONGO_URI
    kubectl create secret generic mongo-secret-operation-uri --from-literal=uri=$MONGO_OPERATION_URI
    kubectl create secret generic mongo-secret-billing-uri --from-literal=uri=$MONGO_BILLING_URI
    kubectl create secret generic mongo-secret-operation --from-literal=username=$MONGO_USERNAME --from-literal=password=$MONGO_PASSWORD
    kubectl create secret generic mongo-secret-billing --from-literal=username=$MONGO_USERNAME --from-literal=password=$MONGO_PASSWORD
    if [[ $VAULT_PROFILE == "local" ]]; then
        kubectl create secret generic vault-secret --from-literal=token=$(generate_password 30 -hex)
    fi
    kubectl create secret generic modular-sdk-secret --from-literal=accesskey=$MODULAR_SDK_ACCESS_KEY --from-literal=secretKey=$MODULAR_SDK_SECRET_KEY
    kubectl create secret generic modular-api-secret --from-literal=system-password=$(generate_password 20 -hex) --from-literal=secret-key="$(generate_password 50)"
    kubectl create secret generic modular-service-secret --from-literal=system-password=$MODULAR_API_SECRET_KEY
    kubectl create secret generic modular-default-user --from-literal=password=$(generate_password sdk)
    kubectl create secret generic jwt-secret --from-literal=secret=$(generate_password 16 -hex)
else
    sudo cp -r $APPLICATIONS_DATA_PATH/secrets $MAESTRO_WORKING_DIR/
    kubectl apply -f $MAESTRO_WORKING_DIR/secrets/
    sudo rm -rf $MAESTRO_WORKING_DIR/secrets
fi

if [[ $ENVIRONMENT != "MCC" ]]; then
    aws ssm get-parameter --name "Maestro.application.properties" --region $HOME_REGION --with-decryption | jq -r '.Parameter.Value' > $MAESTRO_WORKING_DIR/artifacts/application.properties
fi
chmod +x $MAESTRO_WORKING_DIR/terraform-artifacts/*
docker build -f Dockerfile-m3-server -t m3-server .
docker build -f Dockerfile-m3-api-server -t m3-api-server .
docker save --output m3-server.tar m3-server
minikube image load m3-server.tar
minikube image load m3-api-server
minikube image load modular-cli.tar
minikube image load modular-admin.tar
minikube image load maestro-ui.tar

helm plugin install https://github.com/hypnoglow/helm-s3.git
helm repo add mcc "$HELM_REPOSITORY"
helm repo update mcc

if [[ $VAULT_PROFILE == "local" ]]; then
    echo "[INFO] Waiting for Vault pods to be ready..."
    helm install --wait --timeout 300s vault mcc/vault --set service.type=NodePort,ui.enabled=true
    echo "[INFO] Vault pods are now ready..."
fi

echo "[INFO] Waiting for MinIO pods to be ready..."
if [[ $HTTPS_ENABLED == "true" ]]; then
    sudo mkdir -p /etc/nginx/ssl
    aws ssm get-parameter --name "Maestro.ssl-fullchain.credentials" --region $HOME_REGION --with-decryption | jq -r '.Parameter.Value' > fullchain.pem
    aws ssm get-parameter --name "Maestro.ssl-privkey.credentials" --region $HOME_REGION --with-decryption | jq -r '.Parameter.Value' > privkey.pem
    kubectl create secret generic minio-tls-secret \
      --from-file=public.crt=fullchain.pem \
      --from-file=private.key=privkey.pem
    sudo mv fullchain.pem /etc/nginx/ssl/
    sudo mv privkey.pem /etc/nginx/ssl/
    sudo chown -R root: /etc/nginx/ssl/
    helm install --wait --timeout 300s minio mcc/minio --set service.type=NodePort,consoleService.type=NodePort,console.enabled=true,httpProtocol=https
else
    helm install --wait --timeout 300s minio mcc/minio --set service.type=NodePort,consoleService.type=NodePort,console.enabled=true
fi
echo "[INFO] MinIO pods are now ready..."

if [[ $MONGO_PROFILE == "local" ]]; then
    echo "[INFO] Waiting for Mongo pods to be ready..."
    helm install --wait --timeout 300s mongo mcc/mongo --set service.type=NodePort
    echo "[INFO] Mongo pods are now ready..."
fi
EOF

if [[ $IS_NEW_DEPLOYMENT == "true" ]]; then
    mkdir -p $MAESTRO_WORKING_DIR/secrets/
    SECRETS_LIST=$(kubectl get secrets -o name | cut -d'/' -f2 | grep -v sh.helm)
    for secret in $SECRETS_LIST; do
        kubectl get secret $secret -o yaml > $MAESTRO_WORKING_DIR/secrets/$secret.yaml
    done
    sudo cp -r $MAESTRO_WORKING_DIR/secrets $APPLICATIONS_DATA_PATH/
    sudo rm -rf $MAESTRO_WORKING_DIR/secrets
fi

if [[ $MONGO_PROFILE == "local" ]]; then
    chmod +x $MAESTRO_WORKING_DIR/ami-scripts/mongo_update.sh
    sudo -EH -u "$FIRST_USER" $MAESTRO_WORKING_DIR/ami-scripts/mongo_update.sh
    sudo rm -rf $MAESTRO_WORKING_DIR/mongo-collections
fi


log "Configuring nginx"
sudo rm -f /etc/nginx/sites-enabled/*
sudo rm -f /etc/nginx/sites-available/*
sudo mkdir /etc/nginx/streams-available || true
sudo mkdir /etc/nginx/streams-enabled || true

nginx_conf | sudo tee /etc/nginx/nginx.conf > /dev/null
if [[ $VAULT_PROFILE == "local" ]]; then
    nginx_vault_conf | sudo tee /etc/nginx/sites-available/vault > /dev/null
    sudo ln -sf /etc/nginx/sites-available/vault /etc/nginx/sites-enabled/
fi
if [[ $RABBITMQ_PROFILE == "local" ]]; then
    nginx_rabbitmq_conf | sudo tee /etc/nginx/sites-available/rabbitmq > /dev/null
    sudo ln -sf /etc/nginx/sites-available/rabbitmq /etc/nginx/sites-enabled/
fi

if [[ $HTTPS_ENABLED == "true" ]]; then
    nginx_minio_api_https_conf | sudo tee /etc/nginx/sites-available/minio > /dev/null
    nginx_minio_console_https_conf | sudo tee /etc/nginx/sites-available/minio-console > /dev/null
    nginx_maestro_https_conf | sudo tee /etc/nginx/sites-available/maestro > /dev/null
else
    nginx_minio_api_conf | sudo tee /etc/nginx/sites-available/minio > /dev/null
    nginx_minio_console_conf | sudo tee /etc/nginx/sites-available/minio-console > /dev/null
    nginx_maestro_conf | sudo tee /etc/nginx/sites-available/maestro > /dev/null

fi

nginx_modular_api_conf | sudo tee /etc/nginx/sites-available/modular-api > /dev/null
sudo ln -sf /etc/nginx/sites-available/modular-api /etc/nginx/sites-enabled/
sudo ln -sf /etc/nginx/sites-available/maestro /etc/nginx/sites-enabled/maestro
sudo ln -sf /etc/nginx/sites-available/minio /etc/nginx/sites-enabled/
sudo ln -sf /etc/nginx/sites-available/minio-console /etc/nginx/sites-enabled/
sudo systemctl reload nginx

curl "https://dl.min.io/client/mc/release/linux-$(dpkg --print-architecture)/mc" --create-dirs -o $MAESTRO_WORKING_DIR/minio-binaries/mc
chmod +x $MAESTRO_WORKING_DIR/minio-binaries/mc
sudo chown -R $FIRST_USER: $MAESTRO_WORKING_DIR/minio-binaries
minio_user=$(kubectl get secret minio-secret -o jsonpath="{.data.username}" --kubeconfig $MAESTRO_WORKING_DIR/.kube/config | base64 --decode)
minio_password=$(kubectl get secret minio-secret -o jsonpath="{.data.password}" --kubeconfig $MAESTRO_WORKING_DIR/.kube/config | base64 --decode)
if [[ $HTTPS_ENABLED == "true" ]]; then
    MAESTRO_PRIVATE_IP=$(TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` && curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
    echo "$MAESTRO_PRIVATE_IP $ONPREM_DNS" >> /etc/hosts
    $MAESTRO_WORKING_DIR/minio-binaries/mc alias set minio https://$ONPREM_DNS:9000 $minio_user $minio_password
    sed -i "s,var invokeUrl = .*,var invokeUrl = 'https://$ONPREM_DNS/minioapi/api';,g" $MAESTRO_WORKING_DIR/sdk.js
else
    $MAESTRO_WORKING_DIR/minio-binaries/mc alias set minio http://$(minikube_ip):32102 $minio_user $minio_password
    sed -i "s,var invokeUrl = .*,var invokeUrl = 'http://$ONPREM_DNS/minioapi/api';,g" $MAESTRO_WORKING_DIR/sdk.js
fi
if [[ $STORAGE_PROFILE == "local" ]]; then
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/static
    $MAESTRO_WORKING_DIR/minio-binaries/mc anonymous set download minio/static
    $MAESTRO_WORKING_DIR/minio-binaries/mc cp $MAESTRO_WORKING_DIR/sdk.js minio/static/
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-dictionary-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc cp -r $MAESTRO_WORKING_DIR/localization/* minio/m3-dictionary-bucket/

    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-paas-billing-reports-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-auto-configuration-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-user-scripts-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-notification-audit-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-billing-reports-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-charts-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-sts-tokens-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-billing-files-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-r8s-storage-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-tenants-cf-templates-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-ansible-di-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-metrics-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-sdk-keys-bucket
    $MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/https://$ONPREM_DNS/content
fi
$MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-public-s3-content
$MAESTRO_WORKING_DIR/minio-binaries/mc anonymous set download minio/m3-public-s3-content
$MAESTRO_WORKING_DIR/minio-binaries/mc cp -r $MAESTRO_WORKING_DIR/content minio/m3-public-s3-content/
$MAESTRO_WORKING_DIR/minio-binaries/mc mb minio/m3-cli-bucket
$MAESTRO_WORKING_DIR/minio-binaries/mc anonymous set download minio/m3-cli-bucket
$MAESTRO_WORKING_DIR/minio-binaries/mc cp -r $MAESTRO_WORKING_DIR/m3-cli-minio/* minio/m3-cli-bucket/

minio_m3_cli_bucket_access_policy | sudo tee $MAESTRO_WORKING_DIR/minio_m3_cli_bucket_access_policy.json > /dev/null
$MAESTRO_WORKING_DIR/minio-binaries/mc policy set $MAESTRO_WORKING_DIR/minio_m3_cli_bucket_access_policy.json minio/m3-cli-bucket

JSON_CONTENT=$(cat <<EOF
{
"access_link": "$LM_API_LINK",
"access_response": $lm_response
}
EOF
)
if [[ $VAULT_PROFILE == "local" ]]; then
    VAULT_PATH="kv/m3.access"
    kubectl exec deploy/vault --kubeconfig $MAESTRO_WORKING_DIR/.kube/config -- sh -c "echo '$JSON_CONTENT' | vault kv put $VAULT_PATH data=-"
else
    aws ssm put-parameter --name "m3.access" --value "$JSON_CONTENT" --type "SecureString" --overwrite
fi

# Building helm vars
HELM_VARS=""
HELM_VARS+="homeRegion=$HOME_REGION"
if [[ $RABBITMQ_PROFILE == "external" ]]; then
    RABBIT_VARS="rabbitmqService=$RABBITMQ_HOST,rabbitmqPort=$RABBITMQ_PORT,rabbitmqVhost=$RABBITMQ_VHOST,rabbitmqSslEnabled=true,rabbitmqProfile=$MONGO_PROFILE"
    HELM_VARS+=",$RABBIT_VARS"
fi
if [[ $MONGO_PROFILE == "external" ]]; then
    MONGO_VARS="mongoPort=$MONGO_PORT,mongoService=$MONGO_HOST,mongoProfile=$MONGO_PROFILE"
    HELM_VARS+=",$MONGO_VARS"
fi
if [[ $VAULT_PROFILE == "external" ]]; then
    VAULT_VARS="vaultProfile=$VAULT_PROFILE"
    HELM_VARS+=",$VAULT_VARS"
fi
if [[ $STORAGE_PROFILE == "external" ]]; then
    STORAGE_VARS="storageProfile=$STORAGE_PROFILE,sdkBucket=$M3_UI_SDK_BUCKET,sdkBucketPath=$M3_UI_SDK_PATH"
    HELM_VARS+=",$STORAGE_VARS"
fi
if [[ $CONNECT_EXTERNAL_GRAYLOG == "true" ]]; then
    GRAYLOG_VARS="graylogHost=$GRAYLOG_HOST,hostname=$INSTANCE_HOSTNAME_FOR_GRAYLOG"
    HELM_VARS+=",$GRAYLOG_VARS"
fi
HELM_VARS+=",environment=$ENVIRONMENT"
if [[ $ENVIRONMENT != "MCC" ]]; then
    HOME_ACCOUNT_ID=$(TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` && curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .accountId)
    HELM_VARS+=",homeAccountId=$HOME_ACCOUNT_ID"
fi

MODULAR_VARS=""
MODULAR_VARS+="deployTargetBucket=$DEPLOY_TARGET_BUCKET,modularReportBucket=$MODULAR_REPORT_BUCKET,modularBucket=$MODULAR_BUCKET,modularMaestroUser=$MODULAR_MAESTRO_USER,httpProtocol=$HTTP_PROTOCOL"

sudo su - "$FIRST_USER" <<EOF
set -e
if [[ $ENVIRONMENT != "MCC" ]]; then
    minikube ssh -- "sudo DEBIAN_FRONTEND=noninteractive apt update"
    minikube ssh -- "sudo DEBIAN_FRONTEND=noninteractive apt install s3fs -y"
    minikube ssh -- "sudo mkdir /mnt/datalake"
    minikube ssh -- "sudo s3fs $DATALAKE_BUCKET /mnt/datalake/ -o iam_role='$ROLE' -o endpoint='$DATALAKE_BUCKET_SOURCE_REGION' -o url='https://s3-$DATALAKE_BUCKET_SOURCE_REGION.amazonaws.com' -o uid=0 -o gid=0 -o umask=022"
    minikube ssh -- "echo '$DATALAKE_BUCKET: /mnt/datalake/ fuse.s3fs _netdev,allow_other,iam_role=$ROLE,endpoint=$DATALAKE_BUCKET_SOURCE_REGION,uid=0,gid=0,mp_umask=022,nonempty 0 0' | sudo tee -a /etc/fstab"
fi
EOF

sudo su - "$FIRST_USER" <<EOF
set -e
if [[ $RABBITMQ_PROFILE == "local" ]]; then
    echo "[INFO] Waiting for Rabbit pods to be ready..."
    helm install --wait --timeout 300s rabbitmq mcc/rabbitmq
    echo "[INFO] Rabbit pods are ready..."
fi

echo "HELM_VARS: $HELM_VARS"
echo "MODULAR_VARS: $MODULAR_VARS"
echo "[INFO] Waiting for Modular and Server pods to be ready..."
if [[ $RABBITMQ_PROFILE == "external"  ||  $MONGO_PROFILE == "external" ]]; then
    helm install modular-api mcc/modular-api --set "service.type=NodePort,onpremDns=${ONPREM_DNS},${HELM_VARS},${MODULAR_VARS}"
    helm install m3-server mcc/m3-server --set-string springProfilesActive="${SPRING_PROFILES}",m3OnpremS3Host=${ONPREM_DNS},onpremDns=${ONPREM_DNS},${HELM_VARS}
    helm install m3-ui-server mcc/m3-ui-server --set-string springProfilesActive="${SPRING_PROFILES}",m3OnpremS3Host=${ONPREM_DNS},onpremDns=${ONPREM_DNS},${HELM_VARS}
else
    helm install m3-server mcc/m3-server --set-string springProfilesActive="${SPRING_PROFILES}",onpremDns=$ONPREM_DNS,m3OnpremS3Host=$ONPREM_DNS,m3OnpremS3ExternalUrl=${HTTP_PROTOCOL}://$ONPREM_DNS/minio,${HELM_VARS}
    helm install m3-ui-server mcc/m3-ui-server --set-string springProfilesActive="${SPRING_PROFILES}",onpremDns=$ONPREM_DNS,m3OnpremS3Host=$ONPREM_DNS,m3OnpremS3ExternalUrl=${HTTP_PROTOCOL}://$ONPREM_DNS:9000,${HELM_VARS}
    helm install modular-api mcc/modular-api --set service.type=NodePort,apiHost=m3-server,httpProtocol=$HTTP_PROTOCOL
fi
helm install --wait --timeout 300s modular-cli mcc/modular-cli
echo "[INFO] Modular and Server pods are now ready..."

echo "[INFO] Waiting for the UI pod to be ready..."
if [[ $HTTPS_ENABLED == "true" ]]; then
    helm install --wait --timeout 300s ui mcc/ui --set "onpremDns=${ONPREM_DNS},httpProtocol=https"
else
    helm install --wait --timeout 300s ui mcc/ui --set "onpremDns=${ONPREM_DNS},httpProtocol=http"
fi
echo "[INFO] The UI pod is now ready..."

helm get values ui -o json > "$MAESTRO_WORKING_DIR/maestro-ui-values.json"
helm get values m3-server -o json > "$MAESTRO_WORKING_DIR/m3-server-values.json"
helm get values modular-api -o json > "$MAESTRO_WORKING_DIR/modular-api-values.json"
EOF

log "Enabling minikube service"
enable_minikube_service

sudo tee -a /etc/ssh/sshd_config <<EOF
  HostKeyAlgorithms +ssh-rsa
  PubkeyAcceptedKeyTypes +ssh-rsa
EOF

sudo systemctl restart ssh

log "Cleaning apt cache"
sudo apt clean

log "Cleaning artifacts"
if [[ $ENVIRONMENT == "MCC" ]]; then
    rm $MAESTRO_WORKING_DIR/M3-Operation $MAESTRO_WORKING_DIR/M3-OnPremises $MAESTRO_WORKING_DIR/M3-Billing
    rm $MAESTRO_WORKING_DIR/*.tar
    sudo su - "$FIRST_USER" <<EOF
set -e
docker rmi m3-server
docker rmi m3-api-server
EOF

fi
