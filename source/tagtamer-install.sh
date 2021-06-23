#!/bin/bash

# Install rpms
yum update -y
yum install -y python3 python3-pip
amazon-linux-extras install nginx1 -y

# Install Python modules
mkdir -p /home/ec2-user/tag-tamer/prod
chown -R ec2-user:ec2-user /home/ec2-user/tag-tamer
su - ec2-user -c "python3 -m venv /home/ec2-user/tag-tamer/prod;source /home/ec2-user/tag-tamer/prod/bin/activate; pip3 install boto3 botocore flask flask-WTF gunicorn python-jose /var/tmp/tag-tamer/source/Flask-AWSCognito; deactivate"

# Copy code and config
cd /var/tmp/tag-tamer/source
cp config/tag-tamer.conf /etc/nginx/conf.d
cp config/proxy_params /etc/nginx
cp config/ssl-redirect.conf  /etc/nginx/default.d/
cp config/tag-tamer.service /etc/systemd/system
cp -pr code/* to /home/ec2-user/tag-tamer/

mkdir -p /var/log/tag-tamer
mkdir -p /home/ec2-user/tag-tamer/downloads

# Permissions
chown root:root /etc/nginx/conf.d/tag-tamer.conf /etc/nginx/proxy_params /etc/nginx/default.d/ssl-redirect.conf /etc/systemd/system/tag-tamer.service
chown -R ec2-user:ec2-user /home/ec2-user/tag-tamer /var/log/tag-tamer

# Initialize Tag Tamer log file
touch /var/log/tag-tamer/tag-tamer.log
chown -R ec2-user:ec2-user /var/log/tag-tamer/tag-tamer.log
chmod 664 /var/log/tag-tamer/tag-tamer.log

dos2unix /home/ec2-user/tag-tamer/*.py
dos2unix /home/ec2-user/tag-tamer/templates/*.html

# Set server_tokens to off in nginx.conf file
sed -i '/server_tokens/d' /etc/nginx/nginx.conf
sed -i '/sendfile.*/i\    server_tokens       off;' /etc/nginx/nginx.conf

# SSL certificate creation - START

# Fix IP in config
sed -i  "s/10.0.5.59/`hostname -i`/g" /etc/nginx/conf.d/tag-tamer.conf 

# Get Public or Private Hostnames/IPs to configure in certificate
FQDN1=`curl http://169.254.169.254/latest/meta-data/local-hostname` 
FQDN2=`curl http://169.254.169.254/latest/meta-data/public-hostname` 
IP1=`curl http://169.254.169.254/latest/meta-data/local-ipv4`
IP2=`curl http://169.254.169.254/latest/meta-data/public-ipv4`

# Create root CA 
mkdir -p /etc/pki/nginx/
cd /etc/pki/nginx/
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 398 -out rootCA.crt -subj "/C=US/ST=NC/L=Raleigh/O=AWS/OU=AWS Support/CN=amazonaws.com"

# Create intermediate certificate - Alt DNS name input file
echo "subjectAltName = @alt_names

[alt_names]
DNS.1 = $FQDN1
IP.1 = $IP1" > v3.ext

# Removed public IP/DNS from cert. Add below if needed to above section.
# DNS.2 = $FQDN2
# IP.2 = $IP2

# Create intermediate certificate
openssl genrsa -out tag-tamer.key 2048
openssl req -new -sha256 -key tag-tamer.key -subj "/C=US/ST=NC/L=Raleigh/O=AWS/OU=AWS Support/CN=$FQDN1" -out tag-tamer.csr
openssl x509 -req -in tag-tamer.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out tag-tamer.crt -days 398 -sha256 -extfile  v3.ext  

# Create file for import into browser, this can be shared to import into trust store of client from where Tag Tamer application is accessed.
# ca-bundle file below.
cat tag-tamer.crt rootCA.crt > tag-tamer.ca-bundle

# Tag Tamer application connectivity from web browser will be shown as untrusted by default.
# It's highly recommended to import ca-bundle into customer desktop from where Tag Tamer application is accessed.
# Example: Import to Mac OS trust store
# Ask application Administrator to import  /etc/pki/nginx/tag-tamer.ca-bundle to browser where required.
# sudo security add-trusted-cert -d -r trustAsRoot -k /Library/Keychains/System.keychain tag-tamer.ca-bundle
# For Windows certificate import process refer to
# https://docs.microsoft.com/en-us/skype-sdk/sdn/articles/installing-the-trusted-root-certificate

# Customer can also use their own trusted certificate instead self-signed certificate.
# Update below 3 entries in /etc/nginx/conf.d/tag-tamer.conf with customer certificate path.
#        ssl_certificate "/etc/pki/nginx/tag-tamer.crt";
#        ssl_certificate_key "/etc/pki/nginx/tag-tamer.key";
#	     ssl_client_certificate "/etc/pki/nginx/rootCA.crt";


# Verification command on Tag Tamer web app server:  openssl x509 -text -noout -in tag-tamer.crt 

# SSL certificate creation - END

# Enable and start services
systemctl enable tag-tamer.service; systemctl start tag-tamer.service
systemctl enable nginx; systemctl start nginx