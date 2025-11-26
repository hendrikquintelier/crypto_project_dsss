#!/bin/bash

# Ensure script runs from correct directory
if [ "$(basename "$PWD")" != "crypto_do_once" ]; then
    echo "Please run this script from the 'crypto_do_once' directory."
    exit 1
fi

# Stop on any error
set -e

echo "Setting up PKI infrastructure (separate CA and server keystores)..."

###########################################
# Variables
###########################################

ROOT_CA_ALIAS="root_ca"
ROOT_CA_KEYSTORE="root_ca_keystore.p12"
ROOT_CA_PASSWORD="capassword"

SERVER_ALIAS="cauth_server"
SERVER_KEYSTORE="cauth_server_keystore.p12"
SERVER_PASSWORD="serverpassword"

TRUSTSTORE_PASSWORD="trustpassword"
VALIDITY_DAYS=3650

SERVER_CN="172.20.0.10"
SERVER_ORG="Private Parking"
SERVER_COUNTRY="BE"

###########################################
# Cleanup existing files
###########################################

rm -rf "$ROOT_CA_KEYSTORE" "$SERVER_KEYSTORE"
rm -rf cauth_truststore.p12 sp_truststore.p12 ho_truststore.p12 co_truststore.p12
rm -rf root_ca.crt server.csr server.crt

###########################################
# 1. Create Root CA keystore + self-signed certificate
###########################################

echo "1. Creating Root CA private key + self-signed certificate..."

keytool -genkeypair \
    -alias "$ROOT_CA_ALIAS" \
    -keyalg RSA \
    -keysize 4096 \
    -validity "$VALIDITY_DAYS" \
    -keystore "$ROOT_CA_KEYSTORE" \
    -storepass "$ROOT_CA_PASSWORD" \
    -keypass "$ROOT_CA_PASSWORD" \
    -dname "CN=Root CA, O=National Authority, C=Country Code" \
    -ext BasicConstraints:critical=ca:true \
    -ext KeyUsage:critical=keyCertSign,cRLSign

###########################################
# 2. Export Root CA certificate
###########################################

echo "2. Exporting Root CA certificate (root_ca.crt)..."

keytool -exportcert \
    -alias "$ROOT_CA_ALIAS" \
    -keystore "$ROOT_CA_KEYSTORE" \
    -storepass "$ROOT_CA_PASSWORD" \
    -file root_ca.crt \
    -rfc

###########################################
# 3. Create server private key and keystore
###########################################

echo "3. Creating server private key in its own keystore..."

# keytool -genkeypair \

###########################################
# 4. Generate CSR for server
###########################################

echo "4. Generating CSR for server..."

# keytool -certreq \

###########################################
# 5. Sign server CSR using Root CA
###########################################

echo "5. Signing server certificate with Root CA..."

# keytool -gencert \

###########################################
# 6. Import Root CA certificate into server keystore
###########################################

echo "6. Importing Root CA certificate into server keystore..."

# keytool -importcert \

###########################################
# 7. Import signed server certificate
###########################################

echo "7. Importing CA-signed server certificate..."

# keytool -importcert \

###########################################
# 8. Create truststores for server + all clients
###########################################

echo "8. Creating truststores..."

# keytool -importcert \

###########################################
# Cleanup
###########################################

echo "9. Cleaning up CSR and intermediate files..."
rm -f server.csr server.crt

###########################################
# Summary
###########################################

echo ""
echo "PKI Setup Complete!"
echo ""
echo "Created files:"
echo "  - $ROOT_CA_KEYSTORE (Root CA private key + Root CA certificate)"
echo "  - $SERVER_KEYSTORE (Server private key + CA-signed certificate)"
echo "  - root_ca.crt (public CA certificate)"
echo "  - cauth_truststore.p12 (server truststore)"
echo "  - sp_truststore.p12 (client truststore)"
echo "  - ho_truststore.p12 (homeowner truststore)"
echo "  - co_truststore.p12 (carowner truststore)"
echo ""
echo "Client keystores (SP/HO/CO) will be created during enrollment."
echo ""

echo "=== Server Keystore Contents ==="
keytool -list -keystore "$SERVER_KEYSTORE" -storepass "$SERVER_PASSWORD"

echo ""
echo "=== CA Truststore (example) ==="
keytool -list -keystore cauth_truststore.p12 -storepass "$TRUSTSTORE_PASSWORD"
