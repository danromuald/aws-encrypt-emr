#!/usr/bin/env bash
#===============================================================================
#          FILE: aws-emr-transit-enc.sh
#         USAGE: aws-emr-transit-enc.sh
#   DESCRIPTION: Use this script (or portions of it) to launch an EMR cluster with
#                TLS encryption in transit.
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: Dan R. Mbanga
#  ORGANIZATION: ---
#       CREATED: 11/07/2016
#      REVISION: ---
#      Idver   : 1.0
#===============================================================================
LC_ALL=C
LANG=C
set -o nounset
set -o pipefail
set -o errexit
# set -x

#### Vars ####
Idver=1.0
author="Dan R. Mbanga"
ORGANIZATION="danulab"
DOMAIN="danulab.com"
AWS_BUCKET="danulab.com"
S3_CERTS_KEY="sec-artifacts/tls/${ORGANIZATION}-certs.zip"
S3_OBJECT="s3://${AWS_BUCKET}/${S3_CERTS_KEY}"

################################
## no changes below this line ##
################################

function main()
{
    readonly PROGNAME=$(basename $0)
    readonly PROGDIR=$(readlink -m $(dirname $0))
    readonly PIDFILE="${PROGNAME%.*}.pid"
    echo $$ >${PIDFILE}

    if [[ $(uname) != "Linux" ]]
    then
        printf "%\n" "Needs Linux."
        exit 1
    fi

    TMP_FILE=$(mktemp --tmpdir ${PROGNAME}.$$.XXXXXX)

    trap 'rm -rf ${TMP_FILE} ${PIDFILE}' EXIT
}

function aws_cleanup()
{
    # Cleanup
    aws \
        s3api \
        delete-object \
        --bucket ${AWS_BUCKET} \
        --key ${S3_CERTS_KEY}
}

function create_ca()
{
    # Create the CA certificate
    openssl \
        req \
        -newkey rsa:1024 \
        -x509 \
        -keyout cakey.pem \
        -out cacert.pem \
        -days 3650 \
        -nodes \
        -subj "/C=US/ST=NY/L=New York/O=${ORGANIZATION}/OU=Analytics/CN=${DOMAIN}"
}

function create_user_cert()
{
    # Create a user certificate for EMR to use.
    openssl \
        req \
        -newkey rsa:1024 \
        -keyout privateKey.pem \
        -out emr-csr.pem \
        -days 3650 \
        -nodes  \
        -subj "/C=US/ST=NY/L=New York/O=${ORGANIZATION}/OU=EMR/CN=*.ec2.internal"
}

function create_helper_files()
{
    # Create helper files:
    touch index.txt
    mkdir -p newcerts/ final/
    echo '001A' > serial
}

function gen_opensslconf()
{
cat <<EOF >> openssl.cnf
HOME               = .
RANDFILE           = \$ENV::HOME/.rnd
oid_section        = new_oids

[ new_oids ]

[ ca ]
default_ca               = CA_default       # The default ca section

[ CA_default ]
dir                      =     .            # Where everything is kept
certs                    = \$dir            # Where the issued certs are kept
crl_dir                  = \$dir/crl        # Where the issued crl are kept
database                 = \$dir/index.txt  # database index file.
new_certs_dir            = \$dir/newcerts   # default place for new certs.
certificate              = \$dir/cacert.pem # The CA certificate
serial                   = \$dir/serial     # The current serial number
crlnumber                = \$dir/crlnumber  # the current crl number
crl                      = \$dir/crl.pem    # The current CRL
private_key              = \$dir/cakey.pem  # The private key
RANDFILE                 = \$dir/.rand      # private random number file
x509_extensions          = usr_cert         # The extentions to add to the cert
name_opt                 = ca_default       # Subject Name options
cert_opt                 = ca_default       # Certificate field options
default_days             = 3650             # how long to certify for
default_crl_days         = 30               # how long before next CRL
default_md               = sha1             # which md to use.
preserve                 = no               # keep passed DN ordering
policy                   = policy_match

[ policy_match ]
countryName              = match
stateOrProvinceName      = match
organizationName         = match
organizationalUnitName   = optional
commonName               = supplied
emailAddress             = optional

[ policy_anything ]
countryName              = optional
stateOrProvinceName      = optional
localityName             = optional
organizationName         = optional
organizationalUnitName   = optional
commonName               = supplied
emailAddress             = optional

[ req ]
default_bits             = 1024
default_keyfile          = privkey.pem
distinguished_name       = req_distinguished_name
attributes               = req_attributes
x509_extensions          = v3_ca # The extentions to add to the self signed cert
string_mask              = nombstr

[ req_distinguished_name ]
countryName              = Country Name (2 letter code)
countryName_default      = AU
countryName_min          = 2
countryName_max          = 2
stateOrProvinceName      = State or Province Name (full name)
stateOrProvinceName_default = Some-State
localityName             = Locality Name (eg, city)
0.organizationName       = Organization Name (eg, company)
0.organizationName_default  = Internet Widgits Pty Ltd
organizationalUnitName   = Organizational Unit Name (eg, section)
commonName               = Common Name (e.g. server FQDN or YOUR name)
commonName_max           = 64
emailAddress             = Email Address
emailAddress_max         = 64

[ req_attributes ]
challengePassword        = A challenge password
challengePassword_min    = 4
challengePassword_max    = 20
unstructuredName         = An optional company name

[ usr_cert ]
basicConstraints         = CA:FALSE
nsComment                = "OpenSSL Generated Certificate"
subjectKeyIdentifier     = hash
authorityKeyIdentifier   = keyid,issuer

[ v3_req ]
basicConstraints         = CA:FALSE
keyUsage                 = nonRepudiation, digitalSignature, keyEncipherment

[ v3_ca ]
subjectKeyIdentifier     = hash
authorityKeyIdentifier   = keyid:always,issuer:always
basicConstraints         = CA:true

[ crl_ext ]
authorityKeyIdentifier   = keyid:always,issuer:always

[ proxy_cert_ext ]
basicConstraints         = CA:FALSE
nsComment                = "OpenSSL Generated Certificate"
subjectKeyIdentifier     = hash
authorityKeyIdentifier   = keyid,issuer:always
proxyCertInfo            = critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

EOF
}

function sign_gen()
{
    # Sign the csr and generate the signed certificateChain
    openssl \
        ca \
        -in emr-csr.pem \
        -keyfile cakey.pem \
        -cert cacert.pem  \
        -batch \
        -out certificateChain.pem \
        -config openssl.cnf
}

function zip_artifacts()
{
    # Prepare the zip artifacts for S3
    printf "%s\n" \
        "preparing the zip artifacts for S3"

    cp certificateChain.pem final/
    cp cacert.pem final/trustedCertificates.pem
    cp privateKey.pem final/
    cd final

    zip -r9 ${ORGANIZATION}-certs.zip *

    printf "%s\n" \
        "Artifacts ready."
}

function upload_artifacts()
{
    printf "%s\n" \
        "Now uploading to S3"
    aws \
        s3 \
        cp ${ORGANIZATION}-certs.zip ${S3_OBJECT}

    printf "%s\n" \
        "Upload done"
}

function create_security_profile()
{
# Create Security Profile on EMR.
cat <<EOF >> transit-encryption-only.json
{
    "EncryptionConfiguration": {
        "EnableInTransitEncryption" : true,
        "EnableAtRestEncryption" : false,
        "InTransitEncryptionConfiguration" : {
            "TLSCertificateConfiguration" : {
                "CertificateProviderType" : "PEM",
                "S3Object" : ${S3_OBJECT}
            }
        }
    }

EOF
}

function create_sec_conf()
{
    # Create security configuration on EMR
    printf "%s\n" \
        "Creating the Security Configuration"

    aws \
        emr \
        create-security-configuration \
        --name transitOnly  \
        --security-configuration file://./transit-encryption-only.json
}

function create_emr_cluster()
{
    # Create the EMR cluster
    printf "%s\n" \
        "Creating the EMR cluster"


#
    aws \
        emr \
        create-cluster \
        --termination-protected \
        --applications Name=Hadoop Name=Hive Name=Pig Name=Hue Name=Spark Name=Zeppelin Name=Ganglia Name=Tez Name=Oozie Name=Mahout Name=Presto Name=ZooKeeper \
        --tags 'env=dev' \
        --ec2-attributes '{"KeyName":"<YOUR KEY NAME>","InstanceProfile":"EMR_EC2_DefaultRole" }' \
        --service-role EMR_DefaultRole \
        --security-configuration 'transitOnly' \
        --enable-debugging \
        --release-label emr-5.1.0 \
        --log-uri '<YOUR S3 BUCKET FOR LOGS>' \
        --name 'CryptoTransit' \
        --instance-groups '[{"InstanceCount":1,"InstanceGroupType":"MASTER","InstanceType":"m3.2xlarge","Name":"Master instance group - 1"},{"InstanceCount":2,"BidPrice":"0.3","InstanceGroupType":"TASK","InstanceType":"m3.2xlarge","Name":"Task instance group - 3"},{"InstanceCount":2,"InstanceGroupType":"CORE","InstanceType":"m3.2xlarge","Name":"Core instance group - 2"}]' \
        --region us-east-1

    printf "%s\n" \
        "Done."
}


# calling all functions
main
aws_cleanup
create_ca
create_user_cert
create_helper_files
gen_opensslconf

sign_gen
zip_artifacts
upload_artifacts
# create_security_profile
# create_sec_conf
# create_emr_cluster
