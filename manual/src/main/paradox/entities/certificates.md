# Certificates

All generated and imported certificates are listed in the `https://otoroshi.xxxx/bo/dashboard/certificates` page. All those certificates can be used to serve traffic with TLS, perform mTLS calls, sign and verify JWT tokens.

The list of available actions are:

* `Add item`: redirects the user on the certificate creation page. It's useful when you already had a certificate (like a pem file) and that you want to load it in Otoroshi.
* `Let's Encrypt certificate`: asks a certificate matching a given host to Let's encrypt 
* `Create certificate`: issues a certificate with an existing Otoroshi certificate as CA.
* `Import .p12 file`: loads a p12 file as certificate

## Add item

* `Id`: the generated unique id of the certificate
* `Name`: the name of the certificate
* `Description`: the description of the certificate
* `Auto renew cert.`: certificate will be issued when it will be expired. Only works with a CA from Otoroshi and a known private key
* `Client cert.`: the certificate generated will be used to identicate a client to a server
* `Keypair`: the certificate entity will be a pair of public key and private key.
* `Public key exposed`: if true, the public key will be exposed on `http://otoroshi-api.your-domain/.well-known/jwks.json`
* `Certificate status`: the current status of the certificate. It can be valid if the certificate is not revoked and not expired, or equal to the reason of the revocation
* `Certificate full chain`: list of certificates used to authenticate a client or a server
* `Certificate private key`: the private key of the certificate or nothing if wanted. You can omit it if you want just add a certificte full chain to trust them.
* `Private key password`: the password to protect the private key
* `Certificate tags`: the tags attached to the certificate
* `Certaificate metadata`:  the metadata attached to the certificate

## Let's Encrypt certificate

* `Let's encrypt`: if enabled, the certificate will be generated by Let's Encrypt. If disabled, the user will be redirect to the `Create certificate` page
* `Host`: the host send to Let's encrypt to issue the certificate

## Create certificate view

* `Issuer`: the CA used to sign your certificate
* `CA certificate`: if enabled, the certificate will be used as an authority certificate. Once generated, it will be use as CA to sign the new certificates
* `Let's Encrypt`: redirects to the Let's Encrypt page to request a certificate
* `Client certificate`: the certificate generated will be used to identicate a client to a server
* `Include A.I.A`: include authority information access urls in the certificate
* `Key Type`: the type of the private key
* `Key Size`: the size of the private key
* `Signature Algorithm`: the signature algorithm used to sign the certificate
* `Digest Algorithm`:  the digest algorithm used
* `Validity`: how much time your certificate will be valid
* `Subject DN`:  the subject DN of your certificate
* `Hosts`: the hosts of your certificate

