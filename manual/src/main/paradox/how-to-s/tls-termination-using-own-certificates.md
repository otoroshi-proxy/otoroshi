# TLS termination using your own certificates

The goal of this tutorial is to expose a service via https using a certificate generated by openssl.

@@include[initialize.md](../includes/initialize.md) { #initialize-otoroshi }

Try to call the service.

```sh
curl 'http://myservice.oto.tools:8080'
```

This should output something like

```json
{
  "method": "GET",
  "path": "/",
  "headers": {
    "host": "mirror.opunmaif.io",
    "accept": "*/*",
    "user-agent": "curl/7.64.1",
    "x-forwarded-port": "443",
    "opun-proxied-host": "request.otoroshi.io",
    "otoroshi-request-id": "1463145856319359618",
    "otoroshi-proxied-host": "myservice.oto.tools:8080",
    "opun-gateway-request-id": "1463145856554240100",
    "x-forwarded-proto": "https",
  },
  "body": ""
}
```

Let's try to call the service in https.

```sh
curl 'https://myservice.oto.tools:8443'
```

This should output

```sh
curl: (35) LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to myservice.oto.tools:8443
```

To fix it, we have to generate a certificate and import it in Otoroshi to match the domain `myservice.oto.tools`.

> If you already had a certificate you can skip the next set of commands and directly import your certificate in Otoroshi

We will use openssl to generate a private key and a self-signed certificate.

```sh
openssl genrsa -out myservice.key 4096
# remove pass phrase
openssl rsa -in myservice.key -out myservice.key
# generate the certificate authority cert
openssl req -new -x509 -sha256 -days 730 -key myservice.key -out myservice.cer -subj "/CN=myservice.oto.tools"
```

Check the content of the certificate 

```sh
openssl x509 -in myservice.cer -text
```

This should contains something like

```sh
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number: 9572962808320067790 (0x84d9fef455f188ce)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=myservice.oto.tools
        Validity
            Not Before: Nov 23 14:25:55 2021 GMT
            Not After : Nov 23 14:25:55 2022 GMT
        Subject: CN=myservice.oto.tools
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
...
```

Once generated, go back to Otoroshi and navigate to the certificates management page (`top right cog icon / SSL/TLS certificates` or at @link:[`/bo/dashboard/certificates`](http://otoroshi.oto.tools:8080/bo/dashboard/certificates)) and click on `Add item`.

Set `myservice-certificate` as `name` and `description`.

Drop the `myservice.cer` file or copy the content to the `Certificate full chain` field.

Do the same action for the `myservice.key` file in the `Certificate private key` field.

Set your passphrase password in the `private key password` field if you added one.

Let's try the same call to the service.

```sh
curl 'https://myservice.oto.tools:8443'
```

An error should occurs due to the untrsuted received certificate server

```sh
curl: (60) SSL certificate problem: self signed certificate
More details here: https://curl.haxx.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```

End this tutorial by trusting the certificate server 

```sh
curl 'https://myservice.oto.tools:8443' --cacert myservice.cer
```

This should finally output

```json
{
  "method": "GET",
  "path": "/",
  "headers": {
    "host": "mirror.opunmaif.io",
    "accept": "*/*",
    "user-agent": "curl/7.64.1",
    "x-forwarded-port": "443",
    "opun-proxied-host": "request.otoroshi.io",
    "otoroshi-request-id": "1463158439730479893",
    "otoroshi-proxied-host": "myservice.oto.tools:8443",
    "opun-gateway-request-id": "1463158439558515871",
    "x-forwarded-proto": "https",
    "sozu-id": "01FN6MGKSYZNJYHEMP4R5PJ4Q5"
  },
  "body": ""
}
```

