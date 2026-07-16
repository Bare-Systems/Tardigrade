# RSA-PSS-RSAE-SHA256 fixtures

These fixed fixtures were generated with OpenSSL 3.0.13:

```sh
printf 'Tardigrade RSA-PSS SHA-256 acceptance vector\n' >message.txt
openssl genrsa -traditional -3 2048 >private.pem
openssl rsa -in private.pem -RSAPublicKey_out -outform DER -out public-2048.der
openssl dgst -sha256 -sign private.pem \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
  -out signature-2048.bin message.txt
```

The same commands with 3072 and 4096 replace the modulus size. The DER files
contain `RSAPublicKey` values, and the signatures use RSA-PSS with SHA-256 and
a fixed 32-byte salt. The private keys are intentionally not checked in.
