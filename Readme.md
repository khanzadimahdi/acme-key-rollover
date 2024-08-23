# ACME account key rollover

This code implements ACME key rollover according to RFC: https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.5

### how to run

```shell
# 1. create new RSA key
make generate-newkey

# 2. rotate to new key
make run
```
