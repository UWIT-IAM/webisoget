/* ========================================================================
 * Copyright (c) 2004-2014 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

#define VERIFICATION_THE_OLD_WAY

/* Library for the webisoget package */

/* Retrieve a web page, following redirections, and 
   responding to some forms.

   This allows us to obtain pubcookies and thereby
   retrieve pubcookie protected pages.

   by Fox

*/

#include "webisoget.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/err.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>


int verify_peer = 0;
int delete_op = 0;
long lone = 1;
long ltwo = 2;
long lzero = 0;

extern char *postdata;
extern FILE *postfile;
extern char *putdata;
extern FILE *putfile;

/* String functions */

/* not everyone has strndup */
#ifdef I_REALLY_NEED_STRNDUP
static char *strndup(char *str, int len)
{
   char *dup = (char*) malloc(len+1);
   strncpy(dup, str, len);
   dup[len] = '\0';
   return (dup);
}
#endif

static Str newStr()
{
   Str s = (Str) malloc(sizeof(Str_));
   int l = STRSIZE;
   s->base = (void*) malloc(l);
   *s->base = '\0';
   s->l = l;
   s->c = 0;
   return (s);
}

static void chkStr(Str s, int len)
{
   int l = STRSIZE;
   if (l<len) l = len;
   if ((s->l)>(s->c+len+1)) return;
   s->base = (void*) realloc(s->base, s->l + l);
   s->l += l;
}

static void catStr(Str s, char *str, int lstr)
{
   chkStr(s, lstr);
   memcpy(s->base+s->c, str, lstr);
   s->c += lstr;
   *(s->base+s->c) = '\0';
}
   

static void freeStr(Str s)
{
   if (s->base) free(s->base);
   free(s);
}


/* frames and anchors */

void add_frame(WebGet W, char *name)
{
   if (W->frames) W->frames = (char**) realloc(W->frames, sizeof(char*)*(W->nframes+1));
   else W->frames = (char**) malloc(sizeof(char*));
   W->frames[W->nframes++] = strdup(name);
}

void add_anchor(WebGet W, char *name)
{
   if (W->anchors) W->anchors = (char**) realloc(W->anchors, sizeof(char*)*(W->nanchors+1));
   else W->anchors = (char**) malloc(sizeof(char*));
   W->anchors[W->nanchors++] = strdup(name);
}

void add_header(WebGet W, char *text)
{
   if (W->num_user_headers<MAX_USER_HEADERS) W->user_headers[W->num_user_headers++] = strdup(text);
}

/* Since 2.7.4 we use curl's verification.  Cirl now allows use to 
   fake DNS lookup differently.
 */

#ifdef VERIFICATION_THE_OLD_WAY

/* Peer verification.  We can't let curl do this
   because we allow hostname mappings.  

   Curl doesn't give us any control after the connection
   is established, thus denying us the capability of
   checking the cert's name then.  So we have to do
   that in the verify callback.  However, that means
   we are not thread-safe while establishing  the connection. */

/* Check cert name, pattern can be: '*.aaa.bbb' etc.
   Return 1 if match OK */

static int check_name(char *pat, char *name)
{
   char c;
   while (1) {
      c = *pat++;
      if (!c) return ((*name)?0:1);
      if (c=='*') {
         if (!*pat) return (1);
         while (*name) if(check_name(name++, pat)) return (1);
         return (0);
      }
      if (toupper(c) != toupper(*(name++))) return (0);
   }
}

/* SSL verify callback. 
   If verifying, check that the cert name matches the peer name.
   Return 1 if OK. */

char *static_peer_name;
static int sslverify_callback(int ok, X509_STORE_CTX *ctx)
{
   X509 *peercert;
   char cn[256];
   STACK_OF(GENERAL_NAME) *altnams;
   int i, na, r;
   int d =  X509_STORE_CTX_get_error_depth(ctx);
    
   peercert=X509_STORE_CTX_get_current_cert(ctx);
   X509_NAME_get_text_by_NID (X509_get_subject_name(peercert), NID_commonName, cn, sizeof(cn));


   if (!ok) {
      int err = X509_STORE_CTX_get_error(ctx);
      if (verify_peer) return (ok);
   }
   if (d) return (verify_peer?ok:1);
   
   /* If there's no hostname, or we're not verifying, return OK now */

   if ((!static_peer_name) || (!verify_peer)) return (1);

   /* Else check altnames first */

   altnams = X509_get_ext_d2i(peercert, NID_subject_alt_name, NULL, NULL);
   na = sk_GENERAL_NAME_num(altnams);
   for (i=0; i<na; i++) {
      char *altn;
      GENERAL_NAME *ck = sk_GENERAL_NAME_value(altnams, i);
      if (ck->type != GEN_DNS) continue;
      altn = (char *)ASN1_STRING_data(ck->d.ia5);
      if (check_name(altn, static_peer_name)) break;
   }
   GENERAL_NAMES_free(altnams);

   if (i<na) return (1); /* name ok */
   if (na<0) {  /* RFC2459: altnames must be used if present */
      if (check_name(cn,static_peer_name)) return (1);
   }

   /* make up an error */
   SSLerr(SSL_F_SSL_VERIFY_CERT_CHAIN, SSL_R_PEER_ERROR_CERTIFICATE);
   return (0);
}


static CURLcode curl_ctx_callback(CURL *curl, void *ctx, void *parm)
{
   static_peer_name = (char*) parm;
   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, sslverify_callback);
   return (0);
}

#endif /* VERIFICATION_THE_OLD_WAY */

/* hostname mappings: for 'name' use 'realname' instead */

// get ip for dns name
char *get_dottedip(char *host) {
   struct hostent *he;
   int ret;
   struct in_addr **addr_list;
   
   he = gethostbyname(host);
   if (he==NULL) {
      perror(host);
      return (NULL);
   }
   addr_list = (struct in_addr **) he->h_addr_list;
   int i;
   char *ip = (char*)malloc(256);;
   for(i = 0; addr_list[i] != NULL; i++) {
      //Return the first one;
      strcpy(ip , inet_ntoa(*addr_list[i]) );
      return (ip);
   }
   return (NULL);
}

void add_host_map(WebGet W, char *str)
{
   HostMap m;
   char *n, *s;
   if ((s=strchr(str,'='))!=NULL) {
      *s = '\0';
      for (m=W->host_maps; m; m=m->next) {
         if (!strcasecmp(m->name, str)) break;
      }
      if (m==NULL) {
         m = (HostMap) malloc(sizeof(HostMap_));
         m->name = strdup(str);
         m->next = W->host_maps;;
         W->host_maps = m;
      } else {
         if (m->realname) free(m->realname);
      }
      char *realname = strdup(s+1);
      *s = '=';
      if ((s=strchr(realname,'\n'))!=NULL) *s = '\0';
      m->realname = get_dottedip(realname); // the map realname is string of dotted address
      free(realname);
   }
}


/* parse URL */
static URL parse_url(WebGet W, char *txt) {

   char *p, *q;
   URL url = (URL) malloc(sizeof(URL_));
   int hl;

   /* extract protocol string */
   
   if (strncmp(txt,"http://",7)==0) {
      url->prot = PROT_HTTP;
      url->port = 80;
      url->use_ssl = 0;
   } else if (strncmp(txt,"https://",8)==0) {
      url->prot = PROT_HTTPS;
      url->port = 443;
      url->use_ssl = 1;
   } else {
      free (url);
      return (NULL);
   }

   if ((p = strstr(txt, "://")) == NULL) {
      free (url);
      return (NULL);
   }
   txt = p + 3;

   /* extract host name and path */
   
   url->domain = strdup(txt);
   if ((p=strchr(url->domain,'/'))!=NULL) *p = '\0';
   if ((q=strchr(url->domain,':'))!=NULL) {
      *q++ = '\0';
      url->port = atoi(q);
   }
   if ((p=strchr(txt,'/'))!=NULL) url->path = strdup(p);
   else url->path = strdup("/");
   if ((p=strchr(url->path,'\n'))!=NULL) *p = '\0';
   if ((p=strchr(url->path,'\r'))!=NULL) *p = '\0';
   return (url);
}

/* make a url string from a URL */
static char *make_url(WebGet W, URL u)
{
   char *url = (char*) malloc(strlen(u->domain)+strlen(u->path)+32);
   char pnum[16];
   char *domain = u->domain;
   if (u->prot==PROT_BAD) return (strdup("no_url"));
   
   /* check for non-standard port */
   if ( (u->use_ssl && (u->port!=443)) ||
        ((!u->use_ssl) && (u->port!=80)) ) sprintf(pnum,":%d", u->port);
   else pnum[0] = '\0';

   sprintf(url, "%s://%s%s%s", u->use_ssl?"https":"http", domain, pnum, u->path);
   return (url);
}


/* Page and page headers */


void free_page(WebPage p)
{
   if (p->content) freeStr(p->content);
   if (p->text) free(p->text);
   if (p->lower_text) free(p->lower_text);
   /* other stuff to free ? */
}
  
/* ------- Cookies ------------- */

/* convert the awkward gmt string (wday, dd-mmm-yyyy hh:mm:ss) to a time_t */
static char *mon[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
static char *wday[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
static time_t gmt2time(char *gmt)
{
  char *s = strchr(gmt, ',');
  int n;
  char mtxt[12];
  struct tm t;
  time_t res;

  if (!s) return (0);
  
  memset(&t, 0, sizeof(t));
  n = sscanf(s+1,"%d-%3s-%4d %2d:%2d:%2d",  
        &t.tm_mday, mtxt, &t.tm_year, 
        &t.tm_hour, &t.tm_min, &t.tm_sec); 
  if (n!=6) return (0);
  
  t.tm_year -= 1900;
  for (n=0;n<12;n++) if (!strcmp(mtxt,mon[n])) break;
  t.tm_mon = n;
  
  res = mktime(&t) - timezone;
  return (res);
}

/* convert a time_t to the awkward gmt string (static allocation) */
static char *time2gmt(time_t tim)
{
   static char gmt[256];
   struct tm *t;
   gmt[0] = '\0';
   t = gmtime(&tim);
   if (!t) return (gmt);
   sprintf(gmt, "%s, %2d-%s-%4d %02d:%02d:%02d GMT",
       wday[t->tm_wday], t->tm_mday, mon[t->tm_mon-1], t->tm_year+1900,
       t->tm_hour, t->tm_min, t->tm_sec);
   return (gmt);
}

/* free cookie struct */
void free_cookie(Cookie c)
{
   if (!c) return;
   if (c->name) free(c->name);
   if (c->text) free(c->text);
   if (c->domain) free(c->domain);
   if (c->path) free(c->path);
   free(c);
}

/* Add a cookie to our list. Sort common name+domain by path specificity */

static void add_cookie(WebGet W, Cookie new)
{
  Cookie lc = NULL;
  Cookie c;
  for (c=W->cookies;c;lc=c,c=c->next) {
     if (strcasecmp(c->name,new->name)) continue;
     if (strcasecmp(c->domain,new->domain)) continue;
     // same name and domain
     if (!strcasecmp(c->path,new->path)) {
        // replace old cookie
        if (lc) lc->next = new;
        else W->cookies = new;
        new->next = c->next;
        free_cookie(c);
        return;
     }
     if (!strncasecmp(c->path, new->path, strlen(c->path))) {
        // new is more specific than c
        if (lc) lc->next = new;
        else W->cookies = new;
        new->next = c;
        return;
     }
  }

  // else add at end
  if (lc) lc->next = new;
  else W->cookies = new;
  return;
}

/* Parse a set-cookie string.  This is made difficult
   by the comma having two functions:  it is part of
   a date specification; AND it delimits multiple cookies. */

static void parse_cookie(WebGet W, char *txt, int new, WebPage page)
{
   Cookie c;
   char *n, *d, *e, *p;
   int ck;
   char *mcp;

   if ((n = strchr(txt, '\n'))!=NULL) *n = '\0';
   
   for (;;) { /* loop on all possible cookies */
     mcp = NULL;
     ck = 0;
     while (txt) {  /* loop on cookie parts.  comma might be end of cookie */
        while (*txt && *txt==' ') txt++;

        e = strchr(txt, ';');  /* end of cookie part */
        if (strncasecmp(txt,"expires",7)) mcp = strchr(txt,','); 
        else mcp = strchr(txt+20,','); 

        if (e && mcp && mcp<e) e = mcp;
        else mcp = NULL;
        if (!e) e = mcp;
        if (e) *e = '\0';

        d = strchr(txt,'='); /* start of data */
        if (d) *d = '\0';

        if (ck || d) {  /* no '=' at start is bogus cookie */
           if (!ck) { /* first item is cookie name and value */
              c = (Cookie) malloc(sizeof(Cookie_));
              memset(c, '\0', sizeof(Cookie_));
              c->name = strdup(txt);
              c->text = strdup(d?d+1:"");
              c->new = new;
              ck = 1;
           } else { /* domain, path, expires, secure  */
              if (d && !strcasecmp(txt,"domain")) {
                 c->domain = strdup(d+1);
              } else if (d && !strcasecmp(txt,"path")) {
                 c->path = strdup(d+1);
              } else if (d && !strcasecmp(txt,"expires")) {
                 c->expire = gmt2time(d+1);
                 c->expires = 1;
              } else if (!strcasecmp(txt,"secure")) {
                 c->secure = 1;
              }
           }
        }
        if (mcp) break;
        if (e) txt = e+1;
        else break;
     }

     if (ck) {
        PRINTF1(" > got cookie: %s\n", c->name);

        if (!c->domain) {
           c->domain = strdup(page?page->url->domain:"");
           PRINTF1(" > fix domain to %s\n", c->domain);
        }
        if (!c->text) c->text = strdup("");
        if (!c->path) {
           c->path = strdup(page?page->url->path:"");
           if ((p=strchr(c->path,'?'))!=NULL) *p = '\0';
           if ((p=strrchr(c->path,'/'))!=NULL) *(p+1) = '\0';
           PRINTF1(" > fix path to %s\n", c->path);
        }
        PRINTF2("         data: %s=%s, for %s/%s\n", c->name,
           c->text, c->domain, c->path);
        if (c->expires) PRINTF2("      expires: %s\n", ctime(&c->expire));

if (!strcmp(c->name, "xJSESSIONID")) {
    PRINTF1(" > ignoring JSESSION\n");
} else {
        add_cookie(W, c);
}

     }

     /* may have more cookies */
     if (mcp) txt = mcp+1;
     else break;
   }
}
 

/* Retrieve cached cookies */

int restore_cookies(WebGet W)
{
   FILE *f;
   int fl;
   char *buf;

   if (!W->cache_name) return(0);
   if (!(f=fopen(W->cache_name,"r"))) return (0);
   
   if (fseek(f, 0, SEEK_END)) return (0);
   fl = ftell(f);
   fseek(f, 0, SEEK_SET);
   buf = (char*) malloc(fl+1);
   
   while (fgets(buf, fl, f)>0) {
      parse_cookie(W, buf, 0, NULL);
   }
   fclose(f);
   free(buf);  
   return (1);

}

/* Save cookies to cache */

int save_cookies(WebGet W)
{
   FILE *f;
   Cookie c;
   char exp[256];
   time_t now = time(NULL);

   if (!W->cache_name) return(0);
   f = fopen(W->cache_name,"w");
   if (!f) return (0);
   for (c=W->cookies;c;c=c->next) {
      exp[0] = '\0';
      if (c->expires) {
         if (c->expire<=now) continue;
         sprintf(exp,"; expires=%s", time2gmt(c->expire));
      }
      fprintf(f, "%s=%s; domain=%s; path=%s%s\n", 
         c->name, c->text, c->domain, c->path, exp);
   }
   fclose(f);
   return (1);
}

/* Get the cookies to send to this page */

static Str select_cookies(WebGet W, URL url)
{
   Str ck = newStr();
   Cookie c;
   int n;
   time_t now = time(NULL);
   char *domain = url->domain;
   HostMap M;

   for (c=W->cookies;c;c=c->next) {
      /* check domain (from right)  and path (from left) */
      if (c->domain && strcasecmp(c->domain,
            domain+strlen(domain)-strlen(c->domain))) continue; 
      if (c->path && strncmp(c->path,
            url->path, strlen(c->path))) continue; 
      if (c->expires && (c->expire<=now)) continue;
      catStr(ck, c->name, strlen(c->name));
      catStr(ck, "=", 1);
      catStr(ck, c->text, strlen(c->text));
      catStr(ck, ";", 1);
      PRINTF1(" > sending cookie: %s\n", c->name);
      PRINTF2(" >           data: %s, for %s%s\n",
                c->text, c->domain, c->path);
   }
   return (ck);
}

void print_cookies(WebGet W) 
{
   Cookie c;
   for (c=W->cookies;c;c=c->next) {
         if (c->new) printf("Cookie: %s=%s; domain=%s; path=%s\n",
            c->name, c->text, c->domain, c->path);
   }
}



/* Find the value for key 'name' in the string.
   Return empty string if keyword only.
   Return NULL if keyword not found. 
   "pos" get the pointer to the original value. */

static char *find_key(char *str, char *name, char **pos)
{
   char *v, *e;
   char *s = str;
   int nl = strlen(name);

   while (*s) {
      while (isspace(*s) || (*s==';')) s++;
      if (!strncmp(s, name, nl) && !isalnum(*(s+nl))) break;
      while (*s && (!isspace(*s)) && (*s!=';')) s++;
   }

   if (!*s) return(NULL);
   s += nl;
   while (*s==' ') s++;

   if (*s++!='=') return(strdup(""));  /* keyword only */

   /* look for value */
   if (*s=='"') {
      s++;
      e = strchr(s,'"');
   } else if (*s=='\'') {
      s++;
      e = strchr(s,'\'');
   } else {
      for (e=s;(*e)&&(*e!=';')&&(*e!=' ')&&(*e!='>'); e++);
   }
   if (!e) return (NULL); /* invalid */

   v = strndup(s, e-s);
   if (pos) *pos = s;
   return (v);
}

/* Load a known form from a string */

int load_known_form(WebGet W, char *str)
{
   KnownForm f = (KnownForm) malloc(sizeof(KnownForm_));
   KnownFormInput fi;
   char *s, *v, *z;
   int ok = 0;

   f->domain = NULL;
   f->name = NULL;
   f->inputs = NULL;
   f->submit_name = NULL;
   f->submit_value = NULL;

   /* parse "name=value;" strings.  semicolons can be escaped. 
      This leaves the '\\', which will be stripped in encode_form_text */

   PRINTF3("..kf define\n");

   if ((s=strchr(str,'\n'))!=NULL) *s = '\0';

   for (s=str;*s;) {
      int ctl = 1;
      while (*s && *s==' ') s++;
      if ((v=strchr(s,'='))!=NULL) {
         for (z=v; *z; z++) if ((*z==';')&&(*(z-1)!='\\')) break;
         ok++;
         *v++ = '\0';
         if (*z) *z++ = '\0';
        
         if (!strncmp(s, "input:", 6)) {
            s += 6;
            ctl = 0;
         }
         if (ctl && !strcasecmp(s,"domain")) {
            f->domain = strdup(v);
            PRINTF3("..kf domain = %s\n", v);
         } else if (ctl && !strcasecmp(s,"name")) {
            f->name = strdup(v);
            PRINTF3("..kf name = %s\n", v);
         } else if (ctl && !strcasecmp(s,"submit_name")) {
            f->submit_name = strdup(v);
            PRINTF3("..kf submit_name = %s\n", v);
         } else if (ctl && !strcasecmp(s,"submit_value")) {
            f->submit_value = strdup(v);
            PRINTF3("..kf submit_value = %s\n", v);
         } else {
            fi = (KnownFormInput) malloc(sizeof(KnownFormInput_));
            fi->next = f->inputs;
            f->inputs = fi;
            fi->name = strdup(s);
            fi->data = strdup(v);
            PRINTF3("..kf (%s=%s)\n", s, v);
         }
      s = z;
      } else break;
   }
   if (ok) {
     f->next = W->known_forms;
     W->known_forms = f;
     PRINTF3("..kf done: %s\n", f->name?f->name:"--");
   } else free (f);
   return(1); 
}

/* Load a known form from a file */

int load_known_form_from_file(WebGet W, char *file)
{
   FILE *f;
   int fl;
   char *buf;

   if (!file) return(0);
   if (!(f=fopen(file,"r"))) return (0);
   
   if (fseek(f, 0, SEEK_END)) return (0);
   fl = ftell(f);
   fseek(f, 0, SEEK_SET);
   buf = (char*) malloc(fl+1);
   
   while (fgets(buf, fl, f)>0) {
      load_known_form(W, buf);
   }
   fclose(f);
   free(buf);
   return (1);
}

/* Encode the form text.  Single escapes are ignored. 
   "\;" -> semicolon, "\n" -> newline */

static char *encode_form_text(char *t)
{
   char *enc = (char*) malloc(3*strlen(t)+12);
   char *e = enc;
   for (; *t; t++) {
       if (isalnum(*t) || (*t=='.') || (*t=='_') || (*t=='-')) *e++ = *t;
       else if (*t=='\n') *e++ = '%', *e++ = '0', *e++ = 'D', *e++ = '%', *e++ = '0', *e++ = 'A';
       else if (*t=='\r') *e++ = '%', *e++ = '0', *e++ = 'D';
       else if (*t==' ') *e++ = '+';
       else if (*t=='%') *e++ = '%', *e++ = '2', *e++ = '5';
       else if (*t=='/') *e++ = '%', *e++ = '2', *e++ = 'F';
       else if (*t=='(') *e++ = '%', *e++ = '2', *e++ = '8';
       else if (*t==')') *e++ = '%', *e++ = '2', *e++ = '9';
       else if (*t=='\'') *e++ = '%', *e++ = '2', *e++ = '7';
       else if (*t==':') *e++ = '%', *e++ = '3', *e++ = 'A';
       else if (*t==';') *e++ = '%', *e++ = '3', *e++ = 'B';
       else if (*t=='<') *e++ = '%', *e++ = '3', *e++ = 'C';
       else if (*t=='>') *e++ = '%', *e++ = '3', *e++ = 'E';
       else if (*t=='=') *e++ = '%', *e++ = '3', *e++ = 'D';
       else if (*t=='?') *e++ = '%', *e++ = '3', *e++ = 'F';
       else if (*t=='+') *e++ = '%', *e++ = '2', *e++ = 'B';
       else if (*t=='&') *e++ = '%', *e++ = '2', *e++ = '6';
       else if (*t=='#') *e++ = '%', *e++ = '2', *e++ = '3';
       else if (*t=='!') *e++ = '%', *e++ = '2', *e++ = '1';
       else if (*t==',') *e++ = '%', *e++ = '2', *e++ = 'C';
       else if (*t=='"') *e++ = '%', *e++ = '2', *e++ = '2';
       else if (*t=='^') *e++ = '%', *e++ = '5', *e++ = 'E';
       else if (*t=='$') *e++ = '%', *e++ = '2', *e++ = '4';
       else if (*t=='@') *e++ = '%', *e++ = '4', *e++ = '0';
       else if (*t=='\\') {
           if (*(t+1)=='\\') *e++ = '%', *e++ = '5', *e++ = 'C', t++;
           if (*(t+1)=='n') *e++ = '%', *e++ = '0', *e++ = 'A', t++;
       } else {
           *e++ = *t;
       }
   }
   *e = '\0';
   return(enc);
}

/* Sometimes incoming form data is pre-encoded.  That has to be undone. */
// thanks to Sam Attridge.

static char *decode_text(char *t) {
   char *dec = (char*) malloc(3*strlen(t)+12);
   char *ret = dec;
   for (; *t; t++) {
      if (!strncasecmp(t, "&lt;", 4)) *dec++='<', t=t+3; 
      else if (!strncasecmp(t, "&gt;", 4)) *dec++='>', t=t+3; 
      else if (!strncasecmp(t, "&amp;", 5)) *dec++='&', t=t+4; 
      else if (!strncasecmp(t, "&quot;", 6)) *dec++='"', t=t+5; 
      else if (!strncasecmp(t, "&apos;", 6)) *dec++='\'', t=t+5; 
      else *dec++ = *t;
   }
   *dec = '\0';
   return(ret);

}

/* Add a name=value to our form response */

static void append_form_text(Str text, char *n, char *v)
{
  char *enc;

  if (text->c != 0) catStr(text, "&", 1);
  enc = encode_form_text(n);
  catStr(text, enc, strlen(enc));
  // free(n);
  free(enc);
  catStr(text, "=", 1);
  char *vv = decode_text(v);
  enc = encode_form_text(vv); 
  catStr(text, enc, strlen(enc));
  // free(v);
  free(vv);
  free(enc);
}

/* See if this page has a form we should fill out.
   If so, return that form */

static Form isaform(WebPage page)
{
   WebGet W = page->W;
   Form form;
   KnownForm kf;
   KnownFormInput kfi;
   Str text;
   char *fs, *fe;
   char *action;
   char *method;
   char *name;
   char *s, *e;
   char *n, *v, *w, *wn;
   char *enc_n, *enc_v;
   URL url = page->url;
   int l;
   char *ap;
   char *proto;
   char port[7];
   char *sub_n, *sub_v;
   int need_sub;
   char *fs_sav;
   char *fe_sav;
 
   /* Find a form that we should respond to */

   fe = NULL;
   for (fs=page->lower_text; (fs=strstr(fs,"<form")); fs=fe+1) {

      fe = strchr(fs,'>');
      if (!fe) return (NULL);
      *fe = '\0';  /* to limit searches */
   
      action = find_key(fs, "action", &ap);
      /* get un-lowered action text */
      if (action) {
	l = strlen(action);
	n = (char *) malloc(l+1);
	strncpy(n, page->text+(ap-page->lower_text), l);
	n[l] = '\0';
	action = decode_text(n);
        free(n);
      } else action = strdup("");

      method = find_key(fs, "method", NULL);
      name = find_key(fs, "name", NULL);
      if (!name) name = find_key(fs, "id", NULL);
      if (!name) name = strdup("");

      if (action && method) {
         /* add protocol if missing */
         if (strncmp(action,"http",4)) {
            char portspec[24] = "";
            if (url->prot==PROT_HTTP && url->port!=80) snprintf(portspec, 24, ":%d", url->port);
            if (url->prot==PROT_HTTPS && url->port!=443) snprintf(portspec, 24, ":%d", url->port);
            s = (char*)malloc(strlen(action)+strlen(url->domain)+21+strlen(url->path));
            proto=(url->prot==PROT_HTTP? "http":"https");
            if (*action) {
              if (*action=='/') {
	         sprintf(s,"%s://%s%s%s", proto, url->domain, portspec, action);
              } else {
	         sprintf(s,"%s://%s%s%s", proto, url->domain, portspec, url->path);
                 if (*action=='?') strcat(s, action);  
                 else strcpy(strrchr(s,'/')+1, action);
              }
	    } else {
	      sprintf(s,"%s://%s%s%s", proto, url->domain, portspec, url->path);
              /* strip parameters if method is GET */
              if (!strcasecmp(method,"get")) if ((ap=strrchr(s,'?'))!=NULL) *ap = '\0';
	    }
            action = s;
            PRINTF1(" > form action fixed to %s\n", action);
         }
         for (s=method;*s;s++) if (islower(*s)) *s = toupper(*s);
   
         *fe = '>';  /* put back */

         fs_sav = fs;
         fe_sav = strstr(fs,"</form");
         if (!fe_sav) return (NULL);     /* invalid form */
         *fe_sav = '\0';  /* to limit searches */

         /* do we act on this form */
         for (kf=W->known_forms;kf;kf=kf->next) {
            int have_correct_submit = 0;

            fs = fs_sav;
            fe = fe_sav;

             if (kf->domain && strcasecmp(kf->domain, url->domain)) continue;
             if (kf->name && strcasecmp(kf->name, name)) continue;

            /* Found a form - fill out and submit */
         
            if ((!kf->submit_name)&&(!kf->submit_value)) have_correct_submit = 1;

            PRINTF1(" > responding to form %s\n",
                  kf->name?kf->name:"-null-");
         
            /* Start the response with all the user's supplied values */
         
            text = newStr(); 
         
            if (kf) {
               for (kfi=kf->inputs;kfi;kfi=kfi->next) {
                  append_form_text(text, kfi->name, kfi->data);
               }
            }
         
         
         #ifdef NOSCRIPT
            s = fs;
            while (s = strstr(s, "<script>")) {  /* omit anything in scripts */
                char *e = strstr(s, "</script>");
                while (s<(e+9)) *s++ = ' ';
            }
         #endif
         
            /* Process the inputs: <input ...>  
               If user supplied a "submit" we do only that one - else do the first one we find.
             */
         
            s = fs;
            e = NULL;
            sub_n = NULL; 
            sub_v = NULL; 
            need_sub = 1;
         
            while ((s = strstr(s, "<input"))!=NULL) {
                char *wp;
                int userv = 0;
                int subtype = 0;
         
                e = strchr(s, '>');
                if (!e) break;  /* invalid */
                *e = '\0';
         
                wn = find_key(s, "name", &wp);
               
                // check the submit value and name with or without a name
         
                w = find_key(s, "type", NULL);
                if (w) {
                   if (!strcasecmp(w, "submit")) {
                       subtype = 1;
                       if (wn && kf->submit_name && !strcasecmp(wn, kf->submit_name)) {
                          PRINTF1(".. form by submit name: %s\n", wn);
                          have_correct_submit = 1;
                       }
                       if (kf->submit_value) {
                          char *ww = find_key(s, "value", &wp);
                          if (ww && !strcasecmp(ww, kf->submit_value)) {
                             PRINTF1(".. form by submit value: %s\n", ww);
                             have_correct_submit = 1;
                          }
                          if (ww) free(ww);
                       }
                   } 
                   if (!strcasecmp(w, "file")) userv = 1;
                   free(w);
                }
         
                if (wn) {
                   n = strndup(page->text+(wp-page->lower_text), strlen(wn));

                   /* Add only if user did not supply a value */
         
                   if (kf) {
                      for (kfi=kf->inputs;kfi;kfi=kfi->next) {
                         if (!strcasecmp(n, kfi->name)) userv = 1;
                      }
                   }
                   if (subtype && userv) need_sub = 0;
               
                   if (!userv) {
                      w = find_key(s, "value", &wp);
                      if (w) {
                         v = strndup(page->text+(wp-page->lower_text), strlen(w));
                         free(w);
                      } else v = strdup("");
            
                      if (subtype) {
                         if (!sub_n) {
                            sub_n = strdup(n);
                            sub_v = strdup(v);
                         }
                      } else append_form_text(text, n, v);
                      free(v);
                   }
                   free(n);
                   free(wn);
                }
                *e = '>';
                s = e + 1;
                e = NULL;
            }
            if (sub_n && need_sub) append_form_text(text, sub_n, sub_v);
            if (sub_n) free(sub_n);
            if (sub_v) free(sub_v);
         
            if (e) *e = '>';  /* replace */
            
            if (!have_correct_submit) {
               PRINTF1(".. reject form due to wrong submit name\n");
               freeStr(text);
               continue;
            }
         
            /* Process textareas: <textarea ...>default_value</textarea>  
               */
         
            s = fs;
            e = NULL;
         
            while ((s = strstr(s, "<textarea"))!=NULL) {
                char *wp;
                int userv = 0;
                char *dv;
         
                dv = strchr(s, '>');
                if (!dv) break;  /* invalid */
                dv++;
                while (isspace(*dv)) dv++;
         
                e = strstr(dv, "</textarea");
                if (!e) break;  /* invalid */
                *e = '\0';
         
                w = find_key(s, "name", &wp);
                if (w) {
                   n = strndup(page->text+(wp-page->lower_text), strlen(w));
                   free(w);
         
                   /* Add only if user did not supply a value */
         
                   if (kf) {
                      for (kfi=kf->inputs;kfi;kfi=kfi->next) {
                         if (!strcasecmp(n, kfi->name)) userv = 1;
                      }
                   }
         
                   if (!userv) {
                      v = strndup(page->text+(dv-page->lower_text), e-dv);
                      append_form_text(text, n, v);
                      free(v);
                   }
                   free(n);
                }
                *e = '<';
                s = e + 10;
                e = NULL;
            }
            if (e) *e = '<';  /* replace */
            
            /* We do not automatically respond to "options" and "selections".
               The user can supply those values in the form text. */
         
            if (fe) *fe = '<';
         
            form = (Form) malloc(sizeof(Form_));
            form->method = method;
            form->action = action;
            form->name = name;
            form->data = strdup(text->base);
            // printf("form-data: %ss\n", form->data);
            /* freeStr(text); */
            return (form);
         } /* for (kf) */

         *fe_sav = '<';
         fs = fs_sav;
         fe = fe_sav;
      }
      *fe = '>';  /* replace */
   }

   return (NULL);  /* none found */
}  


/* Possibly add the protocol and hostname to a url */

static char *full_url(WebPage page, char *text)
{
   static char ustr[4096];
   char *tq, *ts;
   URL u = page->url;
   ustr[0] = '\0';
   if (!text) return (ustr);
   if (strncmp(text,"http",4)==0) return (text);
   sprintf(ustr,"%s://%s:%d",
        u->use_ssl?"https":"http", u->domain, u->port);

   if (*text=='/') strcat(ustr, text);
   else {
      tq = strchr(u->path, '?');
      if (tq) *tq = '\0';
      ts = strrchr(u->path,'/');
      strncat(ustr,u->path,ts-u->path+1);
      strcat(ustr,text);
      if (tq) *tq = '?';
   }
   return (ustr);
}


/* See if this page has a redirection we should follow.
   Location, Redirect, Frame, anchors  */

static char *redirect_url(WebPage page)
{
   WebGet W = page->W;
   PageHeader h;
   char *s, *e;
   char *n, *v;
   char *fs, *fe;
   char *rp;
   char *fsp;
   char *rr;
   int i;
 
   /* Check for new location in the headers */
   for (h=page->headers;h;h=h->next) {
      if (!strcasecmp(h->name, "Location")) return (full_url(page, h->text));
      if (!strcasecmp(h->name, "Refresh")) {
         return (full_url(page, find_key(h->text, "URL", NULL)));
      }
   }
      
   /* Check for new location in the text */
   fsp = page->lower_text;
   fs = fsp;
   fe = NULL;
   rr = NULL;
   while ((fs=strstr(fs,"<meta")) && !rr) {
     if (!fs) break;
     fe = strchr(fs,'>');
     if (!fe) break;
     *fe = '\0';  /* to limit searches */
   
     n = find_key(fs, "http-equiv", NULL);
     if (n && !strcasecmp(n,"refresh")) {
        char *v = find_key(fs, "content", &rp);
        if (v) {
          int sec = atoi(v); /* seconds before refresh */
          if (sec>1) {
             PRINTF1(" > delayed refresh (%d sec) not followed\n", sec);
             break;
          }
          s = strstr(v,"url=");
          if (s) {  /* we need the un-lowered one */
            int l;
            l = strlen(s+4);
            rr = (char *) malloc(l+1);
            strncpy(rr, page->text + (rp-page->lower_text) + (s+4-v), l);
            rr[l] = '\0';
            break;
          }
        }
     }
     *fe++ = '>';
     fs = fe+1;
     fe = NULL;
   }
   if (fe) *fe = '>';
   if (rr) return (full_url(page, rr));


   /* check for frames we should follow */
   fs = fsp;
   fe = NULL;
   while ((fs=strstr(fs,"<frame")) && !rr) {
     if (!fs) break;
     fe = strchr(fs,'>');
     if (!fe) break;
     *fe = '\0';  /* to limit searches */
   
     if ((n=find_key(fs, "name", &rp))!=NULL) {
       for (i=0;i<W->nframes;i++) if (!strcasecmp(W->frames[i],n)) break;
       if (i!=W->nframes) {
          char *v = find_key(fs, "src", &rp);
          if (v) {
             int l = strlen(v);
             rr = (char *) malloc(l+1);
             strncpy(rr, page->text + (rp-page->lower_text), l);
             rr[l] = '\0';
             break;
          }
       }
     }
     *fe++ = '>';
     fs = fe;
     fe = NULL;
   }
   if (fe) *fe = '>';
   if (rr) return (full_url(page, rr));

   /* check for anchors we should follow */
   fs = fsp;
   fe = NULL;
   while ((fs=strstr(fs,"<a ")) && !rr) {
     char *href;
     if (!fs) break;
     fe = strchr(fs,'>');
     if (!fe) break;
     *fe = '\0';  /* to limit searches */
   
     href = find_key(fs, "href", &rp);
     s = fe+1;
     if (!(e=strstr(s, "</a>"))) break;
     *e = '\0';
     for (i=0;i<W->nanchors;i++) if (!strcasecmp(W->anchors[i],s)) break;
     *e = '<';
     if (i!=W->nanchors) {
        int l = strlen(href);
        rr = (char *) malloc(l+1);
        strncpy(rr, page->text + (rp-page->lower_text), l);
        rr[l] = '\0';
        break;
     }
     *fe++ = '>';
     fs = fe;
     fe = NULL;
   }
   if (fe) *fe = '>';
   if (rr) return (full_url(page, rr));

   return (NULL);
}  

// copy with '&#...;' dereferencing (len includes the zero byte)
// (ignore any translations not ascii)

char *dereference_page(WebPage page)
{
   char *base = page->content->base;
   int len = page->length+1;
   char *out = (char*) malloc(len);
   char *op = out;
   char *p;
   int b = 0;

   while ((p=strstr(base, "&#"))!=NULL) {
       char *e;
       char c;

       // copy up to here
       memcpy(op, base, p-base);
       op += p-base;
       base = p;

       p += 2;
       b = 10;
       if (*p=='x' || *p=='X') b=16, p++;
       c = strtol(p, &e, b);
       if (c && isascii(c)) {
          *op++ = c;
          base = e;
          if (*base==';') base++;
       } else *op++ = *base++;
   }
   // copy rest
   strcpy(op, base);
   if (b) page->length = strlen(out);
   return (out);
}

static char *formtype;
int alarm_set = 0;

int page_sock = 0;

/* curl text reciever.  just accumulate text.
   If maxxbuf bytes received, reroute output to binfile and done. */
static size_t page_reader(void *buf, size_t len, size_t num, void *wp)
{
  WebPage page = (WebPage) wp;
  WebGet W = page->W;
  /* fprintf(stderr, "..recv %d(%d) bytes: [%s]\n", len, num, buf); */
  if ((W->maxxbuf>0) && (!page->hitbin) && (page->content->c + len*num > W->maxxbuf)) {
      PRINTF1("Max text reached at %d\n", page->content->c);
      if (!W->binfile) {
         fprintf(stderr, "ERR: Max text exceeded and no bin file!\n");
         return (0);
      }
      fwrite(page->content->base, page->content->c, 1, W->binfile);
      page->hitbin = 1;
  }
  if (page->hitbin) {
     fwrite(buf, len, num, W->binfile);
  } else {
     catStr(page->content, buf, len*num);
  }
  return (len*num);
}

/* curl header reader. */
static size_t header_reader(void *buf, size_t len, size_t num, void *wp)
{
  WebPage page = (WebPage) wp;
  WebGet W = page->W;
  PageHeader ph;
  char *p, *e;

  // PRINTF2("..head %d(%d) bytes: [%s]\n", len, num, buf);

  /* Assumption: we can modify the data */
  if ((p=strchr(buf,':'))!=NULL) {
     *p++ = '\0';
     if ((e=strchr(p,'\n'))!=NULL) *e = '\0';
     if ((e=strchr(p,'\r'))!=NULL) *e = '\0';
     ph = (PageHeader) malloc(sizeof(PageHeader_));
     /* This reverses the order of headers */
     ph->next = page->headers;
     page->headers = ph;
     ph->name = strdup(buf);
     ph->text = strdup(p+1);
     PRINTF2(" header> %s: %s\n", ph->name, ph->text);
     if (!strcasecmp(ph->name,"Set-Cookie")) parse_cookie(W, p+1,1,page);
     if (!strcasecmp(ph->name,"Content-Length")) {
         page->content_length = atoi(ph->text);
         PRINTF1(" content_length=%d\n", page->content_length);
     }
   }
  return (len*num);
}

static size_t put_function(void *ptr, size_t size, size_t nmemb, void *stream) 
{
   // fprintf(stderr, ".. put wants %d*%d bytes\n", size, nmemb);
   memcpy(ptr, "<body><li></li></body>", 22);
   return (22);
}

WebPage get_one_page(WebGet W, char *urlstr, Form form) 
{
   URL url;
   struct curl_slist *fakehost = NULL;

   int i;
   int c;
   int n;
   int x;
   WebPage page = (WebPage) malloc(sizeof(WebPage_));
   PageHeader  ph, lph;
   struct timeval tv;
   char *s, *e, *p;
   Str ckstr;
   Str xbuf;
   int postform = 0;
   int getform = 0;
   char *fixurl;
   struct timeval pst;
   int ret;

   gettimeofday(&pst, NULL);
   memset (page, '\0', sizeof(WebPage_));
   page->content = newStr();
   page->W = W;
   
   curl_easy_setopt(W->curl, CURLOPT_WRITEDATA, page);
   curl_easy_setopt(W->curl, CURLOPT_WRITEHEADER, page);

   page->url = parse_url(W, urlstr);
   if (!page->url) {
       free_page(page);
       return (NULL);
   }
   curl_easy_setopt(W->curl, CURLOPT_SSL_CTX_DATA, page->url->domain);

   if (W->headers) curl_slist_free_all(W->headers);
   W->headers = NULL;
   fixurl = make_url(W, page->url);

   if (form) {
    if (!strcasecmp(form->method,"get")) {
       getform = 1;
       PRINTF1("..resp to form by get\n");
    } else if (!strcasecmp(form->method,"post")) {
       postform = 1;
       PRINTF1("..resp to form by post\n");
    }
   }

   PRINTF1(">> Getting page: %s %s\n", fixurl, delete_op?"(DELETE)":"");

   /* compose HTTP request */

   ckstr = select_cookies(W, page->url);
   if (ckstr->base && *ckstr->base) curl_easy_setopt(W->curl, CURLOPT_COOKIE, ckstr->base);
   curl_easy_setopt(W->curl, CURLOPT_USERAGENT, W->user_agent);
   /* TEST */
   // curl_easy_setopt(W->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
   // curl_easy_setopt(W->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
   curl_easy_setopt(W->curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_DEFAULT);

   /* check for mapped host */
   HostMap M;
   for (M=W->host_maps; M; M=M->next) {
      if (strcasecmp(M->name, page->url->domain)) continue;
      PRINTF1("using '%s' for '%s'\n", M->realname, M->name);
      curl_easy_setopt(W->curl, CURLOPT_FRESH_CONNECT, lone);

      char fakeip[256];
      snprintf(fakeip, 256, "-%s:%d",  M->name, page->url->port);
      fakehost = curl_slist_append(NULL, fakeip);
      curl_easy_setopt(W->curl, CURLOPT_RESOLVE, fakehost);

      curl_slist_free_all(fakehost);
      snprintf(fakeip, 256, "%s:%d:%s",  M->name, page->url->port, M->realname);
      fakehost = curl_slist_append(NULL, fakeip);
      curl_easy_setopt(W->curl, CURLOPT_RESOLVE, fakehost);
   }

   /* add user's headers */
   
   for (i=0; i<W->num_user_headers; i++) {
       W->headers = curl_slist_append(W->headers, W->user_headers[i]);
   }
   curl_easy_setopt(W->curl, CURLOPT_HTTPHEADER, W->headers);

   if (getform) {

      /* GET form response appends the data to the url */
      char *geturl = (char*) malloc(strlen(fixurl)+strlen(form->data)+2);
      sprintf(geturl,"%s?%s", fixurl, form->data);
      curl_easy_setopt(W->curl, CURLOPT_HTTPGET, lone);
      curl_easy_setopt(W->curl, CURLOPT_URL, geturl);

   } else if (postform) {

      /* POST form response sends the data separately */
      curl_easy_setopt(W->curl, CURLOPT_POSTFIELDS, form->data);
      curl_easy_setopt(W->curl, CURLOPT_POST, lone);
      curl_easy_setopt(W->curl, CURLOPT_URL, fixurl);

   } else {

    if (postdata) {
      curl_easy_setopt(W->curl, CURLOPT_POSTFIELDS, postdata);
      curl_easy_setopt(W->curl, CURLOPT_POST, lone);
      curl_easy_setopt(W->curl, CURLOPT_URL, fixurl);

/**
    } else if (putdata) {
      curl_easy_setopt(W->curl, CURLOPT_VERBOSE, lone);
      // curl_easy_setopt(W->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
      curl_easy_setopt(W->curl, CURLOPT_READFUNCTION, put_function);
      curl_easy_setopt(W->curl, CURLOPT_UPLOAD, lone);
 **/

    } else if (putfile) {
      int nb = 0;
      fseek(putfile, 0, SEEK_END);
      nb = ftell(putfile);
      fseek(putfile, 0, SEEK_SET);
      curl_easy_setopt(W->curl, CURLOPT_VERBOSE, lone);
      // curl_easy_setopt(W->curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
      curl_easy_setopt(W->curl, CURLOPT_READDATA, putfile);
      curl_easy_setopt(W->curl, CURLOPT_INFILESIZE, nb);
      curl_easy_setopt(W->curl, CURLOPT_UPLOAD, lone);
      curl_easy_setopt(W->curl, CURLOPT_URL, fixurl);

    } else if (delete_op) {
      curl_easy_setopt(W->curl, CURLOPT_CUSTOMREQUEST, "DELETE");
      curl_easy_setopt(W->curl, CURLOPT_URL, fixurl);

    } else {

      /* Else is simple GET */
      curl_easy_setopt(W->curl, CURLOPT_HTTPGET, lone);
      curl_easy_setopt(W->curl, CURLOPT_URL, fixurl);
    }
   }

   if (form) PRINTF3( " > form data: %s\n", form->data);

   /* Get or post the page */

   ret = curl_easy_perform(W->curl);

   if (fakehost) curl_slist_free_all(fakehost);

   if (ret) {
      free_page(page);
      W->curl_err = ret;
      return (NULL);
   }
   if (page->hitbin) return (page);

   if (page->content_length) page->length = page->content_length;
   else page->length = page->content->c;
      
   // page->text = malloc(page->length+1);
   // memcpy(page->text, page->content->base, page->length+1);
   page->text = dereference_page(page);
   page->lower_text = malloc(page->length+1);
   memcpy(page->lower_text, page->text, page->length+1);
   for (n=0,s=page->lower_text;n<page->length;n++,s++) if (isupper(*s)) *s = tolower(*s);
   freeStr(page->content);
   page->content = NULL;
   PRINTF3("  DATA\n %s  \nEDATA\n", page->text);


   /* curl_easy_cleanup(W->curl); */
   /* curl_easy_reset(W->curl); */

   if (W->show_pt) {
      struct timeval pet;
      int et;
      gettimeofday(&pet, NULL);
    
      et = (pet.tv_sec-pst.tv_sec)*1000 + (pet.tv_usec-pst.tv_usec)/1000;
      printf("PageET: page=%s, EMS=%d\n", fixurl, et);
   }
    
   return (page);

}


void print_text(WebPage page)
{
   WebGet W = page->W;
   PRINTF1("PAGEDATA\n");
   fwrite(page->text, page->length, 1, stdout);
   printf("\n");
   PRINTF1("ENDPAGEDATA\n");
}

/* Get pages - following redirections, forms, frames, etc. */

WebPage process_pages(WebPage page)
{
   WebGet W = page->W;
   char *rstr;
   Form f;
   int hop = 0;

   while (page && hop++<W->maxhop && !page->hitbin) {

      /* redirections */
      if ((rstr=redirect_url(page))!=NULL) {
         hop++;
         free_page(page);
         page = get_one_page(W, rstr, NULL);
         continue;
      }
      /* forms */
      if ((f=isaform(page))!=NULL) {
         hop++;
         free_page(page);
         page = get_one_page(W, f->action, f);
         continue;
      }
      break; /* no more pages to get */
   }
  
   /* maybe show or save the result */
   if (page) {
      if (W->show_cookies) print_cookies(W);
      if (W->binfile) {
          if (!page->hitbin) fwrite(page->text, page->length, 1, W->binfile);
          fclose (W->binfile);
          W->binfile = NULL;
      }
      if ((!page->hitbin) && W->show_text) print_text(page);
   }

   return (page);
}  


/* Initialize, etc. */

void new_curl(WebGet W) {
   if (W->curl!=NULL) curl_easy_cleanup(W->curl);
   W->curl = curl_easy_init();
   if (verify_peer) {
      curl_easy_setopt(W->curl, CURLOPT_SSL_VERIFYPEER, lone);
      curl_easy_setopt(W->curl, CURLOPT_SSL_VERIFYHOST, ltwo);
   } else {
      curl_easy_setopt(W->curl, CURLOPT_SSL_VERIFYPEER, lzero);
      curl_easy_setopt(W->curl, CURLOPT_SSL_VERIFYHOST, lzero);
   }
   curl_easy_setopt(W->curl, CURLOPT_WRITEFUNCTION, page_reader);
   curl_easy_setopt(W->curl, CURLOPT_HEADERFUNCTION, header_reader);
#ifdef VERIFICATION_THE_OLD_WAY
   curl_easy_setopt(W->curl, CURLOPT_SSL_CTX_FUNCTION, curl_ctx_callback);
#endif
   curl_easy_setopt(W->curl, CURLOPT_DNS_CACHE_TIMEOUT, lzero);

}


WebGet new_WebISOGet()
{
   WebGet W = (WebGet) malloc(sizeof(WebGet_));

   memset(W, '\0', sizeof(WebGet_));

   new_curl(W);

   W->maxhop = 20;
   W->maxxbuf = MAXXBUF;
   W->user_agent = USER_AGENT_WEBISOGET;
   
   return (W);
}



