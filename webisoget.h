/* ========================================================================
 * Copyright (c) 2004-2005 The University of Washington
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


/* Library definitions for the webisoget package */

#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>

extern long timezone;
extern int daylight;
extern int verify_peer;

#include <curl/curl.h>
#include <curl/easy.h>

#ifndef FALSE
#define FALSE 0
#endif

#define MAX_USER_HEADERS 100  // should be dynamic?

#define STRSIZE 8192
#define MAXXBUF 1024*1024

#define USER_AGENT_GECKO "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7a) Gecko/20040413"
#define USER_AGENT_WEBISOGET "Mozilla/4.0 (compatible; MSIE 5.01; WebISOGet"
#define USER_AGENT_IE "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)"

#define PRINTF1 if (W->debug>0) printf /* verbose level */
#define PRINTF2 if (W->debug>1) printf /* debug levels */
#define PRINTF3 if (W->debug>2) printf

/* strings */
typedef struct Str__ {
  char *base;  /* base of allocated mem */
  int l;  /* total length */
  int c;  /* current pointer */
} Str_, *Str;


/* allow hostname mappings: for 'name' use 'realname' instead */
typedef struct HostMap__ {
   struct HostMap__ *next;
   char *name;
   char *realname;
} HostMap_, *HostMap;

/* expanded url */
typedef struct URL__ {
   int prot;
   char *domain;
   int port;
   char *path;
   int use_ssl;
} URL_, *URL;

#define PROT_BAD   0
#define PROT_HTTP  1
#define PROT_HTTPS 2


/* Cookies */

typedef struct Cookie__ {
   struct Cookie__ *next;
   char *name;
   char *text;
   char *domain;
   char *path;
   int  expires;
   time_t expire;
   int secure;
   int new;
} Cookie_, *Cookie;


/* Forms that we should reply to */
typedef struct KnownFormInput__ {
  struct KnownFormInput__ *next;
  char *name; 
  char *data;
} KnownFormInput_, *KnownFormInput;

typedef struct KnownForm__ {
  struct KnownForm__ *next;
  char *domain;
  char *name;
  KnownFormInput inputs;
  char *submit_name;
  char *submit_value;
} KnownForm_, *KnownForm; 


/* possible response to a form */ 
typedef struct Form__ {
  char *method;
  char *action;
  char *name;
  char *data;
} Form_, *Form;


/* Configuration switches, etc. */

typedef struct WebGet__ {
  int debug;
  int show_text;
  int show_cookies;
  int show_pt;

  int maxhop;
  int timeout;
  int maxxbuf;
  char *user_agent;

  FILE *binfile;
  char *cache_name;
  Cookie cookies;

  HostMap host_maps;

  char **frames;
  int nframes;

  char **anchors;
  int nanchors;

  KnownForm known_forms;

  CURL *curl;
  int curl_err;

  char *user_headers[MAX_USER_HEADERS];
  int num_user_headers;
  struct curl_slist *headers;

} WebGet_, *WebGet;




/* Page and page headers */

typedef struct PageHeader__ {
   struct PageHeader__ *next;
   char *name;
   char *text;
} PageHeader_, *PageHeader;
   
/* Webpage */

typedef struct WebPage__ {
   WebGet W;
   PageHeader headers;
   Str content;
   char *text;
   char *lower_text;
   URL url;
   int length;
   int content_length;
   int hitbin;
} WebPage_, *WebPage;



/* prototypes */

void add_frame(WebGet W, char *name);
void add_anchor(WebGet W, char *name);
void add_host_map(WebGet W, char *str);
void free_page(WebPage p);
int restore_cookies(WebGet W);
int save_cookies(WebGet W);
void print_cookies(WebGet W);
int load_known_form(WebGet W, char *str) ;
int load_known_form_from_file(WebGet W, char *file);
WebPage get_one_page(WebGet W, char *urlstr, Form form);
WebPage process_pages(WebPage page);
WebGet new_WebISOGet();
void add_header(WebGet W, char *text);
void new_curl(WebGet W);
