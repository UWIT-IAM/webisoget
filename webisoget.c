/* ========================================================================
 * Copyright (c) 2004-2006 The University of Washington
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


/* Retrieve a web page, following redirections, and 
   responding to some forms.

   This allows us to obtain , for example, pubcookies and thereby
   retrieve pubcookie protected pages.

*/

#include "webisoget.h"

char *postdata = NULL;
FILE *postfile = NULL;
char *putdata = NULL;
FILE *putfile = NULL;

int interactive = 0;
extern int delete_op;
long lone = 1;
long ltwo = 2;
long lzero = 0;

static char *user_agent = USER_AGENT_GECKO;

static char *prog;
struct {
 char *cmd;
 char *help;
} commands[] = {
 {"anchor anchor_text ", "<a...> link to follow"},
 {"cache file_name    ", "cookie cache for restore/save"},
 {"cafile file_name   ", "CA certificates (PEM)"},
 {"cert file_name     ", "Client certificate (PEM)"},
 {"key file_name      ", "Client certificate key (PEM) [aka 'certkey']"},
 {"continue           ", "reprocess last page"},
 {"cookies            ", "enable cookie report"},
 {"debug              ", "for more commentary"},
 {"debug2             ", "for more commentary"},
 {"debug3             ", "for even more commentary "},
 {"delete             ", "next request will be DELETE"},
 {"header header      ", "add header "},
 {"form form_info     ", "form info"},
 {"formfile file_name ", "form info in file"},
 {"frame frame_name   ", "frame to follow"},
 {"map virt=real      ", "mapping of hostnames"},
 {"maxhop count       ", "max number of redirects to follow (def=20)"},
 {"maxtext count      ", "max chars of text to stdout (def=1M, 0=unlimited)"},
 {"out output_file    ", "write final page to output_file"},
 {"pagetimes          ", "show elapsed time per page"},
 {"postfile file      ", "file to post"},
 {"putfile file       ", "file to put"},
 {"quit               ", "exit"},
 {"text               ", "enable display of page text"},
 {"timeout seconds    ", "set timeout in seconds (default=60)"},
 {"url url            ", "url to get"},
 {"verbose            ", "for commentary"},
 {"version            ", "show version"},
 { NULL, NULL }
};
 
 
static void usage()
{
   int c;
   if (interactive) {
     printf("Commands..\n");
     for (c=0; commands[c].cmd; c++) {
        printf("   %s %s\n", commands[c].cmd, commands[c].help);
     }
     printf("\n");
   } else {
     fprintf(stderr, "usage: %s [commands] \n", prog);
     for (c=0; commands[c].cmd; c++) {
        fprintf(stderr, "   -%s %s\n", commands[c].cmd, commands[c].help);
     }
     fprintf(stderr,"Commands are processed in the order sepcified.\n");
     fprintf(stderr,"Absence of a url enters stdin command mode.\n");
     fprintf(stderr, "\n");
     exit(1);
   }
}

static void helper()
{
   int c;
   for (c=0; commands[c].cmd; c++) {
      fprintf(stderr, "   %s %s\n", commands[c].cmd, commands[c].help);
   }
   fprintf(stderr, "\n");
}

/* read from a file into a string */

static char *get_file(char *file)
{
   FILE *f = fopen(file,"r");
   char *str;
   long l;

   if (!f) return (NULL);
   fseek(f, 0, SEEK_END);
   l = ftell(f);
   rewind(f);

   str = (char*) malloc(l+1);
   size_t r = fread(str, l, 1, f);
   fclose(f);

   return(str);
}



static void set_debug(WebGet W, int d)
{
   W->debug = d;
   if (d>1) curl_easy_setopt(W->curl, CURLOPT_VERBOSE, 1);
}

/* process a command */

static WebPage current_page = NULL;
static int didurl = 0;

static int docmd(WebGet W, char *cmd, char *arg)
{
   char                inbuf[1024];
   char               *p;
   int                 headers = 1;

   char *url = NULL;
   WebPage page;
   char *s;
   char curl_errtxt[CURL_ERROR_SIZE];

   curl_easy_setopt(W->curl, CURLOPT_ERRORBUFFER, curl_errtxt);

   /* parameter setting */
   if (!strcmp(cmd,"verbose")) {
      set_debug(W, 1);
      curl_easy_setopt(W->curl, CURLOPT_VERBOSE, 1);
   } else if (!strcmp(cmd,"debug")) {
      set_debug(W, 2);
   } else if (!strcmp(cmd,"debug2")) {
      set_debug(W, 2);
   } else if (!strcmp(cmd,"debug3")) {
      set_debug(W, 3);

   } else if (!strcmp(cmd,"cookies")) {
      W->show_cookies = 1;

   } else if (!strcmp(cmd,"pubcookies")) {
      /* obsolete option */
      W->show_cookies = 1;

   } else if (!strcmp(cmd,"text")) {
      W->show_text = 1;

   } else if (!strcmp(cmd,"maxhop")) {
      if (!arg) usage();
      W->maxhop = atoi(arg);
      if (W->maxhop<0) usage();

   } else if (!strcmp(cmd,"maxtext")) {
      if (!arg) usage();
      W->maxxbuf = atoi(arg);
      if (W->maxxbuf<0) usage();

   } else if (!strcmp(cmd,"timeout")) {
      if (!arg) usage();
      W->timeout = atoi(arg);
      if (W->timeout<=0) usage();
      curl_easy_setopt(W->curl, CURLOPT_TIMEOUT, W->timeout);

   } else if (!strcmp(cmd,"cache")) {
      if (!arg) usage();
      W->cache_name = strdup(arg);
      restore_cookies(W);

   } else if (!strcmp(cmd,"form")) {
      if (!arg) usage();
      load_known_form(W, arg);

   } else if (!strcmp(cmd,"formfile")) {
      if (!arg) usage();
      load_known_form_from_file(W, arg);

   } else if (!strcmp(cmd,"frame")) {
      if (!arg) usage();
      add_frame(W, arg);

   } else if (!strcmp(cmd,"anchor")) {
      if (!arg) usage();
      add_anchor(W, arg);

   } else if (!strcmp(cmd,"map")) {
      if (!arg) usage();
      add_host_map(W, arg);

   } else if (!strcmp(cmd,"postdata")) {
      if (!arg) usage();
      postdata = strdup(arg);

   } else if (!strcmp(cmd,"postfile")) {
      if (!arg) usage();
      postdata = get_file(arg);

   } else if (!strcmp(cmd,"putdata")) {
      if (!arg) usage();
      putdata = strdup(arg);

   } else if (!strcmp(cmd,"putfile")) {
      if (!arg) usage();
      putfile = fopen(arg, "r");

   } else if (!strcmp(cmd,"header")) {
      if (!arg) usage();
      add_header(W, arg);

   } else if (!strcmp(cmd,"url")) {
      if (!arg) usage();
      if (current_page) {
         free_page(current_page);
         current_page = NULL;
      }
      page = get_one_page(W, arg, NULL);
      delete_op = 0;
      if (page) page = process_pages(page);
      if (!page) {
          if (W->curl_err) fprintf(stderr, "Curl error %d: %s\n", W->curl_err, curl_errtxt);
          return (0);
      }
      didurl++;
      current_page = page;

   } else if ((!strcmp(cmd,"continue"))||(!strcmp(cmd,"c"))) {
      if (current_page) current_page = process_pages(current_page);

   } else if ((!strcmp(cmd,"bin")) || (!strcmp(cmd,"out"))) {
      if (!arg) usage();
      W->binfile = fopen(arg,"w");
      if (!W->binfile) {
         perror("binfile");
         if (!interactive) exit (1);
      }

   } else if (!strcmp(cmd,"delete")) {
      delete_op = 1;

   } else if (!strcmp(cmd,"cert")) {
      if (!arg) usage();
      curl_easy_setopt(W->curl, CURLOPT_SSLCERT, strdup(arg));
      curl_easy_setopt(W->curl, CURLOPT_SSLCERTTYPE, "PEM");

   } else if ((!strcmp(cmd,"certkey")) || (!strcmp(cmd, "key"))) {
      if (!arg) usage();
      curl_easy_setopt(W->curl, CURLOPT_SSLKEY, strdup(arg));
      curl_easy_setopt(W->curl, CURLOPT_SSLKEYTYPE, "PEM");

   } else if (!strcmp(cmd,"cafile")) {
      if (!arg) usage();
      curl_easy_setopt(W->curl, CURLOPT_CAINFO, strdup(arg));
      // curl_easy_setopt(W->curl, CURLOPT_SSL_VERIFYPEER, lone);
      // curl_easy_setopt(W->curl, CURLOPT_SSL_VERIFYHOST, ltwo);
      verify_peer = 1;

   } else if (!strcmp(cmd,"noverify")) {
      // curl_easy_setopt(W->curl, CURLOPT_SSL_VERIFYPEER, lzero);
      // curl_easy_setopt(W->curl, CURLOPT_SSL_VERIFYHOST, lzero);
      verify_peer = 0;

   } else if (!strcmp(cmd,"pagetimes")) {
      W->show_pt = 1;

   } else if (!strcmp(cmd,"agent")) {
      if (!arg) usage();
      W->user_agent = strdup(arg);

   } else if (!strcmp(cmd,"version")) {
      fprintf(stdout, "%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
      exit (0);

   } else if (!strcmp(cmd,"newcurl")) {
     new_curl(W);

   } else if (!strcmp(cmd,"quit")) {
      save_cookies(W);
      exit (0);

   } else usage();

   return (1);
}


int  main(int argc, char *argv[])
{
   char inbuf[1024];
   char *p;
   int  headers = 1;
   int  r;
   WebGet W;

   char *cmd, *arg;

   prog = (argv++)[0];
   tzset();

   /* Initialize library */

   W = new_WebISOGet();

   /* process command line commands */

   while (--argc) {

      cmd = (argv++)[0]+1;
      if ((argc>1) && (*(argv[0])!='-')) {
         arg = (argv++)[0];
         argc--;
      } else arg = NULL;
      
      if (!docmd(W, cmd, arg)) exit(1);

   }

   /* no url on command line means get instructions from stdin */

   if (!didurl) {

      interactive = 1;
      for (;;) {
       fputs("cmd: ", stderr);
       if (fgets(inbuf,1024, stdin)) {
         char *n;
         char *cmd, *arg;
         if (!*inbuf) break;
         if ((n=strchr(inbuf,'\n'))!=NULL) *n = '\0';

         /* get command and arg */
         cmd = inbuf;
         while (*cmd==' ') cmd++;  /* delete leading spaces */
         if (!*cmd) continue;
         arg = cmd;
         while (isalnum(*arg)) arg++;
         *arg++ = '\0';
         while (*arg==' ') arg++;
         if (*arg) {
           n = arg + strlen(arg) - 1;
           while (isspace(*n)) *n-- = '\0'; /* delete trailing spaces */
         }
         
         if (!docmd(W, cmd, arg)) exit (1);
       } else {
         puts("");
         break;
       }
      }
   }

   /* save the received cookies if all went OK */

   save_cookies(W);
   exit (0);
}

