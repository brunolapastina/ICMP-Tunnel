/*
Compile: gcc -o icmp_client -Wall -lcrypto icmp_client.c
ICMP data transfer client
Copyright (C) 2011 Sean Williams

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include "CICMPExchangeClient.h"

void usage(){
   fprintf(stderr, "Usage: ./bin -h <ip> -f <filename>\n");
   exit(EXIT_SUCCESS);
}

int main (int argc, char **argv)
{
   CICMPExchangeClient* pobjClient = NULL;
   unsigned char  payload[1024];
   unsigned char  sha1_hash[20];
   u_short  payload_len;
   char* filename = NULL;
   bool  bDone = false;
   int   ret = 0;
   int   fd;
   int   opt = 0;
   
   SHA_CTX  stHashCtx;

   while ((opt = getopt(argc, argv, "hd:f:")) != -1) {
      switch (opt) {
      case 'f':
         filename = optarg;
         break;
      case 'd':
         pobjClient = new CICMPExchangeClient( optarg );
         break;
      case 'h':
      default:
         usage();
      }
   }
   
   if ( !pobjClient || !filename )
   {
      usage();
   }
   
   if ((fd = open(filename, O_RDONLY)) == -1){
      perror("open");
      exit(1);
   }
   
   SHA1_Init( &stHashCtx );
   
   while( !bDone )
   {
      memset(payload, 0, sizeof(payload));
      
      ret = read( fd, payload, sizeof(payload) );
      if ( -1 == ret )
      {
         perror("read");
         exit(1);
      }
      else if (ret == 0)
      {  // End of file, send payload-end delimiter '.'
         payload[0] = '.';
         payload_len = 1;
         bDone = true;
      }
      else
      {  // Gather next bit of file
         payload_len = ret;
         SHA1_Update( &stHashCtx, payload, payload_len );
      }
      
      pobjClient->Send( payload, payload_len );
   }
   
   // Calc and send the SHA1 file hash
   SHA1_Final( sha1_hash, &stHashCtx );
   
   printf( "Hash = " );
   for( int i = 0; i < 20; i++ )
   {
      printf( "%02X ", sha1_hash[i] );
   }
   printf( "\n" );
   
   pobjClient->Send( sha1_hash, sizeof(sha1_hash) );

   close(fd);
   
   delete( pobjClient );
   
   return 0;
}
