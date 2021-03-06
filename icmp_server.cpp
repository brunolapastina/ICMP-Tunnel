/*
Compile: gcc -o icmp_server -Wall -lcrypto icmp_server.c
ICMP data transfer server
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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>

unsigned short checksum (unsigned short *addr, int len)
{
   int nleft = len;
   int sum = 0;
   unsigned short *w = addr;
   unsigned short answer = 0;
   while (nleft > 1){
      sum += *w++;
      nleft -= 2;
   }
   if (nleft == 1){
      *(unsigned char *) (&answer) = *(unsigned char *) w;
      sum += answer;
   }
   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);
   answer = ~sum;
   return (answer);
}

void usage(){
   fprintf(stderr, "Usage: ./bin [-f <filename>]\n");
   exit(EXIT_SUCCESS);
}

int main (int argc, char **argv)
{
   int ret = 0;
   int one = 1;
   int sock_icmp;
   int fd;
   int ip_len;
   int icmp_len;
   int icmp_data_in_len;
   int opt = 0;
   char *filename = NULL;
   unsigned char sha1hash[20];
   char buf_incoming[5000];
   char buf_outgoing[5000];
   char payload[5000];
   char exec_mode = 0;
   struct sockaddr_in dst;
   struct ip *ip_hdr_in, *ip_hdr_out;
   struct icmp *icmp_hdr_in, *icmp_hdr_out;

   while ((opt = getopt(argc, argv, "hcf:")) != -1) {
      switch (opt) {
      case 'f':
         filename = optarg;
         break;
      case 'c':
         exec_mode = 1;
         break;
      case 'h':
      default:
         usage();
      }
   }

   if ((sock_icmp = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
   {
      perror ("socket");
      exit (1);
   }
  
   if ((ret = setsockopt (sock_icmp, IPPROTO_IP, IP_HDRINCL, (char *) &one, sizeof (one))) < 0)
   {
      perror ("setsockopt");
      exit (1);
   }

   if (filename)
   {
      if ((fd = open(filename, O_WRONLY|O_CREAT|O_TRUNC|O_SYNC, S_IRUSR)) == -1)
      {
         perror("open");
         exit(1);
      }
   }
   else
{
      fd = STDOUT_FILENO;
   }
   
   // Disable kernel response to ping
   system( "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all" );

   //eth_hdr = (struct ether_header *) buf_incoming;
   //ip_hdr_in = (struct ip *) (buf_incoming + sizeof (struct ether_header));
   //icmp_hdr_in = (struct icmp *) ((unsigned char *) ip_hdr_in + sizeof (struct ip));
   ip_hdr_in = (struct ip *) (buf_incoming);
   icmp_hdr_in = (struct icmp *) ((unsigned char*) ip_hdr_in + sizeof (struct ip));

   ip_hdr_out = (struct ip *) buf_outgoing;
   icmp_hdr_out = (struct icmp *) (buf_outgoing + sizeof (struct ip));

   while ((ret = recv (sock_icmp, ip_hdr_in, sizeof (buf_incoming), 0)) > 0)
   {
      if ( (IPPROTO_ICMP == ip_hdr_in->ip_p) && (ICMP_ECHO == icmp_hdr_in->icmp_type) )
      {
         ip_hdr_out->ip_v = ip_hdr_in->ip_v;
         ip_hdr_out->ip_hl = ip_hdr_in->ip_hl;
         ip_hdr_out->ip_tos = ip_hdr_in->ip_tos;
         ip_hdr_out->ip_len = ip_hdr_in->ip_len;
         ip_hdr_out->ip_id = ip_hdr_in->ip_id;
         ip_hdr_out->ip_off = 0;
         ip_hdr_out->ip_ttl = 255;
         ip_hdr_out->ip_p = IPPROTO_ICMP;
         ip_hdr_out->ip_sum = 0;
         ip_hdr_out->ip_src.s_addr = ip_hdr_in->ip_dst.s_addr;
         ip_hdr_out->ip_dst.s_addr = ip_hdr_in->ip_src.s_addr;
         ip_hdr_out->ip_sum = checksum ((unsigned short *) buf_outgoing, ip_hdr_out->ip_hl);

         icmp_hdr_out->icmp_type = ICMP_ECHOREPLY;
         icmp_hdr_out->icmp_code = 0;
         icmp_hdr_out->icmp_id = icmp_hdr_in->icmp_id;
         icmp_hdr_out->icmp_seq = icmp_hdr_in->icmp_seq;
         icmp_hdr_out->icmp_cksum = 0;

         ip_len = ntohs (ip_hdr_in->ip_len);
         icmp_len = ip_len - sizeof (struct iphdr);
         icmp_data_in_len = ntohs(ip_hdr_in->ip_len) - sizeof(struct ip) - sizeof(struct icmphdr);
         
         printf( "Received (%d, %d) ID=%hu Seq=%hu: (%d)\n", ip_hdr_in->ip_p, icmp_hdr_in->icmp_type, icmp_hdr_in->icmp_id, icmp_hdr_in->icmp_seq, icmp_data_in_len );
         
         memset(payload, 0, sizeof(payload));
         memcpy(payload, icmp_hdr_in->icmp_data, icmp_data_in_len);
         
         //write(fd, payload, icmp_data_in_len);

         memcpy(icmp_hdr_out->icmp_data, payload, icmp_data_in_len);
         dst.sin_family = AF_INET;
         dst.sin_addr.s_addr = ip_hdr_out->ip_dst.s_addr;
         icmp_hdr_out->icmp_cksum = checksum ((unsigned short *) icmp_hdr_out, icmp_len);
         
         printf( "Sending  (%d, %d) ID=%d Seq=%d\n", ip_hdr_out->ip_p, icmp_hdr_out->icmp_type, icmp_hdr_out->icmp_id, icmp_hdr_out->icmp_seq );
         
         ret = sendto(sock_icmp, buf_outgoing, ip_len, 0, (struct sockaddr *) &dst, sizeof (dst));
         if (ret < 0){
            perror ("sendto");
            // Enable kernel response to ping
            system( "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all" );
            exit(1);
         }
         
         if (payload[0] == '.' && icmp_data_in_len == 1)
         {
            break;
         }
      }
      else
      {
         //printf( "*** Pacote errado (%d, %d) ***\n", ip_hdr_in->ip_p, icmp_hdr_in->icmp_type );
      }
   }
   
   memset(sha1hash, 0, sizeof(sha1hash));
   ret = recv(sock_icmp, ip_hdr_in, sizeof(buf_incoming), 0);
   
   memcpy(sha1hash, icmp_hdr_in->icmp_data, sizeof(sha1hash));
   for ( unsigned int i = 0; i < sizeof(sha1hash); i++)
   {
      fprintf( stderr, "%02X ", sha1hash[i] );
   }
   fprintf( stderr, "\n" );
   
   close(fd);
   close(sock_icmp);
   
   // Enable kernel response to ping
   system( "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all" );
   
   return 0;
}
