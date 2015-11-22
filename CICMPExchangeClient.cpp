#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include "CICMPExchangeClient.h"

#define  PACKET_ID      12345
#define  ONE_MB         1024*1024
#define  MAX_PAYLOAD    (MTU - sizeof(struct ip) - sizeof(struct icmphdr))
#define  MAX_RETRIES    5

#define  GetPacketLength( a )       ntohs( (a)->IPHeader.ip_len )
#define  GetPayloadLength( a )      ( ntohs( (a)->IPHeader.ip_len ) - sizeof(struct ip) - sizeof(struct icmphdr) )

static void* ThreadStarter( void* pArg )
{
   ((CICMPExchangeClient*)pArg)->CommThread();
   return NULL;
}

CICMPExchangeClient::CICMPExchangeClient( const char* szDestination ) : m_bKeepRunning( true ),
                                                                        m_iSocket( -1 )
{
   char  szMessage[256];
   int   iRet;
   int   iAux = 1;
   
   inet_pton(AF_INET, szDestination, &m_DestAddr);
   m_vOutBuffer.reserve( 10*ONE_MB );
   m_vInBuffer.reserve( 10*ONE_MB );
   
   m_iSocket = socket ( AF_INET, SOCK_RAW, IPPROTO_ICMP );
   if ( 0 > m_iSocket )
   {
      sprintf( szMessage, "socket: %s", strerror(errno) );
      throw( szMessage );
   }
   
   // Do not generate a IP header automaticaly. We will supply it
   iRet = setsockopt ( m_iSocket, IPPROTO_IP, IP_HDRINCL, (char*) &iAux, sizeof(iAux) );
   if ( 0 > iRet)
   {
      sprintf( szMessage, "setsockopt: %s", strerror(errno) );
      throw( szMessage );
   }
   
   //m_thCommThread = std::thread( CICMPExchangeClient::CommThread, this );
   
   iRet = pthread_create( &m_thCommThread, NULL, ThreadStarter, this );
   if( 0 != iRet )
   {
      sprintf( szMessage, "pthread_create: %s", strerror(errno) );
      throw( szMessage );
   }
   
   system( "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all" );
}

CICMPExchangeClient::~CICMPExchangeClient()
{
   int iRet;
   
   m_bKeepRunning = false;
   
   //m_thCommThread.join();
   
   iRet = pthread_join( m_thCommThread, NULL );
   if( 0 != iRet )
   {
      char  szMessage[256];
      sprintf( szMessage, "pthread_join: %s", strerror(errno) );
      throw( szMessage );
   }
   
   if( 0 <= m_iSocket )
   {
      close( m_iSocket );
   }
   
   system( "echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all" );
}

int CICMPExchangeClient::Send( unsigned char* paucData, unsigned int uiLength )
{
   for( unsigned int i = 0; i < uiLength; i++ )
   {
      m_vOutBuffer.push_back( paucData[i] );
   }
   
   return 0;
}

int CICMPExchangeClient::Receive( unsigned char* paucData, unsigned int uiMaxLength, unsigned int uiLength )
{
   return 0;
}

void CICMPExchangeClient::CommThread()
{
   struct sockaddr_in   stDestAddr;
   unsigned short usPayloadLen;
   unsigned short usSequenceNumber;
   struct timeval tv;
   SPacket* pstOutPacket;
   SPacket* pstInPacket;
   fd_set   aFdSet;
   char  szMessage[256];
   bool  bSentSuccessfuly;
   int   iRet;
   int   i;
   
   stDestAddr.sin_family = AF_INET;
   stDestAddr.sin_addr.s_addr = m_DestAddr.s_addr;
   
   usSequenceNumber = 0;
   
   pstOutPacket = (SPacket*) malloc( MTU );
   if( NULL == pstOutPacket )
   {
      sprintf( szMessage, "malloc: %s", strerror(errno) );
      throw( szMessage );
   }
   
   pstInPacket = (SPacket*) malloc( MTU );
   if( NULL == pstInPacket )
   {
      sprintf( szMessage, "malloc: %s", strerror(errno) );
      throw( szMessage );
   }
   
   while ( m_bKeepRunning || !m_vOutBuffer.empty() )
   {
      if( !m_vOutBuffer.empty() )
      {
         usPayloadLen = (MAX_PAYLOAD < m_vOutBuffer.size() ) ? MAX_PAYLOAD : m_vOutBuffer.size();
         
         FillHeader( pstOutPacket, usSequenceNumber, &m_vOutBuffer[0], usPayloadLen );
         m_vOutBuffer.erase( m_vOutBuffer.begin(), m_vOutBuffer.begin()+usPayloadLen );
         
         for( (i = 0), (bSentSuccessfuly = false); (i < MAX_RETRIES) && (!bSentSuccessfuly); i++ )
         {
            printf( "Sending  (%d, %d) ID=%hu Seq=%hu: (%d)\n", pstOutPacket->IPHeader.ip_p, 
                                                                pstOutPacket->ICMPHeader.icmp_type,
                                                                pstOutPacket->ICMPHeader.icmp_id,
                                                                pstOutPacket->ICMPHeader.icmp_seq,
                                                                GetPayloadLength( pstOutPacket ) );
            
            iRet = sendto( m_iSocket, pstOutPacket, GetPacketLength( pstOutPacket ), 0, (struct sockaddr*) &stDestAddr, sizeof (stDestAddr) );
            if( 0 > iRet )
            {
               sprintf( szMessage, "sendto: %s", strerror(errno) );
               throw( szMessage );
            }
            
            // Wait up to one second for a reply
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            
            // While not timeout
            while( (!bSentSuccessfuly) && ((tv.tv_sec > 0) || (tv.tv_usec > 0)) )
            {
               // Set file descriptor
               FD_ZERO( &aFdSet );
               FD_SET( m_iSocket, &aFdSet );
            
               iRet = select( m_iSocket+1, &aFdSet, NULL, NULL, &tv );
               if( 0 == iRet )
               {  // Timeout exceeded
                  printf( "Timeout on packet sequence %hu\n", pstInPacket->ICMPHeader.icmp_seq );
                  break;
               }
               else if( 0 > iRet )
               {  // Error
                  sprintf( szMessage, "select: %s", strerror(errno) );
                  throw( szMessage );
               }
               else
               {
                  iRet = recv ( m_iSocket, pstInPacket, MTU, 0 );
                  if( 0 > iRet )
                  {  // Error
                     sprintf( szMessage, "recv: %s", strerror(errno) );
                     throw( szMessage );
                  }
                  else if ( 0 == iRet )
                  {  // No data
                     printf( "No data received on packet sequence %hu\n", pstInPacket->ICMPHeader.icmp_seq );
                  }
                  else if ( (IPPROTO_ICMP == pstInPacket->IPHeader.ip_p)                            &&
                            (ICMP_ECHOREPLY == pstInPacket->ICMPHeader.icmp_type )                  &&
                            (pstInPacket->ICMPHeader.icmp_id  == pstOutPacket->ICMPHeader.icmp_id)  &&
                            (pstInPacket->ICMPHeader.icmp_seq == pstOutPacket->ICMPHeader.icmp_seq) )
                  {  // Received the correct packet
                     bSentSuccessfuly = true;
                     break;
                  }
                  else
                  {  // Received an incorrect packet
                     /*printf( "Recevied wrong packet (%d, %d) ID=%hu Seq=%hu Len=%d\n", pstInPacket->IPHeader.ip_p,
                                                                                       pstInPacket->ICMPHeader.icmp_type,
                                                                                       pstInPacket->ICMPHeader.icmp_id,
                                                                                       pstInPacket->ICMPHeader.icmp_seq,
                                                                                       GetPacketLength(pstInPacket) );*/
                  }
               }
            }
            
            if( !bSentSuccessfuly )
            {
               printf( "Retrying\n" );
            }
         }
         
         usSequenceNumber++;
      }
      else
      {
         usleep( 10000 );
      }
   }
   
   free( pstOutPacket );
   free( pstInPacket );
}

unsigned short CICMPExchangeClient::CalcChecksum( void* pData, int iLen )
{
   int nleft = iLen;
   int sum = 0;
   unsigned short* w = (unsigned short*)pData;
   unsigned short answer = 0;
   
   while (nleft > 1)
   {
      sum += *w++;
      nleft -= 2;
   }
   
   if (nleft == 1)
   {
      *(unsigned char *) (&answer) = *(unsigned char *) w;
      sum += answer;
   }
   
   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);
   answer = ~sum;
   
   return (answer);
}

void CICMPExchangeClient::FillHeader( SPacket* pstPacket, unsigned short uiSequence, unsigned char *payload, u_short payload_len )
{
   pstPacket->IPHeader.ip_v = 4;
   pstPacket->IPHeader.ip_hl = 5;
   pstPacket->IPHeader.ip_tos = 0;
   pstPacket->IPHeader.ip_len = htons( sizeof(struct ip) + sizeof(struct icmphdr) + payload_len );
   pstPacket->IPHeader.ip_id = 9;
   pstPacket->IPHeader.ip_off = 0;
   pstPacket->IPHeader.ip_ttl = 127;
   pstPacket->IPHeader.ip_p = IPPROTO_ICMP;
   pstPacket->IPHeader.ip_src.s_addr = htonl(INADDR_ANY);
   pstPacket->IPHeader.ip_dst.s_addr = m_DestAddr.s_addr;
   pstPacket->IPHeader.ip_sum = CalcChecksum( &pstPacket->IPHeader, sizeof(struct ip) );
   
   pstPacket->ICMPHeader.icmp_type = ICMP_ECHO;
   pstPacket->ICMPHeader.icmp_code = 0;
   pstPacket->ICMPHeader.icmp_id = PACKET_ID;
   pstPacket->ICMPHeader.icmp_seq = uiSequence;
   memcpy ( pstPacket->ICMPHeader.icmp_data, payload, payload_len);
   pstPacket->ICMPHeader.icmp_cksum = CalcChecksum( &pstPacket->ICMPHeader, (sizeof(struct icmphdr) + payload_len) );
}