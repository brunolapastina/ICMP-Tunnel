#ifndef _CICMPEXCHANGECLIENT_H_
#define _CICMPEXCHANGECLIENT_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <pthread.h>
#include <vector>

//#define  MTU         1480
#define  MTU         5000

class CICMPExchangeClient
{
public:
   CICMPExchangeClient( const char* szDestination );
   ~CICMPExchangeClient();
   
   void CommThread();
   
   int Send( unsigned char* paucData, unsigned int uiLength );
   int Receive( unsigned char* paucData, unsigned int uiMaxLength, unsigned int uiLength );
   
private:
   typedef struct
   {
      struct ip      IPHeader;
      struct icmp    ICMPHeader;
   } SPacket;

   std::vector<unsigned char> m_vOutBuffer;
   std::vector<unsigned char> m_vInBuffer;
   struct in_addr m_DestAddr;
   //std::thread    m_thCommThread;
   pthread_t      m_thCommThread;
   bool  m_bKeepRunning;
   int   m_iSocket;
   
   unsigned short CalcChecksum( void* pData, int len );
   void FillHeader( SPacket* pstPacket, unsigned short uiSequence, unsigned char *payload, u_short payload_len );
};

#endif