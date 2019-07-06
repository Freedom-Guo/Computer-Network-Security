#ifndef TOOL_H
#define TOOL_H
#include "stdio.h"
#include "stdlib.h"
void Hex2Str( const char *sSrc,  char *sDest, int nSrcLen );
void char2IP( const char *sSrc,  char *sDest, int nSrcLen );

#endif // TOOL_H

void char2Mac( const char *sSrc,  char *sDest, int nSrcLen )
{
    int  i;
    char szTmp[4];

    for( i = 0; i < nSrcLen; i++ )
    {
        sprintf( szTmp, "%02X", (unsigned char) sSrc[i] );
        memcpy( &sDest[i * 3], szTmp, 2 );
        sDest[3*i+2]=':';

    }
    sDest[nSrcLen*2+nSrcLen-1]='\0';
    return ;
}

void char2IP( const char *sSrc,  char *sDest, int nSrcLen ){
    int  i;
    char szTmp[5];

    for( i = 0; i < nSrcLen; i++ )
    {
        sprintf( szTmp, "%3d", (unsigned char) sSrc[i] );
        memcpy( &sDest[i * 4], szTmp, 3);
        sDest[4*i+3]='.';

    }
    sDest[nSrcLen*3+nSrcLen-1]='\0';
    return ;
}
