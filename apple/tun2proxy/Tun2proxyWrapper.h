//
//  Tun2proxyWrapper.h
//  tun2proxy
//
//  Created by ssrlive on 2023/4/23.
//

#ifndef Tun2proxyWrapper_h
#define Tun2proxyWrapper_h

@interface Tun2proxyWrapper : NSObject

+ (void)startWithConfig:(NSString *)proxy_url
                 tun_fd:(int)tun_fd
                tun_mtu:(uint16_t)tun_mtu
           dns_over_tcp:(bool)dns_over_tcp
                verbose:(bool)verbose;
+ (void) shutdown;

@end

#endif /* Tun2proxyWrapper_h */
