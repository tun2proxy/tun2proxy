//
//  Tun2proxyWrapper.m
//  tun2proxy
//
//  Created by ssrlive on 2023/4/23.
//

#import <Foundation/Foundation.h>

#import "Tun2proxyWrapper.h"
#include "tun2proxy-sys.h"

@implementation Tun2proxyWrapper

+ (void)startWithConfig:(NSString *)proxy_url
                 tun_fd:(int)tun_fd
                tun_mtu:(uint32_t)tun_mtu
           dns_over_tcp:(bool)dns_over_tcp
                verbose:(bool)verbose {
  tun2proxy_run(proxy_url.UTF8String, tun_fd, tun_mtu, dns_over_tcp, verbose);
}

+ (void)shutdown {
  tun2proxy_stop();
}

@end
