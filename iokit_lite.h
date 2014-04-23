/*
 * Copyright (c) 2014, winocm. <winocm@icloud.com>. All rights reserved.
 */

#ifndef _IOKIT_LITE_H_
#define _IOKIT_LITE_H_

#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>

typedef mach_port_t		io_service_t, io_connect_t, io_object_t;
extern mach_port_t		kIOMasterPortDefault;

CFTypeRef 			IORegistryEntryCreateCFProperty(io_service_t, CFStringRef, CFAllocatorRef, int);
CFDictionaryRef 	IOServiceMatching(const char*);
io_service_t 		IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);
kern_return_t		IORegistryEntrySetCFProperties(io_service_t, CFTypeRef);

void	IOObjectRelease(io_object_t);

#endif /* _IOKIT_LITE_H_ */