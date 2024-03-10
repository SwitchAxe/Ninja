#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <libusb-1.0/libusb.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define _BSD_SOURCE

// platform-independent constants
#define RCM_PAYLOAD_ADDR ((size_t) 0x40010000) 
#define PAYLOAD_START_ADDR ((size_t) 0x40010E40)
#define STACK_SPRAY_START ((size_t) 0x40014E40)
#define STACK_SPRAY_END ((size_t) 0x40017000)
#define STD_REQ_DEV_TOH_TOE ((size_t) 0x82)
#define STD_REQ_DEV_TOH ((size_t) 0x80)
#define GET_DESCRIPTOR ((size_tt) 0x6)
#define GET_CONFIG ((size_t) 0x8)
#define GET_STATUS ((size_t) 0x0)

// taken from fusee-nano

#define INTERMEZZO_LOCATION ((size_t) 0x4001F000)
#define PAYLOAD_LOAD_BLOCK ((size_t) 0x40020000)
// Linux-specific constants

#define PACKET_SIZE ((size_t) 8)
#define IOCTL_IOR ((size_t) 0x80000000)
#define IOCTL_TYPE ((size_t) 'U')
#define IOCTL_NR_SUBMIT_URB ((size_t) 10)
#define URB_CTRL_REQ ((size_t) 2)

// NX vendor ID
#define NX_VID ((size_t) 0x0955)
// and product ID
#define NX_PID ((size_t) 0x7321)

// exploit specifics
#define CPY_BUF_ADDR(_I) ((_I) ? 0x40009000 : 0x40005000)

#define STACK_END ((size_t) 0x40010000)

typedef struct {
  uint8_t type;
  uint8_t endpoint;
  int status;
  unsigned int flags;
  void* buffer;
  int buffer_length;
  int actual_length;
  int start_frame;
  unsigned int stream_id;
  int error_count;
  unsigned int signr;
  void* user_context;
} SubmitURBIoctl;


// get an handle for a device with
// libusb_open_device_with_vid_pid() and then
// you can find all the other info and store them in
// this struct.
typedef struct {
  uint8_t bus;
  uint8_t addr;
  libusb_device_handle* handle;
} DeviceInfo;

typedef struct {
  size_t length;
  unsigned char* contents;
} FileInfo;

DeviceInfo*
get_device_info(libusb_device_handle* handle);

unsigned char* build_packet(size_t len);
char* pad_number(int n);
char* format_usb_path(int bus, int addr);

SubmitURBIoctl*
build_request(unsigned char* buf, size_t len);

int get_ioctl_number(SubmitURBIoctl* request);

int submit_request(int reqnum, char* path,
		    SubmitURBIoctl* request);

int __internal_event_callback(struct libusb_context* c,
			      struct libusb_device* dev,
			      libusb_hotplug_event ev,
			      void* data);

void wait_for_nx();

unsigned char* read_bytes(libusb_device_handle* handle,
			  int len, int* rc);
int write_bytes(libusb_device_handle* handle,
		 unsigned char* data, size_t len, int* rc);

DeviceInfo* setup_connection();

int write_to_rcm(libusb_device_handle* handle,
		  unsigned char* data, size_t len);

size_t trigger_vulnerability(DeviceInfo* info, size_t length);

size_t get_current_buf();
unsigned char* read_device_id(libusb_device_handle* handle);

void switch_to_highbuf();
void trigger_memcpy(DeviceInfo* info, size_t length);
void hax(); // the core of the whole program!
