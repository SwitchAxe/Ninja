#include "inject.h"

int main() {
  libusb_init(NULL);
  hax();
  libusb_exit(NULL);
  return 0;
}
