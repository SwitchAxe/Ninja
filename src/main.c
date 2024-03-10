#include "inject.h"

int main(int argc, char** argv) {
  libusb_init_context(NULL, NULL, 0);
  hax(argv[1], argv[2]);
  libusb_exit(NULL);
  return 0;
}
