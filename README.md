# Home Management ESP8266 device

This is the software running on the ESP8266 to connect with the `esp8266` module on [home-web](https://github.com/jackyliao123/home-web). It supports remote GPIO control and the use the use of interrupts to notify the server when pin changes are detected.

This uses the ESP8266 FreeRTOS SDK 

### Building

Make sure that `xtensa-lx106-elf-gcc` and required compilers are installed for the system

    git clone --recurse-submodules https://github.com/jackyliao123/home-esp8266
    cd home-esp8266
    source set_env

In `client/main/data`, 2 files should be created: `auth.dat` and `ca.crt`.

`auth.dat` should be a file with 16 bytes, containing an authentication token for this device.
`ca.crt` should be a PEM-encoded CA, used for verifying the TLS1.2 connection.

    cd client
    make flash

`make menuconfig` will run, and the system can be configured as desired.
