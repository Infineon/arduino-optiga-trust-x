# OPTIGA&trade; Trust X
![TrustXPackage](https://github.com/Infineon/Assets/raw/master/Pictures/OPTIGA-Trust-X.png)

Infineon's [OPTIGA&trade; Trust X](https://www.infineon.com/cms/en/product/security-smart-card-solutions/optiga-embedded-security-solutions/optiga-trust/optiga-trust-x-sls-32aia/) security solution library for Arduino

## Summary
[OPTIGA&trade; Trust X](https://www.infineon.com/dgdl/Infineon-OPTIGA%20TRUST%20X%20SLS%2032AIA-DS-v02_18-EN.pdf) is a security solution based on a secure micrcontroller.
Each device is shipped with a unique elliptic-curve keypair and a corresponding X.509 certificate. OPTIGA&trade; Trust X enables easy integration into existing PKI infrastructure.


## Key Features and Benefits
* High-end security controller
* Turnkey solution
* One-way authentication using ECDSA
* Mutual authentication using DTLS client (IETF standard RFC 6347)
* Secure communication using DTLS
* Compliant with the USB Type-C™ Authentication standard
* I2C interface
* Up to 10 KB user memory
* Cryptographic support: ECC256, AES128, SHA-256, TRNG, DRNG
* PG-USON-10-2 package (3 x 3 mm)
* Standard & extended temperature ranges
* Full system integration support
* Common Criteria Certified EAL6+ (high) hardware
* Cryptographic Tool Box based on ECC NIST P256, P384 and SHA256 (sign, verify, key generation, ECDH, session key derivation)      

## Hardware
The wiring to your arduino board depends on the [evaluation board](https://www.infineon.com/cms/en/product/evaluation-boards/optiga-trust-x-eval-kit/) or the 
Shield2GO (link pending) you are using.

## Installation

### Integration of Library
Please download this repository from GitHub either from the latest [release](https://github.com/Infineon/arduino-optiga-trust-x/releases) of directly [here](https://github.com/Infineon/arduino-optiga-trust-x/archive/V1.0.3.zip):
![Download Library](https://raw.githubusercontent.com/Infineon/assets/master/Pictures/DL_OPTIGA_Trust_X.jpg)


To install the OPTIGA&trade; Trust X library in the Arduino IDE, please go to **Sketch** > **Include Library** > **Add .ZIP Library...** in the Arduino IDE and navigate to the downloaded .ZIP file of this repository. The library will be installed in your Arduino sketch folder in libraries and you can select as well as include this one to your project under **Sketch** > **Include Library** > **OPTIGATrustX**.

![Install Library](https://raw.githubusercontent.com/infineon/assets/master/Pictures/Library_Install_ZIP.png)

## Supported Devices
In general, the library should be compatible with any Arduino board, however it has been tested for the following platforms:
* Sparkfun ESP32 Thing (Espressif Systems, ESP32, Xtensa)
* Adafruit Feather M0 (Atmel, SAMD21, Cortex M0)
* STM32 Nucleo (ST Microelectronics, STM32F0, Cortex M0)
* XMC1100 2Go (Infineon Technologies, XMC1100, Cortex M0)
* XMC4700 Relax Kit (Infineon Technologies, XMC4700, Cortex M4)
* WEMOS D1 mini (Espressif Systems, ESP8266, Xtensa)

## Usage
The library is equiped with eight groups of examples which can be found on the following path: File->Examples>OPTIGATrustX 
The following sections describe all the examples in more detail.

### selfTest
selfTest example demonstrates a trustX.checkChip() method usage, which authenticates the OPTIGA™ Trust X on the host MCU. 
This method implements a simple challenge-response authentication scheme, in which the host side authenticates the OPTIGA™ Trust X security chip.  

### calculateHash 
calculateHash demonstrates example usage of the SHA256 hash, as well as a simple benchamarking for your microcontroller. 
The performance of this benchmark test greatly depends on I2C  bus frame size (it affects mainly big blocks of data transmitted to the OPTIGA™ Trust X chip for hashing), 
which was limited by default down to 32 bytes (in case of 32 bytes the library will perfrom fragmentation). 

Please check settings for your specific platform, if you want to improve the performance of the hashing function. 

### calculateSignVerifySign  
calculateSignVerifySign demonstrates signature generation and signature verification methods of the library. 
This example shows two modes of operation: 
1) Calculate a signature using manufacturer private key, the result value is then verified  against the public key
2) Generate a public-private keypair and store the latter inside one of Object IDs of the OPTIGA™ Trust X, 
then sign the digest giving only the latter  Object ID, the result value is then verified  against the public key.  

For the verification three methods are available: 
1) with a given raw public key
2) with Object ID pointing to the memory slot where the public key is located, 
3) if neither Object ID nor raw public key were specified, the function will use a default Object ID with manufacturer public key certificate. 

### generateKeypair
calculateSignVerifySign demonstrates methods for keypair generation, either with a private key export, or without. 
In the latter case the developer should specify the Object ID of the private key. 

### getCertificate, getUniqueID 
getCertificate and getUniqueID demonstrate examples of retrievieng various properties of the OPTIGA™ Trust X Chip. 
As well as these examples the developer can also call getCurrentLimit/setCurrentLimit in order to get or modify the
current limitation of the chip (varies from 5mA by default to maximum 15mA) 

### getRandom
getRandom demonstrates random number generator capabilities. This example outputs random numbers of various sizes (16, 32, 64, 128, 256)

### testFullAPI
testFullAPI is used to briefly test major API calls to the library. The expected output of this function can be found in Figure below. 
*Certificate output might be different

![testFullAPI expected result](https://github.com/Infineon/Assets/raw/master/Pictures/OPTIGA%20Trust%20X%20testFullAPI.png)

## Available functions
Available API is discribed in Wiki of the repository
	
## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process of submitting pull requests to us.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
