# Cryptography for Payment Professionals

The repository contains code examples for the "Cryptography for Payment Professionals" book. The code is provided without warranty, and any use of the code is at your own risk. 

That being said, any comments or bug reports are very welcome.

Please note that to use the C code in this repository, you will need OpenSSL 1.1 and CMake.

## Getting Started

To get started, you will need to have OpenSSL 1.1 and CMake installed on your system. Once you have those installed, follow these steps:

1. Clone the repository to your local machine using the following command:

```
git clone https://github.com/ilya-dubinsky/cfpp.git
```

## Building C examples
To build C examples, use the following steps:

1. Set the `OPENSSL_ROOT_DIR` to the folder under which the OpenSSL 1.1 library is installed. On a Unix or MacOs machine, you can use:

```
export OPENSSL_ROOT_DIR=<OpenSSL installation folder>
```

2. Enter `cfpp/c/build` folder:
```
cd cfpp/c/build
```
3. Run cmake:
```
cmake .
```
4. Once done, run `make`
```
make
```
The test examples will be found under the `cfpp/bin` folder. 

