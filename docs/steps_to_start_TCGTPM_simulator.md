
Prerequisites
=============
sudo dnf install cmake

sudo dnf install openssl-devel

sudo dnf group install c-development

Build and Run
=============
1. Clone the repo

    ``git clone https://github.com/TrustedComputingGroup/TPM.git``

2. Create a build directory

    ``cd TPM ; mkdir -p build``

3. Configure the build files

    ``cmake -S . -B ./build/ -G "Unix Makefiles"``

4. Build the project

    ``cmake --build build/``

    You will find the Simulator binary in build/Simulator

5. Run the simulator

    ``./build/Simulator/Simultator``

6. Issue a startup command (crucial step, at the beginning)

    ``TPM2TOOLS_TCTI=mssim:host=localhost,port=2321 tpm2_startup -c``

7. Run a sample tpm2 command

    ``TPM2TOOLS_TCTI=mssim:host=localhost,port=2321 tpm2_getrandom 5 --hex ; echo``

You can also export the TPM2TOOLS_TCTI as an environment variable,
to avoid setting it before every command: ``export TPM2TOOLS_TCTI=mssim:host=localhost,port=2321``

