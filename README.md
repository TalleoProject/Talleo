
### How To Compile

#### Ubuntu 18.04 or newer

##### Prerequisites

###### Ubuntu 18.04
- You will need the following packages: boost (1.55 or higher), cmake, git, gcc (6.x), g++ (6.x), make, python and openssl. Most of these should already be installed on your system.
- `sudo apt-get -y install build-essential python-dev gcc g++ git cmake libboost-all-dev libgflags-dev libsnappy-dev zlib1g-dev libbz2-dev liblz4-dev libzstd-dev libssl-dev`

###### Ubuntu 20.04

- You will need the following packages: boost (1.67), cmake, git, gcc (7.x), g++ (7.x), make, and python3.
- `sudo apt-get update`
- `sudo apt-get -y install build-essential python3-dev gcc-7 g++-7 git cmake libboost1.67-all-dev libgflags-dev libsnappy-dev zlib1g-dev libbz2-dev liblz4-dev libzstd-dev  libssl-dev`
- `sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 70`
- `sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-7 70`

##### Building

- `git clone https://github.com/TalleoProject/Talleo.git`
- `cd Talleo`
- `mkdir -p build/release; cd build/release`
- `cmake -D STATIC=ON -D ARCH="default" -D CMAKE_BUILD_TYPE=Release ../..`
- `cmake --build .`

##### Known issues
- gcc-7 under Ubuntu 18.04 on some machines can cause memory management errors due to signed integer wraparound while compiling and running the executables
  1. Install `gcc-6` and `g++-6` using apt-get:
    - `sudo apt-get -y install gcc-6 g++-6`
  2. Switch default compiler using update-alternatives:
    - `sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-6 60 --slave /usr/bin/g++ g++ /usr/bin/g++-6`
    - `sudo update-alternatives --set gcc /usr/bin/gcc-6`
  3. Cleanup build tree by removing all files in directory `build/release` and its subdirectories, reconfigure and recompile
- Ubuntu packages for rocksdb can be incompatible with Talleo as sometimes those are built without RTTI, RTTI is required by Talleo, uninstalling `librocksdb-dev` will make the build system use rocksdb from source tree

#### Apple

##### Prerequisites

- Install [cmake](https://cmake.org/). See [here](https://stackoverflow.com/questions/23849962/cmake-installer-for-mac-fails-to-create-usr-bin-symlinks) if you are unable call `cmake` from the terminal after installing.
- Install the [boost](http://www.boost.org/) libraries. Either compile boost manually or run `brew install boost`.
- Install XCode and Developer Tools.
- Install OpenSSL

##### Building

- `git clone https://github.com/TalleoProject/Talleo.git`
- `cd Talleo`
- `mkdir -p build/release; cd build/release`
- `cmake ../..` or `cmake -DBOOST_ROOT=<path_to_boost_install> ../..` when building from a specific boost install. If you used brew to install boost, your path is most likely `/usr/local/include/boost.`
- `cmake --build .`

The binaries will be in `./src` after compilation is complete.

Run `./src/Talleod` to connect to the network and let it sync (it may take a while).

#### Windows 10

##### Prerequisites
- Install either
  1. [Visual Studio 2017 Community Edition](https://my.visualstudio.com/Downloads?q=Visual%20Studio%20Community%202017)
  2. [Visual Studio 2017.9 Community Edition](https://my.visualstudio.com/Downloads?q=Visual%20Studio%20Community%202017%20%28version%2015.9%29)
  3. [Visual Studio 2019 Community Edition](https://my.visualstudio.com/Downloads?q=Visual%20Studio%20Community%202019)
  4. [Visual Studio 2022 Community Edition](https://my.visualstudio.com/Downloads?q=Visual%20Studio%20Community%202022)
- Install OpenSSL

NOTES:
1. When installing Visual Studio 2017, it is **required** that you
    1. Install **Desktop development with C++** and the **VC++ v140 toolchain** when selecting features. The option to install the v140 toolchain can be found by expanding the "Desktop development with C++" node on the right. You will need this for the project to build correctly.
    2. Install [Boost 1.64.0](https://sourceforge.net/projects/boost/files/boost-binaries/1.64.0/), ensuring you download the installer for MSVC 14.0.
2. If you have Visual Studio 2017.9 Community, you will need to use [Boost 1.71.0](https://sourceforge.net/projects/boost/files/boost-binaries/1.71.0/) and v141 toolchain
3. If you have Visual Studio 2019 Community, you will need to use [Boost 1.73.0](https://sourceforge.net/projects/boost/files/boost-binaries/1.73.0/) or later, and v142 toolchain
4. If you have Visual Studio 2022 Community, you will need to use either
    1. [Boost 1.77.0](https://sourceforge.net/projects/boost/files/boost-binaries/1.77.0/) and v142 toolchain
    2. [Boost 1.78.0](https://sourceforge.net/projects/boost/files/boost-binaries/1.78.0/) or later, and v143 toolchain
5. Last tested Boost version is 1.84.0, later versions might be incompatible

##### Building

- From the start menu, open 'x64 Native Tools Command Prompt for VS 2017'.
- `cd <your_Talleo_directory>`
- `mkdir build`
- `cd build`
- If necessary, set the PATH variable for cmake: ie. `set PATH="C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin";%PATH%`
- `cmake -DBOOST_ROOT=C:\local\boost_1_64_0 -DBOOST_LIBRARYDIR=C:\local\boost_1_64_0\lib64-msvc-14.0 -G "Visual Studio 14 Win64" <your_Talleo_directory>
- A 'Talleo.sln' file will be created in the `build` directory.
     1. Open it in Visual Studio 2017 and compile the binaries, or
     2. 'cmake --build . --config Release'
- If all went well, it will complete successfully, and you will find all your binaries in the '..\build\src\Release' directory.

#### FreeBSD

##### Prerequisites
- Install git, cmake, Boost, MiniUPnPc and OpenSSL
- `pkg install -y git cmake boost-all miniupnpc openssl`

##### Building
- `git clone https://github.com/TalleoProject/Talleo.git`
- `cd Talleo`
- `mkdir -p build/release; cd build/release`
- `cmake -D STATIC=ON -D ARCH="default" -D CMAKE_BUILD_TYPE=Release ../..`
- `cmake --build .`

#### Thanks
Cryptonote Developers, Bytecoin Developers, Monero Developers, TurtleCoin Developers, Forknote Project, PinkstarcoinV2 Developers, Bittorium Developers, Talleo developers.

#### Donate
Donate to our project and help us achieve more for you!
Our BTC Address:   1D1YBHmFkd4J7bEG6PYfZBLoXtp98hKsfw


