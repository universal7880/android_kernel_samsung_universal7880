
#!/bin/bash

export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-android-4.9/bin/aarch64-linux-android-
export ANDROID_MAJOR_VERSION=p

make exynos7880-a57y17lte_eur_defconfig
make -j64

