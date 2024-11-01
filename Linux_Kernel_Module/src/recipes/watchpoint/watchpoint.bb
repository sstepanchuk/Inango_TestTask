DESCRIPTION = "Watchpoint Kernel Module"

LICENSE = "MIT"
SRC_URI = "file://watchpoint.c \
            file://Makefile \
            file://LICENSE"
LIC_FILES_CHKSUM = "file://LICENSE;md5=3914388ed65427d749c0c5886d2d12cf"

inherit module

S = "${WORKDIR}"

EXTRA_OEMAKE = "KERNEL_SRC=${STAGING_KERNEL_DIR}"

do_install() {
  install -d ${D}${base_libdir}/modules/${KERNEL_VERSION}/extra
  install -m 0644 ${B}/watchpoint.ko ${D}${base_libdir}/modules/${KERNEL_VERSION}/extra
}

FILES_${PN} = "${base_libdir}/modules/${KERNEL_VERSION}/extra/watchpoint.ko"

DEPENDS += "virtual/kernel"