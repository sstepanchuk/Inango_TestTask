DESCRIPTION = "Watchpoint Kernel Module"
DESCRIPTION_${PN} = "Watchpoint Kernel Module"
DESCRIPTION_${PN}-src = "Watchpoint Kernel Module Source Package"
DESCRIPTION_${PN}-dev = "Watchpoint Kernel Module Development Package"
DESCRIPTION_${PN}-dbg = "Watchpoint Kernel Module Debug Package"

LICENSE = "MIT"
SRC_URI = "file://watchpoint.c \
            file://watchpoint_test.c \
            file://Makefile \
            file://LICENSE"
LIC_FILES_CHKSUM = "file://LICENSE;md5=3914388ed65427d749c0c5886d2d12cf"

inherit module

S = "${WORKDIR}"

EXTRA_OEMAKE = "KERNEL_SRC=${STAGING_KERNEL_DIR} \
                CFLAGS='-I${STAGING_INCDIR}' \
                LDFLAGS='-L${STAGING_LIBDIR}'"

do_install() {
    # Install the kernel module
    install -d ${D}${base_libdir}/modules/${KERNEL_VERSION}/extra
    install -m 0644 ${B}/watchpoint.ko ${D}${base_libdir}/modules/${KERNEL_VERSION}/extra

     # Install the test program
    install -d ${D}${bindir}
    install -m 0755 ${B}/watchpoint_test ${D}${bindir}
}

FILES_${PN} = "${base_libdir}/modules/${KERNEL_VERSION}/extra/watchpoint.ko"
FILES_${PN}-dbg += "${base_libdir}/debug/${KERNEL_VERSION}/extra/.debug/watchpoint.ko"
FILES_${PN}-test = "${bindir}/watchpoint_test"

PACKAGES = "${PN} ${PN}-src ${PN}-dev ${PN}-dbg ${PN}-test"
DEPENDS += "virtual/kernel glibc"