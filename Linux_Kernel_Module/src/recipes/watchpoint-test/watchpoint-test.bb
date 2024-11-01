SUMMARY = "Simple program to monitor allocated memory address"
DESCRIPTION = "This program allocates memory, prints the address, and waits for user input."

SRC_URI = "file://watchpoint_test.c \
            file://LICENSE"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://LICENSE;md5=3914388ed65427d749c0c5886d2d12cf"

DEPENDS = "glibc"

do_install() {
    install -d ${D}${bindir}
    install -m 0755 watchpoint_test ${D}${bindir}/watchpoint_test
}

S = "${WORKDIR}"

do_compile() {
    ${CC} ${CFLAGS} ${LDFLAGS} -o watchpoint_test ${S}/watchpoint_test.c
}