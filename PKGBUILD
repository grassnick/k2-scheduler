# This is an example PKGBUILD file. Use this as a start to creating your own,
# and remove these comments. For more information, see 'man PKGBUILD'.
# NOTE: Please fill out the license field for your package! If it is unknown,
# then please put 'unknown'.

# Maintainer: Your Name <youremail@domain.com>
pkgname=k2-scheduler-dkms
_pkgname=k2-scheduler
pkgver=0.1
pkgrel=1
epoch=
pkgdesc="The K2 scheduler for linux"
arch=('i686' 'x86_64')
url="https://github.com/TUD-OS/k2-scheduler"
license=('GPL')
groups=()
depends=('dkms')
makedepends=()
checkdepends=()
optdepends=()
provides=()
conflicts=()
replaces=()
backup=()
options=()
install=
changelog=
source=("k2.c"
        "Makefile"
		"dkms.conf"
)
noextract=()
md5sums=("SKIP"
         "SKIP"
		 "SKIP"
)
validpgpkeys=()


package() {
	mkdir -p "${pkgdir}/usr/src/${_pkgname}-${pkgver}/"
	install -Dm644 k2.c Makefile dkms.conf -t "${pkgdir}/usr/src/${_pkgname}-${pkgver}/"
}
