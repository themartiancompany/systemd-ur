# Maintainer: Dave Reisner <dreisner@archlinux.org>

pkgname=systemd
pkgver=39
pkgrel=2
pkgdesc="Session and Startup manager"
arch=('i686' 'x86_64')
url="http://www.freedesktop.org/wiki/Software/systemd"
license=('GPL2')
depends=('acl' 'dbus-core' 'kbd' 'libcap' 'util-linux>=2.19' 'udev>=172' 'xz')
makedepends=('gperf' 'cryptsetup' 'intltool' 'linux-api-headers')
optdepends=('cryptsetup: required for encrypted block devices'
            'dbus-python: systemd-analyze'
            'initscripts: legacy support for hostname and vconsole setup'
            'initscripts-systemd: native boot and initialization scripts'
            'python2-cairo: systemd-analyze'
            'systemd-arch-units: collection of native unit files for Arch daemon/init scripts')
options=('!libtool')
backup=(etc/dbus-1/system.d/org.freedesktop.systemd1.conf
        etc/dbus-1/system.d/org.freedesktop.hostname1.conf
        etc/dbus-1/system.d/org.freedesktop.login1.conf
        etc/dbus-1/system.d/org.freedesktop.locale1.conf
        etc/dbus-1/system.d/org.freedesktop.timedate1.conf
        etc/systemd/system.conf
        etc/systemd/user.conf
        etc/systemd/systemd-logind.conf)
install=systemd.install
source=("http://www.freedesktop.org/software/$pkgname/$pkgname-$pkgver.tar.xz"
        "os-release"
        "0001-mount-fix-automount-regression.patch")
md5sums=('7179b34f6f6553d2a36551ac1dec5f0d'
         '752636def0db3c03f121f8b4f44a63cd'
         '6e42637c1b1d4589909329dab777631b')

build() {
  cd "$pkgname-$pkgver"

  # Don't unset locale in getty
  # https://bugzilla.redhat.com/show_bug.cgi?id=663900
  sed -i -e '/^Environ.*LANG/s/^/#/' \
         -e '/^ExecStart/s/agetty/& -8/' units/getty@.service.m4

  # fix default dependencies for automounts in /etc/fstab
  patch -Np1 < "$srcdir/0001-mount-fix-automount-regression.patch"

  ./configure --sysconfdir=/etc \
              --libexecdir=/usr/lib \
              --libdir=/usr/lib \
              --localstatedir=/var \
              --with-rootprefix= \
              --with-rootlibdir=/lib

  make

  # fix .so links in manpages
  sed -i 's|\.so halt\.8|.so man8/systemd.halt.8|' man/{halt,poweroff}.8
  sed -i 's|\.so systemd\.1|.so man1/systemd.1|' man/init.1
}

package() {
  cd "$pkgname-$pkgver"

  make DESTDIR="$pkgdir" install

  # needed by systemd-loginctl for enable-linger
  install -dm755 "$pkgdir/var/lib/systemd"

  install -Dm644 "$srcdir/os-release" "$pkgdir/etc/os-release"
  printf "d /run/console 755 root root\n" > "$pkgdir/usr/lib/tmpfiles.d/console.conf"

  # fix systemd-analyze for python2
  sed -i '1s/python$/python2/' "$pkgdir/usr/bin/systemd-analyze"

  # rename man pages to avoid conflicts with sysvinit and initscripts
  cd "$pkgdir/usr/share/man"

  manpages=(man8/{telinit,halt,reboot,poweroff,runlevel,shutdown}.8
            man5/{hostname,{vconsole,locale}.conf}.5)

  for manpage in "${manpages[@]}"; do
    IFS='/' read section page <<< "$manpage"
    mv "$manpage" "$section/systemd.$page"
  done
}

# vim: ft=sh syn=sh et
