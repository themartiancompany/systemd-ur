# Maintainer: Dave Reisner <dreisner@archlinux.org>

pkgbase=systemd
pkgname=('systemd' 'libsystemd')
pkgver=43
pkgrel=4
arch=('i686' 'x86_64')
url="http://www.freedesktop.org/wiki/Software/systemd"
license=('GPL2')
makedepends=('acl' 'cryptsetup' 'dbus-core' 'docbook-xsl' 'gperf' 'intltool'
             'kmod' 'libcap' 'libxslt' 'linux-api-headers' 'pam' 'udev' 'xz')
options=('!libtool')
source=("http://www.freedesktop.org/software/$pkgname/$pkgname-$pkgver.tar.xz"
        "os-release" "cpp-compat.patch")
md5sums=('446cc6db7625617af67e2d8e5f503a49'
         '752636def0db3c03f121f8b4f44a63cd'
         '414968aa314ced0b0ab4b2207e46aa69')

build() {
  cd "$pkgname-$pkgver"
  
  # Fix C++ compile error when including sd-login.h
  # http://comments.gmane.org/gmane.comp.sysutils.systemd.devel/4514
  patch -p1 -i ../cpp-compat.patch

  ./configure --sysconfdir=/etc \
              --libexecdir=/usr/lib \
              --libdir=/usr/lib \
              --with-pamlibdir=/lib/security \
              --localstatedir=/var \
              --with-rootprefix= \
              --with-distro=arch

  make
}

package_systemd() {
  pkgdesc="systemd and service manager"
  depends=('acl' 'dbus' 'dbus-core' 'libsystemd' 'kbd' 'kmod' 'libcap' 'pam' 'util-linux' 'udev' 'xz')
  optdepends=('cryptsetup: required for encrypted block devices'
              'dbus-python: systemd-analyze'
              'initscripts: legacy support for hostname and vconsole setup'
              'initscripts-systemd: native boot and initialization scripts'
              'python2-cairo: systemd-analyze'
              'systemd-arch-units: collection of native unit files for Arch daemon/init scripts'
              'systemd-sysvcompat: symlink package to provide sysvinit binaries')
  backup=(etc/dbus-1/system.d/org.freedesktop.systemd1.conf
          etc/dbus-1/system.d/org.freedesktop.hostname1.conf
          etc/dbus-1/system.d/org.freedesktop.login1.conf
          etc/dbus-1/system.d/org.freedesktop.locale1.conf
          etc/dbus-1/system.d/org.freedesktop.timedate1.conf
          etc/systemd/system.conf
          etc/systemd/user.conf
          etc/systemd/systemd-logind.conf
          etc/systemd/systemd-journald.conf)
  install="$pkgname.install"

  cd "$pkgname-$pkgver"

  make DESTDIR="$pkgdir" install

  install -Dm644 "$srcdir/os-release" "$pkgdir/etc/os-release"

  printf "d /run/console 755 root root\n" >"$pkgdir/usr/lib/tmpfiles.d/console.conf"
  chmod 644 "$pkgdir/usr/lib/tmpfiles.d/console.conf"

  # symlink to /bin/systemd for compat and sanity
  ln -s ../lib/systemd/systemd "$pkgdir/bin/systemd"

  # use python2 for systemd-analyze
  sed -i '1s/python$/python2/' "$pkgdir/usr/bin/systemd-analyze"

  # didn't build this...
  rm -f "$pkgdir/usr/share/man/man1/systemadm.1"

  # fix .so links in manpage stubs
  find "$pkgdir/usr/share/man" -type f -name '*.[[:digit:]]' \
      -exec sed -i '1s|^\.so \(.*\)\.\([[:digit:]]\+\)|.so man\2/\1.\2|' {} +

  # rename man pages to avoid conflicts with sysvinit and initscripts
  manpages=(man8/{telinit,halt,reboot,poweroff,runlevel,shutdown}.8
            man5/{hostname,{vconsole,locale}.conf}.5)
  cd "$pkgdir/usr/share/man"
  for manpage in "${manpages[@]}"; do
    IFS='/' read section page <<< "$manpage"
    mv "$manpage" "$section/systemd.$page"
  done

  ### split off libsystemd (libs, includes, pkgconfig, man3)
  install -dm755 "$srcdir"/libsystemd/usr/{include,lib/pkgconfig}

  cd "$srcdir"/libsystemd
  mv "$pkgdir/usr/lib"/libsystemd-*.so* usr/lib
  mv "$pkgdir/usr/include/systemd" usr/include
  mv "$pkgdir/usr/lib/pkgconfig"/libsystemd-*.pc usr/lib/pkgconfig
}

package_libsystemd() {
  pkgdesc="systemd client libraries"
  depends=('libcap' 'xz')

  mv "$srcdir/libsystemd"/* "$pkgdir"
}

# vim: ft=sh syn=sh et
