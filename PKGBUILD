# SPDX-License-Identifier: AGPL-3.0
#
# Maintainer: Christian Hesse <mail@eworm.de>
# Maintainer: Pellegrino Prevete <pellegrinoprevete@gmail.com>
# Maintainer: Truocolo <truocolo@aol.com>

_os="$( \
  uname \
    -o)"
_bootloader="true"
_git="true"
_bpf="true"
_docs="true"
[[ "${_os}" == 'Android' ]] && \
  _bootloader="false" && \
  _git="false" && \
   # says incompatible arch when building
   # with glibc on android
  _bpf="false" && \
  _docs="false"
_pkg="systemd"
pkgbase="${_pkg}"
pkgname=(
  "${_pkg}"
  "${_pkg}-libs"
  "${_pkg}-resolvconf"
  "${_pkg}-sysvcompat"
  "${_pkg}-ukify"
)
_tag='e88ad03366b8aa059bb72b39a270128ba62b428' # git rev-parse v${_tag_name}
_stable_tag="253.16"
_tag_name=255.2
pkgver="${_tag_name/-/}"
pkgrel=2
arch=(
  'x86_64'
  'arm'
  'armv7h'
  'aarch64'
)
_http="https://www.github.com"
url="${_http}/${_pkg}/${_pkg}"
makedepends=(
  'acl'
  'audit'
  'bash-completion'
  'clang'
  'cryptsetup'
  'curl'
  'docbook-xsl'
  'gnutls'
  'gperf'
  'kexec-tools'
  'kmod'
  'intltool'
  'iptables'
  'lib32-gcc-libs'
  'libcap'
  'libelf'
  'libfido2'
  'libidn2'
  'libgcrypt'
  'libmicrohttpd'
  'libpwquality'
  'libseccomp'
  'libxcrypt'
  'libxkbcommon'
  'libxslt'
  'linux-api-headers'
  'llvm'
  'lz4'
  'meson'
  'pam'
  'p11-kit'
  'pcre2'
  'python-jinja'
  'python-lxml'
  'python-pyelftools'
  'quota-tools'
  'qrencode'
  'rsync'
  'shadow'
  "${_pkg}"
  'tpm2-tss'
  'util-linux'
  'xz'
)
[[ "${_bpf}" == true ]] && \
  makedepends+=(
    'bpf'
    'libbpf'
  )
checkdepends=(
  'python-pefile'
)
options=(
  'strip'
)
validpgpkeys=(
  # Lennart Poettering <lennart@poettering.net>
  '63CDA1E5D3FC22B998D20DD6327F26951A015CC4'
  # Luca Boccassi <luca.boccassi@gmail.com>
  'A9EA9081724FFAE0484C35A1A81CEA22BC8C7E2E'
  '9A774DB5DB996C154EBBFBFDA0099A18E29326E1'  # Yu Watanabe <watanabe.yu+github@gmail.com>
  '9A774DB5DB996C154EBBFBFDA0099A18E29326E1'  # Yu Watanabe <watanabe.yu+github@gmail.com>
  '5C251B5FC54EB2F80F407AAAC54CA336CFEB557E') # Zbigniew Jędrzejewski-Szmek <zbyszek@in.waw.pl>
source=()
sha512sums=()
[[ "${_git}" == false ]] && \
  source+=(
    # Github
    "${_pkg}-stable-${_stable_tag}.tar.gz::${url}-stable/archive/refs/tags/v${_stable_tag}.tar.gz"
    "${_pkg}-${_tag_name}.tar.gz::${url}/archive/refs/tags/v${_tag_name%.*}.tar.gz"
    # Gitlab
    # "${url}/-/archive/${pkgver}/${_pkg}-${pkgver}.tar.gz"
  ) && \
  sha512sums+=(
    'd6a8ec0d362354d3dac05cfd901761d5d32c3d467678683105e5f09d1aaf25f4c5b7c806f1288f3c3aa599817d1a52d54ab397c5e69affb0f72a06b683c16e21'
    '51728de604c2169d8643718ac72acb8f70f613cfcca9e9abb7dac519f291fa26a16d48f24cae6897356319096cfe8f4d9377743e7870127374f98d432e0c557c'
  )
[[ "${_git}" == true ]] && \
  makedepends+=(
    git
  )
  source+=(
    "git+${url}-stable#tag=${_tag}?signed"
    "git+${url}#tag=v${_tag_name%.*}?signed"
  ) && \
  sha512sums+=(
    'SKIP'
    'SKIP'
  )
source+=(
  '0001-Use-Arch-Linux-device-access-groups.patch'
  # mkinitcpio files
  'initcpio-hook-udev'
  "initcpio-install-${_pkg}"
  'initcpio-install-udev'
  # bootloader files
  'arch.conf'
  'loader.conf'
  'splash-arch.bmp'
  # pam configuration
  "${_pkg}-user.pam"
  # pacman / libalpm hooks
  "${_pkg}-hook"
  "20-${_pkg}-sysusers.hook"
  "30-${_pkg}-binfmt.hook"
  "30-${_pkg}-catalog.hook"
  "30-${_pkg}-daemon-reload-system.hook"
  "30-${_pkg}-daemon-reload-user.hook"
  "30-${_pkg}-hwdb.hook"
  "30-${_pkg}-sysctl.hook"
  "30-${_pkg}-tmpfiles.hook"
  "30-${_pkg}-udev-reload.hook"
  "30-${_pkg}-update.hook"
)
sha512sums+=(
  '3ccf783c28f7a1c857120abac4002ca91ae1f92205dcd5a84aff515d57e706a3f9240d75a0a67cff5085716885e06e62597baa86897f298662ec36a940cf410e'
  '4a6cd0cf6764863985dc5ad774d7c93b574645a05b3295f989342951d43c71696d069641592e37eeadb6d6f0531576de96b6392224452f15cd9f056fae038f8e'
  'ada692514d758fa11e2be6b4c5e1dc2d9d47548f24ada35afdce1dcac918e72ae2251c892773e6cf41fa431c3613a1608668e999eb86a565870fecb55c47b4ba'
  'a8c7e4a2cc9c9987e3c957a1fc3afe8281f2281fffd2e890913dcf00cf704024fb80d86cb75f9314b99b0e03bac275b22de93307bfc226d8be9435497e95b7e6'
  '61032d29241b74a0f28446f8cf1be0e8ec46d0847a61dadb2a4f096e8686d5f57fe5c72bcf386003f6520bc4b5856c32d63bf3efe7eb0bc0deefc9f68159e648'
  'c416e2121df83067376bcaacb58c05b01990f4614ad9de657d74b6da3efa441af251d13bf21e3f0f71ddcb4c9ea658b81da3d915667dc5c309c87ec32a1cb5a5'
  '5a1d78b5170da5abe3d18fdf9f2c3a4d78f15ba7d1ee9ec2708c4c9c2e28973469bc19386f70b3cf32ffafbe4fcc4303e5ebbd6d5187a1df3314ae0965b25e75'
  'b90c99d768dc2a4f020ba854edf45ccf1b86a09d2f66e475de21fe589ff7e32c33ef4aa0876d7f1864491488fd7edb2682fc0d68e83a6d4890a0778dc2d6fe19'
  '3cb8f88c1bffc753d0c540be5d25a0fdb9224478cca64743b5663340f2f26b197775286e6e680228db54c614dcd11da1135e625674a622127681662bec4fa886'
  '299dcc7094ce53474521356647bdd2fb069731c08d14a872a425412fcd72da840727a23664b12d95465bf313e8e8297da31259508d1c62cc2dcea596160e21c5'
  '0d6bc3d928cfafe4e4e0bc04dbb95c5d2b078573e4f9e0576e7f53a8fab08a7077202f575d74a3960248c4904b5f7f0661bf17dbe163c524ab51dd30e3cb80f7'
  '2b50b25e8680878f7974fa9d519df7e141ca11c4bfe84a92a5d01bb193f034b1726ea05b3c0030bad1fbda8dbb78bf1dc7b73859053581b55ba813c39b27d9dc'
  'a436d3f5126c6c0d6b58c6865e7bd38dbfbfb7babe017eeecb5e9d162c21902cbf4e0a68cf3ac2f99815106f9fa003b075bd2b4eb5d16333fa913df6e2f3e32a'
  '190112e38d5a5c0ca91b89cd58f95595262a551530a16546e1d84700fc9644aa2ca677953ffff655261e8a7bff6e6af4e431424df5f13c00bc90b77c421bc32d'
  'a1661ab946c6cd7d3c6251a2a9fd68afe231db58ce33c92c42594aedb5629be8f299ba08a34713327b373a3badd1554a150343d8d3e5dfb102999c281bd49154'
  '9426829605bbb9e65002437e02ed54e35c20fdf94706770a3dc1049da634147906d6b98bf7f5e7516c84068396a12c6feaf72f92b51bdf19715e0f64620319de'
  'da7a97d5d3701c70dd5388b0440da39006ee4991ce174777931fea2aa8c90846a622b2b911f02ae4d5fffb92680d9a7e211c308f0f99c04896278e2ee0d9a4dc'
  'a50d202a9c2e91a4450b45c227b295e1840cc99a5e545715d69c8af789ea3dd95a03a30f050d52855cabdc9183d4688c1b534eaa755ebe93616f9d192a855ee3'
  '825b9dd0167c072ba62cabe0677e7cd20f2b4b850328022540f122689d8b25315005fa98ce867cf6e7460b2b26df16b88bb3b5c9ebf721746dce4e2271af7b97'
)
_backports=(
)
_reverts=(
)

prepare() {
  local \
    _c \
    _l
  cd \
    "${_pkg}-stable-${_stable_tag}"
  # add upstream repository for cherry-picking
  git \
    remote \
      add \
        -f \
        upstream \
        "../${_pkg}"
  for _c \
    in "${_backports[@]}"; do
    if \
      [[ "${_c}" == *..* ]]; then 
      _l='--reverse';
    else 
      _l='--max-count=1'; 
    fi
    git \
      log \
        --oneline \
        "${_l}" \
        "${_c}"
    git \
      cherry-pick \
        --mainline \
          1 \
        --no-commit \
        "${_c}"
  done
  for _c \
    in "${_reverts[@]}"; do
    if [[ "${_c}" == *..* ]]; then 
      _l='--reverse';
    else 
      _l='--max-count=1';
    fi
    git \
      log \
        --oneline \
        "${_l}" \
        "${_c}"
    git \
      revert \
        --mainline \
          1 \
        --no-commit \
        "${_c}"
  done
  # Replace cdrom/dialout/tape
  # groups with optical/uucp/storage
  patch \
    -Np1 \
    -i \
    ../0001-Use-Arch-Linux-device-access-groups.patch
}

build() {
  local \
    _meson_options=() \
    _timeservers=() \
    _nameservers=()
  _timeservers=(
    {0..3}.arch.pool.ntp.org
  )
  _nameservers=(
    # We use these public name services, ordered by their privacy policy (hopefully):
    #  * Cloudflare (https://1.1.1.1/)
    #  * Quad9 (https://www.quad9.net/)
    #  * Google (https://developers.google.com/speed/public-dns/)
    '1.1.1.1#cloudflare-dns.com'
    '9.9.9.9#dns.quad9.net'
    '8.8.8.8#dns.google'
    '2606:4700:4700::1111#cloudflare-dns.com'
    '2620:fe::9#dns.quad9.net'
    '2001:4860:4860::8888#dns.google'
  )
  _meson_options=(
    # internal version comparison is incompatible with pacman:
    #   249~rc1 < 249 < 249.1 < 249rc
    -Dversion-tag="${_tag_name/-/\~}-${pkgrel}-arch"
    -Dshared-lib-tag="${pkgver}-${pkgrel}"
    -Dmode=release

    -Dapparmor=false
    -Dbootloader="${_bootloader}"
    -Dxenctrl=false
    -Dbpf-framework="${_bpf}"
    -Dima=false
    -Dlibidn2=true
    -Dlz4=true
    -Dman=true
    -Dnscd=false
    -Dselinux=false

    # We disable DNSSEC by default, it still causes trouble:
    # https://github.com/systemd/systemd/issues/10579

    -Ddbuspolicydir=/usr/share/dbus-1/system.d
    -Ddefault-dnssec=no
    -Ddefault-hierarchy=unified
    -Ddefault-kill-user-processes=false
    -Ddefault-locale='C.UTF-8'
    -Dlocalegen-path=/usr/bin/locale-gen
    -Ddns-over-tls=openssl
    -Dfallback-hostname='archlinux'
    -Dnologin-path=/usr/bin/nologin
    -Dntp-servers="${_timeservers[*]}"
    -Ddns-servers="${_nameservers[*]}"
    -Drpmmacrosdir=no
    -Dsysvinit-path=
    -Dsysvrcnd-path=

    -Dsbat-distro='arch'
    -Dsbat-distro-summary='Arch Linux'
    -Dsbat-distro-pkgname="${pkgname}"
    -Dsbat-distro-version="${pkgver}"
    -Dsbat-distro-url="https://archlinux.org/packages/core/${CARCH}/${pkgname}/"
  )
  # this uses malloc_usable_size,
  # which is incompatible with fortification level 3
  export \
    CFLAGS="${CFLAGS/_FORTIFY_SOURCE=3/_FORTIFY_SOURCE=2}" \
    CXXFLAGS="${CXXFLAGS/_FORTIFY_SOURCE=3/_FORTIFY_SOURCE=2}"
  arch-meson \
    "${_pkg}-stable-${_stable_tag}" \
    build \
      "${_meson_options[@]}"
  meson \
    compile \
    -C \
      build
}

check() {
  meson \
    test \
      -C \
        build
}

package_systemd() {
  pkgdesc='system and service manager'
  license=(
    'GPL2'
    'LGPL2.1'
  )
  depends=(
    'acl'
    'audit'
    'bash'
    'cryptsetup'
    'dbus'
    'dbus-units'
    'kbd'
    'kmod'
    'hwdata'
    'libaudit.so'
    'libcap'
    'libcap.so'
    'libacl.so'
    'libblkid.so'
    'libcrypt.so'
    'libcrypto.so'
    'libcryptsetup.so'
    'libelf'
    'libgcrypt'
    'libkmod.so'
    'libidn2'
    'libmount.so'
    'libseccomp'
    'libseccomp.so'
    'libssl.so'
    'libxcrypt'
    'lz4'
    'openssl'
    'pam'
    'pcre2'
    "${_pkg}-libs"
    'util-linux'
    'xz'
  )
  provides=(
    'nss-myhostname'
    "${_pkg}-tools=$pkgver"
    "udev=$pkgver"
  )
  replaces=(
    'nss-myhostname'
    "${_pkg}-tools"
    'udev'
  )
  conflicts=(
    'nss-myhostname'
    "${_pkg}-tools"
    'udev'
  )
  optdepends=(
    "curl: ${_pjg}-journal-upload, machinectl pull-tar and pull-raw"
    'gnutls: systemd-journal-gatewayd and systemd-journal-remote'
    'iptables: firewall features'
    'libbpf: support BPF programs'
    "libmicrohttpd: ${_pkg}-journal-gatewayd and ${_pkg}-journal-remote"
    'libpwquality: check password quality'
    'libfido2: unlocking LUKS2 volumes with FIDO2 token'
    'libp11-kit: support PKCS#11'
    'polkit: allow administration as unprivileged user'
    'quota-tools: kernel-level quota management'
    'qrencode: show QR codes'
    "${_pkg}-sysvcompat: symlink package to provide sysvinit binaries"
    "${_pkg}-ukify: combine kernel and initrd into a signed Unified Kernel Image"
    'tpm2-tss: unlocking LUKS2 volumes with TPM2'
  )
  backup=(
    "etc/pam.d/${_pkg}-user"
    "etc/${_pkg}/coredump.conf"
    "etc/${_pkg}/homed.conf"
    "etc/${_pkg}/journald.conf"
    "etc/${_pkg}/journal-remote.conf"
    "etc/${_pkg}/journal-upload.conf"
    "etc/${_pkg}/logind.conf"
    "etc/${_pkg}/networkd.conf"
    "etc/${_pkg}/oomd.conf"
    "etc/${_pkg}/pstore.conf"
    "etc/${_pkg}/resolved.conf"
    "etc/${_pkg}/sleep.conf"
    "etc/${_pkg}/system.conf"
    "etc/${_pkg}/timesyncd.conf"
    "etc/${_pkg}/user.conf"
    "etc/udev/iocost.conf"
    "etc/udev/udev.conf"
  )
  install="${_pkg}.install"
  meson \
    install \
      -C \
        build \
      --destdir \
        "${pkgdir}"
  # we'll create this on installation
  rmdir \
    "${pkgdir}/var/log/journal/remote"
  # runtime libraries shipped with systemd-libs
  install \
    -d \
    -m0755 \
    "${_pkg}-libs/lib"
  mv \
    "${pkgdir}/usr/lib/lib"{nss,"${_pkg}",udev}*.so* \
    "${_pkg}-libs/lib"
  mv \
    "${pkgdir}/usr/lib/pkgconfig" \
    "${_pkg}-libs/lib/pkgconfig"
  mv \
    "${pkgdir}/usr/include" \
    "${_pkg}-libs/include"
  mv \
    "${pkgdir}/usr/share/man/man3" \
    "${_pkg}-libs/man3"

  # ukify shipped in separate package
  install \
    -d \
    -m0755 \
    "${_pkg}-ukify/"{bin,"${_pkg}",man1,install.d}
  mv \
    "${pkgdir}/usr/bin/ukify" \
    "${_pkg}-ukify/bin"
  mv \
    "${pkgdir}/usr/lib/${_pkg}/ukify" \
    "${_pkg}-ukify/${_pkg}"
  mv \
    "${pkgdir}/usr/share/man/man1/ukify.1" \
    "${_pkg}-ukify/man1"
  # we move the ukify hook itself,
  # but keep 90-uki-copy.install in place,
  # because there are other ways to generate
  # UKIs w/o ukify, e.g. w/ mkinitcpio
  mv \
    "${pkgdir}/usr/lib/kernel/install.d/60-ukify.install" \
    "${_pkg}-ukify/install.d"

  # manpages shipped with systemd-sysvcompat
  rm \
    "${pkgdir}/usr/share/man/man8/"{halt,poweroff,reboot,shutdown}.8

  # executable (symlinks) shipped with systemd-sysvcompat
  rm \
    "${pkgdir}/usr/bin/"{halt,init,poweroff,reboot,shutdown}

  # files shipped with systemd-resolvconf
  rm \
    "${pkgdir}/usr/"{bin/resolvconf,share/man/man1/resolvconf.1}

  # avoid a potential conflict with [core]/filesystem
  rm \
    "${pkgdir}/usr/share/factory/etc/"{issue,nsswitch.conf}
  sed \
    -i \
    -e \
      '/^C \/etc\/nsswitch\.conf/d' \
    -e \
      '/^C \/etc\/issue/d' \
    "${pkgdir}/usr/lib/tmpfiles.d/etc.conf"

  # ship default policy to
  # leave services disabled
  echo \
    'disable *' > \
    "${pkgdir}/usr/lib/${_pkg}/system-preset/99-default.preset"

  # add mkinitcpio hooks
  install \
    -D \
    -m0644 \
    "initcpio-install-${_pkg}" \
    "${pkgdir}/usr/lib/initcpio/install/${_pkg}"
  install \
    -D \
    -m0644 \
    initcpio-install-udev \
    "$pkgdir"/usr/lib/initcpio/install/udev
  install \
    -D \
    -m0644 \
    initcpio-hook-udev \
    "$pkgdir"/usr/lib/initcpio/hooks/udev
  # The group 'systemd-journal' is allocated
  # dynamically and may have varying
  # gid on different systems.
  # Let's install with gid 0 (root), systemd-tmpfiles
  # will fix the permissions for us.
  # (see /usr/lib/tmpfiles.d/systemd.conf)
  install \
    -d \
    -o \
      root \
    -g \
      root \
    -m \
      2755 \
    "${pkgdir}/var/log/journal"

  # match directory owner/group
  # and mode from [extra]/polkit
  install \
    -d \
    -o root \
    -g 102 \
    -m 0750 \
    "$pkgdir"/usr/share/polkit-1/rules.d
  # add example bootctl configuration
  install \
    -D \
    -m0644 \
    arch.conf \
    "${pkgdir}/usr/share/${_pkg}/bootctl/arch.conf"
  install \
    -D \
    -m0644 \
    loader.conf \
    "${pkgdir}/usr/share/${_pkg}/bootctl/loader.conf"
  install \
    -D \
    -m0644 \
    splash-arch.bmp \
    "${pkgdir}/usr/share/${_pkg}/bootctl/splash-arch.bmp"
  # pacman hooks
  install \
    -D \
    -m0755 \
    "${_pkg}-hook" \
    "${pkgdir}/usr/share/libalpm/scripts/${_pkg}-hook"
  install \
    -D \
    -m0644 \
    -t \
    "${pkgdir}"/usr/share/libalpm/hooks \
    *.hook
  # overwrite the systemd-user
  # PAM configuration with our own
  install \
    -D \
    -m0644 \
    "${_pkg}-user.pam" \
    "${pkgdir}/etc/pam.d/${_pkg}-user"
}

package_systemd-libs() {
  pkgdesc='systemd client libraries'
  depends=(
    'glibc'
    'gcc-libs'
    'libcap'
    'libgcrypt'
    'lz4'
    'xz'
    'zstd'
  )
  license=(
    'LGPL2.1'
  )
  provides=(
    "lib${_pkg}=${pkgver}"
    "lib${_pkg}.so=${pkgver}"
    "libudev.so"
  )
  conflicts=(
    "lib${_pkg}"
  )
  replaces=(
    "lib${_pkg}"
  )
  install \
    -d \
    -m0755 \
    "$pkgdir"/usr/share/man
  mv \
    "${_pkg}-libs/lib" \
    "$pkgdir"/usr/lib
  mv \
    "${_pkg}-libs/include" \
    "${pkgdir}"/usr/include
  mv \
    "${_pkg}-libs/man3" \
    "$pkgdir"/usr/share/man/man3
}

package_systemd-resolvconf() {
  pkgdesc="${_pkg} resolvconf replacement (for use with ${_pkg}-resolved)"
  license=(
    'LGPL2.1'
  )
  depends=(
    "${_pkg}"
  )
  provides=(
    'openresolv'
    'resolvconf'
  )
  conflicts=(
    'resolvconf'
  )
  install \
    -d \
    -m0755 \
    "$pkgdir"/usr/bin
  ln \
    -s \
    resolvectl \
    "$pkgdir"/usr/bin/resolvconf
  install \
    -d \
    -m0755 \
    "$pkgdir"/usr/share/man/man1
  ln \
    -s \
    resolvectl.1.gz \
    "$pkgdir"/usr/share/man/man1/resolvconf.1.gz
}

package_systemd-sysvcompat() {
  pkgdesc="sysvinit compat for ${_pkg}"
  license=(
    'GPL2'
  )
  conflicts=(
    'sysvinit'
  )
  depends=(
    "${_pkg}"
  )
  install \
    -D \
    -m0644 \
    -t \
    "$pkgdir"/usr/share/man/man8 \
    build/man/{halt,poweroff,reboot,shutdown}.8
  install \
    -d \
    -m0755 \
    "$pkgdir"/usr/bin
  ln \
    -s \
    "../lib/${_pkg}/${_pkg}" \
    "$pkgdir"/usr/bin/init
  for tool \
    in halt \
       poweroff \
       reboot \
       shutdown; do
    ln \
      -s \
      systemctl \
      "$pkgdir"/usr/bin/$tool
  done
}

package_systemd-ukify() {
  pkgdesc='Combine kernel and initrd into a signed Unified Kernel Image'
  license=(
    'GPL2'
  )
  provides=(
    'ukify'
  )
  depends=(
    'binutils'
    'python-cryptography'
    'python-pefile'
    "${_pkg}"
  )
  optdepends=(
    'python-pillow: Show the size of splash image'
    'sbsigntools: Sign the embedded kernel'
  )
  install \
    -d \
    -m0755 \
    "$pkgdir"/usr/{lib/kernel,share/man}
  mv \
    "${_pkg}-ukify/bin" \
    "$pkgdir"/usr/bin
  mv \
    "${_pkg}-ukify/${_pkg}" \
    "${pkgdir}/usr/lib/${_pkg}"
  mv \
    "${_pkg}-ukify/man1" \
    "$pkgdir"/usr/share/man/man1
  mv \
    "${_pkg}-ukify/install.d" \
    "$pkgdir"/usr/lib/kernel/install.d
}

# vim:ft=sh syn=sh et sw=2:
