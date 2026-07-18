Name:           tardigrade
Version:        %{version}
Release:        1%{?dist}
Summary:        Tardigrade edge gateway — TLS termination, reverse proxying, and realtime transport
License:        Apache-2.0
URL:            https://github.com/Bare-Systems/Tardigrade
Source0:        tardi
Source1:        tardigrade.service
Source2:        tardigrade.env
Source3:        LICENSE
Source4:        tardigrade.conf

BuildArch:      %{build_arch}
Requires:       openssl-libs

%description
High-performance Zig edge gateway and HTTP server for TLS termination,
reverse proxying, protocol bridging, and realtime event transport.

%install
install -D -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/tardi
ln -s tardi %{buildroot}%{_bindir}/tardigrade
install -D -m 0644 %{SOURCE1} %{buildroot}%{_unitdir}/tardigrade.service
install -D -m 0640 %{SOURCE2} %{buildroot}%{_sysconfdir}/tardigrade/tardigrade.env
install -D -m 0644 %{SOURCE3} %{buildroot}%{_datadir}/licenses/%{name}/LICENSE
install -D -m 0644 %{SOURCE4} %{buildroot}%{_sysconfdir}/tardigrade/tardigrade.conf
install -d %{buildroot}%{_localstatedir}/log/tardigrade

%pre
getent passwd tardigrade >/dev/null 2>&1 || \
    useradd --system --no-create-home --shell /sbin/nologin tardigrade
exit 0

%post
%systemd_post tardigrade.service
chown root:tardigrade %{_sysconfdir}/tardigrade/tardigrade.env
install -d -o tardigrade -g tardigrade %{_localstatedir}/lib/tardigrade
exit 0

%preun
%systemd_preun tardigrade.service
exit 0

%postun
%systemd_postun_with_restart tardigrade.service
exit 0

%files
%{_datadir}/licenses/%{name}/LICENSE
%{_bindir}/tardi
%{_bindir}/tardigrade
%{_unitdir}/tardigrade.service
%config(noreplace) %{_sysconfdir}/tardigrade/tardigrade.env
%config(noreplace) %{_sysconfdir}/tardigrade/tardigrade.conf
%dir %{_localstatedir}/log/tardigrade

%changelog
* Thu Apr 17 2026 Bare Systems <security@baresystems.dev> - %{version}-1
- Initial RPM packaging
