%define debug_package %{nil}

Name:nvme-snsd
Version:%{_VERSION}
Release:linux
Summary:Huawei PANGEA nvme-snsd
Vendor:Huawei
License: Share
Group:Applications/System
Source:%{_SOURCE}
BuildRoot: %{_tmppath}/%{name}-%{version}-root

%description
   Rpm of nvme-snsd

%prep

echo name: %{name}
echo buildroot: %{buildroot}
echo _SUBDIR: %{_SUBDIR}


%setup -q

%build

%install
rm -rf %{buildroot}/*

cp -rf * %{buildroot}/

%clean
rm -rf %{buildroot}

%pre

%post
echo ""
echo "Installation Path:"
echo ""

chmod 0550 /usr/bin/nvme-snsd
chmod 0440 /usr/share/doc/snsd.conf
chmod 0440 /usr/lib/systemd/system/nvme-snsd.service

systemctl enable nvme-snsd
systemctl start nvme-snsd

%postun
systemctl stop nvme-snsd
systemctl disable nvme-snsd

%files
%defattr (-, root, root)

/usr/bin/*
/usr/share/doc/*
/usr/lib/systemd/system/*

%changelog
