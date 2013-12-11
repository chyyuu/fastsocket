Name:           libfsocket
Version:     	1.0.0   
Release:        1%{?dist}
Summary:        Library that enables application to use fastsocket
Source:		libfsocket-1.0.0.tar
Group:          System Environment/Libraries
License:        GPL

%description
This program is intended to use with fastsocket kernel feature together, 
which interposes some socket related syscall and replaces them with 
interface provided in fastsocket kernel module.

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
rm -rf %buildroot
mkdir -p %buildroot%_libdir/
install -m644 libfsocket.so %buildroot%_libdir/

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc README
%_libdir/libfsocket.so

%changelog
* Wed Dec 11 2013 Xiaofeng Lin <xiaofeng6@staff.sina.com.cn>
- Initial package
