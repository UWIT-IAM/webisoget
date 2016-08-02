Summary:	Retrieve ISO protected web pages
Name:		webisoget
Version:	2.8.4
Release:	1
License:	Apache License v2.0
Group:		Applications/Internet
Source0:	http://staff.washington.edu/fox/webisoget/%{name}-%{version}.tar.gz
URL:		http://staff.washington.edu/fox/webisoget/
Requires:	openssl curl
BuildRequires:	openssl-devel curl-devel
BuildRoot:	%{_tmppath}/%{name}-%{version}-root-%(id -u -n)

%description
Webisoget is a web page retrieval program that will 
follow redirections and frames, and will submit
and follow forms.  It can be used to access
pubcookie and shibboleth protected pages.

%prep
%setup -q

%build
%configure
%{__make}

%install
[ "$RPM_BUILD_ROOT" != "/" ] && %{__rm} -rf $RPM_BUILD_ROOT
%makeinstall
install -d $RPM_BUILD_ROOT%{_docdir}/%{name}
install doc/webisoget.html $RPM_BUILD_ROOT%{_docdir}/%{name}/webisoget.html

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && %{__rm} -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%attr(755,root,root) %{_bindir}/webisoget
%{_libdir}/libwebisoget.so*
%{_libdir}/libwebisoget.a
%doc %{_mandir}/man1/webisoget.1.gz
%doc %{_docdir}/%{name}/webisoget.html
%exclude %{_libdir}/*.la
%exclude %{_includedir}/webisoget.h

%define date	%(echo `LC_ALL="C" date +"%a %b %d %Y"`)
%changelog
* %{date} Peter Schober <peter.schober@univie.ac.at> 2.01-1
- Rough first take at packaging, tested on RHEL5 and rebuilt on SLES9
* %{date} Jim Fox <fox@washington.edu> 2.01-2
- Rough first take at packaging, tested on RHEL5 and rebuilt on SLES9

