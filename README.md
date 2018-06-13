# CryptLink.CertBuilder
A portable (dotnet standard) utility class for generating x509 certificates

[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
[![Build status](https://ci.appveyor.com/api/projects/status/vhtrnq4m0ln13gpb?svg=true)](https://ci.appveyor.com/project/CryptLink/certbuilder)
[![NuGet](https://img.shields.io/nuget/v/CryptLink.CertBuilder.svg)](https://www.nuget.org/packages/CryptLink.CertBuilder/)

## Example
``` C#
    var ca1 = new CertBuilder { SubjectName = "CN=Test CA1", KeyStrength = 4096 }.BuildX509();
    Console.WriteLine(ca1.Thumbprint);
```