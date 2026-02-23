# GhostKatz

An attempt to make https://github.com/RainbowDynamix/GhostKatz into a Sliver extension.

## Original readme

Extract LSASS credentials directly from physical memory by abusing signed vulnerable drivers with physical memory read primitives via `MmMapIoSpace`, bypassing traditional user-mode detection capabilities.

This tool was developed in collaboration between [Julian Peña](https://github.com/RainbowDynamix) and [Eric Esquivel](https://github.com/EricEsquivel).

This release of GhostKatz uses drivers that have already been publicly disclosed as vulnerable. For best results, GhostKatz is intended to operate with kernel drivers that expose read-memory primitive vulnerabilities and are not blocked during loading / publicly known. This public release does not include exploits for previously undisclosed drivers. Instead, the project is designed to be modular and extensible, allowing users to research their own drivers and integrate them by extending the read-memory primitive functions in `utils.c`. Internally, we have automated the discovery and exploitation process and maintain several signed kernel drivers with written exploits.

If you would like to contribute, please see the [contribution documentation](https://github.com/RainbowDynamix/GhostKatz/blob/main/CONTRIBUTING.md).

## Why did we make GhostKatz?
We wanted to start learning how to exploit kernel drivers and thought this would be a cool project. We were also inspired when we saw Outflank's KernelKatz tool and wanted to use it, but we do not have Outflank since we are students. So we made our own.

## Usage
Run `make` to compile the BOFs.

Load the `ghostkatz.cna` Aggressor Script into your Script Manager.

To run GhostKatz, use the command `ghostkatz [logonpasswords/wdigest] -prv <provider id>`.

You can run the help command in your Beacon console with: `help ghostkatz`.

```
beacon> help ghostkatz
Synopsis: ghostkatz [logonpasswords/wdigest] -prv <provider id>
Description:
  Dump credentials from LSASS by using signed kernel drivers to read physical memory.

Examples:
  ghostkatz logonpasswords -prv 1
  ghostkatz wdigest
```

## Demo
![GhostKatz Demo](img/demo.gif)


## Tested Windows Versions
These are simply the versions we manually stress tested. Major versions such as 1607 should not have breaking changes across minor build updates.
- Windows Server 2012 R2
  - Version 6.3 (OS Build: 9600)
- Windows Server 2016 
  - Version 1607 (OS Build: 14393.693)
- Windows Server 2019 
  - Version 1809 (OS Build: 17763.3650)
- Windows 10 
  - Version 21H2 (OS Build: 19044.6809)
  - Version 22H2 (OS Build: 19045.6466)
- Windows Server 2022
  - Version 21H2 (OS Build: 20348.587)

> [!WARNING]
> While GhostKatz has been tested thoroughly, you should use discretion if deploying in production. GhostKatz leverages vulnerable kernel drivers. It is possible errors may result in a BSOD.

## Providers

Drivers that can be exploited with GhostKatz

| Id | Vendor             | Driver Name    | SHA256                                                           |
|----|--------------------|----------------|------------------------------------------------------------------|
| 1  | Toshiba            | TPwSav         | 011df46e94218cbb2f0b8da13ab3cec397246fdc63436e58b1bf597550a647f6 |
| 2  | TechPowerUp        | ThrottleStop   | 16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0 |

## Resources
* [Outflank - Mapping Virtual to Physical Addresses Using Superfetch](https://www.outflank.nl/blog/2023/12/14/mapping-virtual-to-physical-adresses-using-superfetch/)
* [UnknownCheats - [Information] NtQuerySystemInformation SystemSuperfetchInformation by Midi12](https://www.unknowncheats.me/forum/general-programming-and-reversing/397104-ntquerysysteminformation-systemsuperfetchinformation.html)
* [Physical Graffiti Lsass](https://adepts.of0x.cc/physical-graffiti-lsass/)
* [Dumping LSASS with WinDBG and PyKD](https://www.matteomalvica.com/blog/2020/01/20/mimikatz-lsass-dump-windg-pykd/)
* Mimkatz [structures](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.h), [key offsets](https://github.com/gentilkiwi/mimikatz/blob/152b208916c27d7d1fc32d10e64879721c4d06af/mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c)
* [Dumping MSV1 logon credentials](https://whoamianony.top/posts/sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/#3-%E6%89%93%E5%8D%B0%E7%99%BB%E5%BD%95%E4%BC%9A%E8%AF%9D%E4%BF%A1%E6%81%AF)
* [XPN Exploring Mimikatz WDigest](https://blog.xpnsec.com/exploring-mimikatz-part-1/)

## Special Thanks
Thank you to [ch3rn0byl](https://github.com/ch3rn0byl) and [Cedric](https://x.com/c3c) for your time answering the dumb questions we had on the kernel, drivers, and Superfetch.
