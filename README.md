# GhostKatz
Dump LSASS credentials from physical memory by exploiting signed vulnerable drivers exposing physical memory read primitives via `MmMapIoSpace`.

This tool was developed in collaboration between [Julian Peña](https://github.com/RainbowDynamix) and [Eric Esquivel](https://github.com/EricEsquivel).

This release of GhostKatz uses drivers that have already been publicly disclosed as vulnerable. For best results, GhostKatz is intended to operate with kernel drivers that expose read-memory primitive vulnerabilities and are not blocked during loading / publicly known. This public release does not include exploits for previously undisclosed drivers. Instead, the project is designed to be modular and extensible, allowing users to research their own drivers and integrate them by extending the read-memory primitive functions in `utils.c`. Internally, we have automated the discovery and exploitation process and maintain several signed kernel drivers with written exploits.

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

## Providers

Drivers that can be exploited with GhostKatz

| Id | Vendor             | Driver Name    | SHA256                                                           | Blacklisted?    |
|----|--------------------|----------------|------------------------------------------------------------------|-----------------|
| 1  | Toshiba            | TPwSav         | 011df46e94218cbb2f0b8da13ab3cec397246fdc63436e58b1bf597550a647f6 | No              | 
| 2  | TechPowerUp        | ThrottleStop   | 16f83f056177c4ec24c7e99d01ca9d9d6713bd0497eeedb777a3ffefa99c97f0 | No              |
| 3  | Lenovo             | LnvMSRIO       | 245b6ab442a7d53dc30ece28e1c6de727c019669385877cbe929b81aa1a2ad2f | No              |

###### * Blacklist state set at commit time. May be inaccurate.


## Resources
* [Outflank - Mapping Virtual to Physical Addresses Using Superfetch](https://www.outflank.nl/blog/2023/12/14/mapping-virtual-to-physical-adresses-using-superfetch/)
* [Physical Graffiti Lsass](https://adepts.of0x.cc/physical-graffiti-lsass/)
* [Dumping LSASS with WinDBG and PyKD](https://www.matteomalvica.com/blog/2020/01/20/mimikatz-lsass-dump-windg-pykd/)
* [Mimkatz structures](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_utils.h)
* [Dumping MSV1 logon credentials](https://whoamianony.top/posts/sekurlsa-how-to-dump-user-login-credentials-from-msv1_0/#3-%E6%89%93%E5%8D%B0%E7%99%BB%E5%BD%95%E4%BC%9A%E8%AF%9D%E4%BF%A1%E6%81%AF)
* [XPN Exploring Mimikatz WDigest](https://blog.xpnsec.com/exploring-mimikatz-part-1/)

## Special Thanks
Thank you to [ch3rn0byl](https://github.com/ch3rn0byl) and [Cedric](https://x.com/c3c) for your time answering the dumb questions we had on the kernel, drivers, and Superfetch.