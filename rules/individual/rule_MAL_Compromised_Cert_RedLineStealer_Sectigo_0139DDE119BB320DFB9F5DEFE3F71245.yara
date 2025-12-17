import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_0139DDE119BB320DFB9F5DEFE3F71245 {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-11-10"
      version             = "1.0"

      hash                = "64df21caada72b25868c916b897d5188935337edb476cf1c850317ac7aa28d1e"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "Hangil IT Co., Ltd"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "01:39:dd:e1:19:bb:32:0d:fb:9f:5d:ef:e3:f7:12:45"
      cert_thumbprint     = "28F9A8E7601F5338BF6E194151A718608C0124A8"
      cert_valid_from     = "2021-11-10"
      cert_valid_to       = "2024-11-09"

      country             = "KR"
      state               = "Seoul"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "01:39:dd:e1:19:bb:32:0d:fb:9f:5d:ef:e3:f7:12:45"
      )
}
