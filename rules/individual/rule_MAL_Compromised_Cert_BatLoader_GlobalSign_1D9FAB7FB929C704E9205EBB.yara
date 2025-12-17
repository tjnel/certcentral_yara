import "pe"

rule MAL_Compromised_Cert_BatLoader_GlobalSign_1D9FAB7FB929C704E9205EBB {
   meta:
      description         = "Detects BatLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-02-27"
      version             = "1.0"

      hash                = "1c93d7e99ad24f2f4550859cdd3a1d785ad70a7c05b216b1d18a34bd569947ef"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "Buicrosr Monerrka Network Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1d:9f:ab:7f:b9:29:c7:04:e9:20:5e:bb"
      cert_thumbprint     = "D70F10ED3920B81FD2DBDA33BE01DBB8FABC7919"
      cert_valid_from     = "2024-02-27"
      cert_valid_to       = "2025-02-27"

      country             = "CN"
      state               = "Jiangxi"
      locality            = "Jiujiang"
      email               = "???"
      rdn_serial_number   = "91360402MACJW7755M"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1d:9f:ab:7f:b9:29:c7:04:e9:20:5e:bb"
      )
}
