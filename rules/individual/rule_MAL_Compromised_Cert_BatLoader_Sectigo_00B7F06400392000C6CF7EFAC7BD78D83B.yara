import "pe"

rule MAL_Compromised_Cert_BatLoader_Sectigo_00B7F06400392000C6CF7EFAC7BD78D83B {
   meta:
      description         = "Detects BatLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-04-12"
      version             = "1.0"

      hash                = "2727a418f31e8c0841f8c3e79455067798a1c11c2b83b5c74d2de4fb3476b654"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "Zhuzhou ZHUOER-TECH Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:b7:f0:64:00:39:20:00:c6:cf:7e:fa:c7:bd:78:d8:3b"
      cert_thumbprint     = "04669C5DA7360361D1C0E7756E53058A659458E3"
      cert_valid_from     = "2023-04-12"
      cert_valid_to       = "2024-04-12"

      country             = "CN"
      state               = "Hunan Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91430211MA4PUDTX0T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:b7:f0:64:00:39:20:00:c6:cf:7e:fa:c7:bd:78:d8:3b"
      )
}
