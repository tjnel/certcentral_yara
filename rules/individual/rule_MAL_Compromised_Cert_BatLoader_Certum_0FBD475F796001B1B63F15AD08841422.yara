import "pe"

rule MAL_Compromised_Cert_BatLoader_Certum_0FBD475F796001B1B63F15AD08841422 {
   meta:
      description         = "Detects BatLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-09-28"
      version             = "1.0"

      hash                = "1c64bc2911b32ede634aba9e44dedd8d0897cc5d234a95cb0af715381ac6a24c"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "Tax In Cloud sp. z o.o."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "0f:bd:47:5f:79:60:01:b1:b6:3f:15:ad:08:84:14:22"
      cert_thumbprint     = "5C458D6AD871833CE824C4C4C87C51F450EE43F8"
      cert_valid_from     = "2022-09-28"
      cert_valid_to       = "2023-09-28"

      country             = "PL"
      state               = "mazowieckie"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "0000828067"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "0f:bd:47:5f:79:60:01:b1:b6:3f:15:ad:08:84:14:22"
      )
}
