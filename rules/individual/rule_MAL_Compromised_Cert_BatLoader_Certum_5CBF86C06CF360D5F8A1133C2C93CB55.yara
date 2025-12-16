import "pe"

rule MAL_Compromised_Cert_BatLoader_Certum_5CBF86C06CF360D5F8A1133C2C93CB55 {
   meta:
      description         = "Detects BatLoader with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-22"
      version             = "1.0"

      hash                = "d1dff8d1451bb6787f2abec3944deb060c05424fca4831c2c199f5706b7975b3"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "Shenzhen Jingwei Electronic Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5c:bf:86:c0:6c:f3:60:d5:f8:a1:13:3c:2c:93:cb:55"
      cert_thumbprint     = "9A63A5F29AFB3F7F9553A7325E5D9EC38913A4C4"
      cert_valid_from     = "2024-08-22"
      cert_valid_to       = "2025-08-22"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "91440300MA5GXFDW60"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5c:bf:86:c0:6c:f3:60:d5:f8:a1:13:3c:2c:93:cb:55"
      )
}
