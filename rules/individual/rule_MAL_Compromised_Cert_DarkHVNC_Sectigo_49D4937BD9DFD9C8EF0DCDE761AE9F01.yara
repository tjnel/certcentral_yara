import "pe"

rule MAL_Compromised_Cert_DarkHVNC_Sectigo_49D4937BD9DFD9C8EF0DCDE761AE9F01 {
   meta:
      description         = "Detects DarkHVNC with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-22"
      version             = "1.0"

      hash                = "2cc3fa50e3701792b4a42931b452e8c0c112fd34399185d53669455d8aa4bc33"
      malware             = "DarkHVNC"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shanghai Nuobao Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "49:d4:93:7b:d9:df:d9:c8:ef:0d:cd:e7:61:ae:9f:01"
      cert_thumbprint     = "8F826118157EC949C885180AA14864A8C1FE799A"
      cert_valid_from     = "2025-08-22"
      cert_valid_to       = "2026-08-22"

      country             = "CN"
      state               = "Shanghai Shi"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "49:d4:93:7b:d9:df:d9:c8:ef:0d:cd:e7:61:ae:9f:01"
      )
}
