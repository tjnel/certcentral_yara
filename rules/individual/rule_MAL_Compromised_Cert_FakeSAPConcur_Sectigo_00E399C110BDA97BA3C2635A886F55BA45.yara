import "pe"

rule MAL_Compromised_Cert_FakeSAPConcur_Sectigo_00E399C110BDA97BA3C2635A886F55BA45 {
   meta:
      description         = "Detects FakeSAPConcur with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-22"
      version             = "1.0"

      hash                = "ca3e4995ffe857412e84c650dea38f6243174e49559b48936dc2cbc08fdd0f28"
      malware             = "FakeSAPConcur"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Taiyuan Linma Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:e3:99:c1:10:bd:a9:7b:a3:c2:63:5a:88:6f:55:ba:45"
      cert_thumbprint     = "52D949B1CC58F2AABECD3847DFFFE9F9D9764269"
      cert_valid_from     = "2025-07-22"
      cert_valid_to       = "2026-10-20"

      country             = "CN"
      state               = "Shanxi Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:e3:99:c1:10:bd:a9:7b:a3:c2:63:5a:88:6f:55:ba:45"
      )
}
