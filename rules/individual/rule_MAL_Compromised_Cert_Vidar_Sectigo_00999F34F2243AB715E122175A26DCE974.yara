import "pe"

rule MAL_Compromised_Cert_Vidar_Sectigo_00999F34F2243AB715E122175A26DCE974 {
   meta:
      description         = "Detects Vidar with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-28"
      version             = "1.0"

      hash                = "254e367cbd0d77e7423428a8421136100d95800a6cf809f85747da30605e38a0"
      malware             = "Vidar"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Guangzhou Vance Photoelectric Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "00:99:9f:34:f2:24:3a:b7:15:e1:22:17:5a:26:dc:e9:74"
      cert_thumbprint     = "A5E30987BCDB1159EFA2B1574E7C6932C82BD5AB"
      cert_valid_from     = "2024-10-28"
      cert_valid_to       = "2025-10-28"

      country             = "CN"
      state               = "Guangdong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "00:99:9f:34:f2:24:3a:b7:15:e1:22:17:5a:26:dc:e9:74"
      )
}
