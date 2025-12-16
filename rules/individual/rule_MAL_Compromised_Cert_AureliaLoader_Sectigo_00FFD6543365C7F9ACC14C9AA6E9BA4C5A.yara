import "pe"

rule MAL_Compromised_Cert_AureliaLoader_Sectigo_00FFD6543365C7F9ACC14C9AA6E9BA4C5A {
   meta:
      description         = "Detects AureliaLoader with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-10"
      version             = "1.0"

      hash                = "a29c12347e2ff618aa160e1b0f37c46dc39ced9c2336d362cfa67e59bec201e0"
      malware             = "AureliaLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shaanxi Shaogekaifei Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ff:d6:54:33:65:c7:f9:ac:c1:4c:9a:a6:e9:ba:4c:5a"
      cert_thumbprint     = "921D2773FA5EED42670F01D4419797324E996C5E"
      cert_valid_from     = "2025-09-10"
      cert_valid_to       = "2026-09-10"

      country             = "CN"
      state               = "Shaanxi Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ff:d6:54:33:65:c7:f9:ac:c1:4c:9a:a6:e9:ba:4c:5a"
      )
}
