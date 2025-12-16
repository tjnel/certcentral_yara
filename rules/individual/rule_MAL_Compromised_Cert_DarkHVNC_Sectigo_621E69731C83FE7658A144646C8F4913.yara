import "pe"

rule MAL_Compromised_Cert_DarkHVNC_Sectigo_621E69731C83FE7658A144646C8F4913 {
   meta:
      description         = "Detects DarkHVNC with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-10"
      version             = "1.0"

      hash                = "e9315d756f6c02cf88855e08c10107fa0f2d89e7e9c2620150c20e045f9f2305"
      malware             = "DarkHVNC"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wuhan Ronghuixiang Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "62:1e:69:73:1c:83:fe:76:58:a1:44:64:6c:8f:49:13"
      cert_thumbprint     = "8841156E3CF719CDC97C2CF19BC4C01BDF97903B"
      cert_valid_from     = "2025-09-10"
      cert_valid_to       = "2026-09-10"

      country             = "CN"
      state               = "Hubei Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "62:1e:69:73:1c:83:fe:76:58:a1:44:64:6c:8f:49:13"
      )
}
