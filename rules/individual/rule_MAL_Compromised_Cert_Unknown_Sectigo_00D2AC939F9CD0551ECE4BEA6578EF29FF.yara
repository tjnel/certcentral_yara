import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00D2AC939F9CD0551ECE4BEA6578EF29FF {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-03"
      version             = "1.0"

      hash                = "7061a3fbc6de3f2ab0eb819d9f6734718e11f69d8e30bf8bd392a9ba1dd63d50"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shandong Shangchuan Smart Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:d2:ac:93:9f:9c:d0:55:1e:ce:4b:ea:65:78:ef:29:ff"
      cert_thumbprint     = "980995C1299BF37B0330851D4B7EF27DAD7207C0"
      cert_valid_from     = "2025-10-03"
      cert_valid_to       = "2026-10-03"

      country             = "CN"
      state               = "Shandong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:d2:ac:93:9f:9c:d0:55:1e:ce:4b:ea:65:78:ef:29:ff"
      )
}
