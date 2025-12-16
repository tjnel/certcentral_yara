import "pe"

rule MAL_Compromised_Cert_Latam_Trojan_Banker_GlobalSign_48F3DBC38B46B3E29CD6CC7F {
   meta:
      description         = "Detects Latam Trojan Banker with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-01"
      version             = "1.0"

      hash                = "0146d30830cb03b405c7ebbb36e8c8747cdaed1d6b92f07d1cbc7101d229bfa6"
      malware             = "Latam Trojan Banker"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Defz Software Solutions GmbH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "48:f3:db:c3:8b:46:b3:e2:9c:d6:cc:7f"
      cert_thumbprint     = "6B355DEA3DDA10D178AB4164EABF60A00A9DCB70"
      cert_valid_from     = "2024-04-01"
      cert_valid_to       = "2024-12-05"

      country             = "AT"
      state               = "Steiermark"
      locality            = "Ludersdorf-Wilfersdorf"
      email               = "admin@defzsoftwaresolutions.com"
      rdn_serial_number   = "597406p"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "48:f3:db:c3:8b:46:b3:e2:9c:d6:cc:7f"
      )
}
