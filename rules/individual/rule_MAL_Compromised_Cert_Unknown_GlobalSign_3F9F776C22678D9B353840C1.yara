import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_3F9F776C22678D9B353840C1 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-04"
      version             = "1.0"

      hash                = "339433c2cedc450a1f99512423ec4d951a9ba3b8d193af3c1162b7240bc8c6ff"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ADATPARTNER Software und Systeme GmbH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3f:9f:77:6c:22:67:8d:9b:35:38:40:c1"
      cert_thumbprint     = "6F239939B15A961431E6B84B16CF7C2BD15929B5"
      cert_valid_from     = "2024-12-04"
      cert_valid_to       = "2025-12-05"

      country             = "AT"
      state               = "Wien"
      locality            = "Wien"
      email               = "???"
      rdn_serial_number   = "37666t"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3f:9f:77:6c:22:67:8d:9b:35:38:40:c1"
      )
}
