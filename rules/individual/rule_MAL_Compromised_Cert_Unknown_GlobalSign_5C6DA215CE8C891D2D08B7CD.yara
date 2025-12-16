import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_5C6DA215CE8C891D2D08B7CD {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-05"
      version             = "1.0"

      hash                = "c9075edbd201388279ff4c32a3a4a85b6b0b1fd934383394f62a7131d5c6b5fb"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Hebei Duxin Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5c:6d:a2:15:ce:8c:89:1d:2d:08:b7:cd"
      cert_thumbprint     = "018BB49CAC595A1D1D9560AD7C58F8277FA3043F"
      cert_valid_from     = "2025-03-05"
      cert_valid_to       = "2026-03-06"

      country             = "CN"
      state               = "Hebei"
      locality            = "Shijiazhuang"
      email               = "???"
      rdn_serial_number   = "91130102MA0CK7F521"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5c:6d:a2:15:ce:8c:89:1d:2d:08:b7:cd"
      )
}
