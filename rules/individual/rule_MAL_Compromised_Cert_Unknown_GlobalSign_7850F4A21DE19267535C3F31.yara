import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_7850F4A21DE19267535C3F31 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-15"
      version             = "1.0"

      hash                = "3497025e293265e4306312d2be09e51c910d0d9f1d8642dc667c11a3a4d986b6"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "RAPIRA LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "78:50:f4:a2:1d:e1:92:67:53:5c:3f:31"
      cert_thumbprint     = "860EF9F3FC4255C48E58A4B841C75BD58AFAFBBB"
      cert_valid_from     = "2025-09-15"
      cert_valid_to       = "2025-11-02"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "78:50:f4:a2:1d:e1:92:67:53:5c:3f:31"
      )
}
