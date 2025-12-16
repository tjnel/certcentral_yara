import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_5A2B1F9F0E576139DEB85F99 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-30"
      version             = "1.0"

      hash                = "cc427312d340683a6ca3f7dd044ae9fce0c975d9fb73f9aa8871d975c083b954"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CITY GATE INVESTMENT NINH BINH COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5a:2b:1f:9f:0e:57:61:39:de:b8:5f:99"
      cert_thumbprint     = "7A2B75AEB62893C9DD277D855149D31CA5B0EEE5"
      cert_valid_from     = "2025-01-30"
      cert_valid_to       = "2026-01-31"

      country             = "VN"
      state               = "Ninh Bình"
      locality            = "Ninh Bình"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5a:2b:1f:9f:0e:57:61:39:de:b8:5f:99"
      )
}
