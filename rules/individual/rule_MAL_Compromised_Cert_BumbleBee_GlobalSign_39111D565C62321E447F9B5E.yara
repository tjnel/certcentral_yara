import "pe"

rule MAL_Compromised_Cert_BumbleBee_GlobalSign_39111D565C62321E447F9B5E {
   meta:
      description         = "Detects BumbleBee with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-24"
      version             = "1.0"

      hash                = "e5e8a24a628b99b2172fee5d53f003ff097739dc5c23b4374d328d72f45813cd"
      malware             = "BumbleBee"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC Alliance"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "39:11:1d:56:5c:62:32:1e:44:7f:9b:5e"
      cert_thumbprint     = "03A20DAB66BE73F50DE63B88D455A711D72B7DFF"
      cert_valid_from     = "2025-03-24"
      cert_valid_to       = "2026-03-25"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1207700225314"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "39:11:1d:56:5c:62:32:1e:44:7f:9b:5e"
      )
}
