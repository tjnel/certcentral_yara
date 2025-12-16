import "pe"

rule MAL_Compromised_Cert_Meowsterio_Traffer_Team_GlobalSign_41506BE5E85C247D61CCCE7E {
   meta:
      description         = "Detects Meowsterio Traffer Team with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-05"
      version             = "1.0"

      hash                = "65c4b56197458a7cce0daf9a4c7991b6f202367294c87d4c4a024e2dc64659ce"
      malware             = "Meowsterio Traffer Team"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "HIGHNOR INDIA PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "41:50:6b:e5:e8:5c:24:7d:61:cc:ce:7e"
      cert_thumbprint     = "8351DCE66144F50452466FA9104B18B23C577E72"
      cert_valid_from     = "2025-05-05"
      cert_valid_to       = "2026-05-06"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "41:50:6b:e5:e8:5c:24:7d:61:cc:ce:7e"
      )
}
