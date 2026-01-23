import "pe"

rule MAL_Compromised_Cert_Traffer_GlobalSign_3E6CC95AF2CD4010280CA6DD {
   meta:
      description         = "Detects Traffer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-15"
      version             = "1.0"

      hash                = "9743621b54c150ef426c6a7bf8b497eacbe2edfc6460e45bf3299608d5456547"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ali Global Solutions LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3e:6c:c9:5a:f2:cd:40:10:28:0c:a6:dd"
      cert_thumbprint     = "74A1CC43A4BFFFDF33A13A01C9939DEBC0E94BB4"
      cert_valid_from     = "2026-01-15"
      cert_valid_to       = "2027-01-16"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3e:6c:c9:5a:f2:cd:40:10:28:0c:a6:dd"
      )
}
