import "pe"

rule MAL_Compromised_Cert_Wagmi_Traffer_Team_GlobalSign_525DB6D9E035E547A81A3A8D {
   meta:
      description         = "Detects Wagmi Traffer Team with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-16"
      version             = "1.0"

      hash                = "1868b95455df42b9d6968e1f748f1786467bde865c69461444437625ec851c5d"
      malware             = "Wagmi Traffer Team"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOI TREE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "52:5d:b6:d9:e0:35:e5:47:a8:1a:3a:8d"
      cert_thumbprint     = "B8FB7476817DE65A446D5A7F138560AFAD883E0E"
      cert_valid_from     = "2025-04-16"
      cert_valid_to       = "2026-04-17"

      country             = "KE"
      state               = "Nairobi"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "CPR/2013/108876"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "52:5d:b6:d9:e0:35:e5:47:a8:1a:3a:8d"
      )
}
