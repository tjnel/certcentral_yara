import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_16D84CA3D6CC85273B76FABE {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-21"
      version             = "1.0"

      hash                = "0b9afc9019f3074c429025e860294cb9456510609dd1dca8e8378753ade5a17e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "LLC KHORDA"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "16:d8:4c:a3:d6:cc:85:27:3b:76:fa:be"
      cert_thumbprint     = "14F60420135014EEF51C177DE32EC6816CF2040F"
      cert_valid_from     = "2025-04-21"
      cert_valid_to       = "2026-04-22"

      country             = "RU"
      state               = "Oryol  Oblast"
      locality            = "Oryol"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "16:d8:4c:a3:d6:cc:85:27:3b:76:fa:be"
      )
}
