import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_0204699A9056F9CD65B82EC2 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-28"
      version             = "1.0"

      hash                = "483e1a9c8161994b4794dd65e4cfb8b2889b3f7802613e37b4920c9fe8393443"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "RAMASHISH SECURITY SERVICES PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "02:04:69:9a:90:56:f9:cd:65:b8:2e:c2"
      cert_thumbprint     = "2CF8CAF6FA656EFE8C79C24B351332C7901FABDC"
      cert_valid_from     = "2025-07-28"
      cert_valid_to       = "2026-07-29"

      country             = "IN"
      state               = "Bihar"
      locality            = "Samastipur"
      email               = "ramashish.ssindia@zohomail.in"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "02:04:69:9a:90:56:f9:cd:65:b8:2e:c2"
      )
}
