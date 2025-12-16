import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_1374AACB98D398309DC23E87 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-02"
      version             = "1.0"

      hash                = "7d0956a7271c09b26d53a3097433e72229a2785ea0f07084c902c88b954c3d5c"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "The Software Experts, LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "13:74:aa:cb:98:d3:98:30:9d:c2:3e:87"
      cert_thumbprint     = "57348020810778420D356207F52F034DEB30F59F"
      cert_valid_from     = "2024-12-02"
      cert_valid_to       = "2025-12-03"

      country             = "US"
      state               = "Arizona"
      locality            = "Scottsdale"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "13:74:aa:cb:98:d3:98:30:9d:c2:3e:87"
      )
}
