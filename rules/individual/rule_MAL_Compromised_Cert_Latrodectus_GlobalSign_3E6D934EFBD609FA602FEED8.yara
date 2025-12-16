import "pe"

rule MAL_Compromised_Cert_Latrodectus_GlobalSign_3E6D934EFBD609FA602FEED8 {
   meta:
      description         = "Detects Latrodectus with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-26"
      version             = "1.0"

      hash                = "378127a840393f72bc2e98a1a3f54a57d05c08650dd485183a5554f0658632a8"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GRAND E ApS"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3e:6d:93:4e:fb:d6:09:fa:60:2f:ee:d8"
      cert_thumbprint     = "04390F6114AD5E0F1A79EB7B5A618EF99E338E46"
      cert_valid_from     = "2025-08-26"
      cert_valid_to       = "2026-08-27"

      country             = "DK"
      state               = "Region Zealand"
      locality            = "Sandved"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3e:6d:93:4e:fb:d6:09:fa:60:2f:ee:d8"
      )
}
