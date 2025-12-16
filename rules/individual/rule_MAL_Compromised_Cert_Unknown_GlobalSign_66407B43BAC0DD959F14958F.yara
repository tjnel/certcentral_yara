import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_66407B43BAC0DD959F14958F {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-03"
      version             = "1.0"

      hash                = "68fe3534c8dc0f0212a0be60668d36d6f0a41e411ad4ed8c124b7916029ea2ba"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "INDU-SINO IMPEX PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "66:40:7b:43:ba:c0:dd:95:9f:14:95:8f"
      cert_thumbprint     = "699E93BE2E3F3A64254D59A2516AFA012FFDE169"
      cert_valid_from     = "2025-07-03"
      cert_valid_to       = "2026-07-04"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "viseshlahoty2000@rediffmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "66:40:7b:43:ba:c0:dd:95:9f:14:95:8f"
      )
}
