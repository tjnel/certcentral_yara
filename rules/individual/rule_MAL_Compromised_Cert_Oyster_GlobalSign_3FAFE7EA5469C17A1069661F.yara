import "pe"

rule MAL_Compromised_Cert_Oyster_GlobalSign_3FAFE7EA5469C17A1069661F {
   meta:
      description         = "Detects Oyster with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-25"
      version             = "1.0"

      hash                = "a653b4f7f76ee8e6bd9ffa816c0a14dca2d591a84ee570d4b6245079064b5794"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "LLC Fortuna"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3f:af:e7:ea:54:69:c1:7a:10:69:66:1f"
      cert_thumbprint     = "CF22E3985849DD295571C535385019FA9559758C"
      cert_valid_from     = "2025-06-25"
      cert_valid_to       = "2026-06-26"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3f:af:e7:ea:54:69:c1:7a:10:69:66:1f"
      )
}
