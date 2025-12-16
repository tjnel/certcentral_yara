import "pe"

rule MAL_Compromised_Cert_PDFSkills_GlobalSign_476A4CA18A6095A5619A7C4D {
   meta:
      description         = "Detects PDFSkills with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-12"
      version             = "1.0"

      hash                = "1994b6c8c30b4346f6b00da12fc161eb73210af08b914a1c4768b109b234f2df"
      malware             = "PDFSkills"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BLACK INDIGO LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "47:6a:4c:a1:8a:60:95:a5:61:9a:7c:4d"
      cert_thumbprint     = "3B5253A4853056458675B5CB1903C05BC2DBBD1B"
      cert_valid_from     = "2024-11-12"
      cert_valid_to       = "2025-11-13"

      country             = "IL"
      state               = "Central District"
      locality            = "Ra'anana"
      email               = "Support@blackindigoltd.com"
      rdn_serial_number   = "515530624"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "47:6a:4c:a1:8a:60:95:a5:61:9a:7c:4d"
      )
}
