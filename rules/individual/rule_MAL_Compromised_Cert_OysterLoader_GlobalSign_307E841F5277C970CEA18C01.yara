import "pe"

rule MAL_Compromised_Cert_OysterLoader_GlobalSign_307E841F5277C970CEA18C01 {
   meta:
      description         = "Detects OysterLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-14"
      version             = "1.0"

      hash                = "9d669404f58ee1437e23ea74e3565a7d445142e0a428d3add6e633b691426e08"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "S.N. ADVANCED SEWERAGE SOLUTIONS LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "30:7e:84:1f:52:77:c9:70:ce:a1:8c:01"
      cert_thumbprint     = "CBBD6817F60B3746069D18C4BAD9761B5E7D57AA"
      cert_valid_from     = "2025-11-14"
      cert_valid_to       = "2026-11-15"

      country             = "IL"
      state               = "Central District"
      locality            = "Kiryat Ekron"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "30:7e:84:1f:52:77:c9:70:ce:a1:8c:01"
      )
}
