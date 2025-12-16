import "pe"

rule MAL_Compromised_Cert_Latrodectus_GlobalSign_79E97FA4E98323F95F2625C7 {
   meta:
      description         = "Detects Latrodectus with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-28"
      version             = "1.0"

      hash                = "987bfdf18e0b3dac53bcc8cc906ef6c907c3e23d9ff23eb703e196782ae00b00"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "EVEREST REMIT SEWA LLP"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "79:e9:7f:a4:e9:83:23:f9:5f:26:25:c7"
      cert_thumbprint     = "19F9CEBDFD773033B1A0A949AA87D793ADB463DB"
      cert_valid_from     = "2025-07-28"
      cert_valid_to       = "2026-07-29"

      country             = "IN"
      state               = "Delhi"
      locality            = "New Delhi"
      email               = "officeeverestremit@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "79:e9:7f:a4:e9:83:23:f9:5f:26:25:c7"
      )
}
