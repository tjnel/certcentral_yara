import "pe"

rule MAL_Compromised_Cert_AureliaLoader_GlobalSign_502C9ACFE6C45CCDA77F9088 {
   meta:
      description         = "Detects AureliaLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-25"
      version             = "1.0"

      hash                = "83eb2d1dc17099a0ecf20de117ad640c919b6994f3efb83428d93d2aa1dcc4cb"
      malware             = "AureliaLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Straight Side Consulting Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "50:2c:9a:cf:e6:c4:5c:cd:a7:7f:90:88"
      cert_thumbprint     = "DE343A0AE941D4107D6DED1EC131EC52A218F44A"
      cert_valid_from     = "2025-07-25"
      cert_valid_to       = "2026-07-26"

      country             = "CA"
      state               = "Ontario"
      locality            = "Brampton"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "50:2c:9a:cf:e6:c4:5c:cd:a7:7f:90:88"
      )
}
