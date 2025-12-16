import "pe"

rule MAL_Compromised_Cert_PDFixers_GlobalSign_2AC7FCE6B9C96D57663F6BB4 {
   meta:
      description         = "Detects PDFixers with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-11-21"
      version             = "1.0"

      hash                = "cc0cb1ff8cd7c38e282fc2822a94fdd93773e0f6d046d9328cdd6c1d49f4483d"
      malware             = "PDFixers"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ADSMARKETO LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2a:c7:fc:e6:b9:c9:6d:57:66:3f:6b:b4"
      cert_thumbprint     = "40C0CB1A69BC8AF1256B2862D729A330937B4CFF"
      cert_valid_from     = "2023-11-21"
      cert_valid_to       = "2024-11-21"

      country             = "UA"
      state               = "Kyiv"
      locality            = "Kyiv"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2a:c7:fc:e6:b9:c9:6d:57:66:3f:6b:b4"
      )
}
