import "pe"

rule MAL_Compromised_Cert_ChromeLoader_GlobalSign_7ABFA692078F1AD6A4B845F9 {
   meta:
      description         = "Detects ChromeLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-03-30"
      version             = "1.0"

      hash                = "3c03fed6b2e374d6d4d3d8a0606a390fc010974d6d3b75be52a84663e4ba9a35"
      malware             = "ChromeLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "incredimarket LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7a:bf:a6:92:07:8f:1a:d6:a4:b8:45:f9"
      cert_thumbprint     = "E1DF5CA0CA71233D09CD19987B5C06E17F64A0AC"
      cert_valid_from     = "2023-03-30"
      cert_valid_to       = "2024-03-30"

      country             = "GE"
      state               = "Imereti"
      locality            = "Samtredia"
      email               = "???"
      rdn_serial_number   = "438736496"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7a:bf:a6:92:07:8f:1a:d6:a4:b8:45:f9"
      )
}
