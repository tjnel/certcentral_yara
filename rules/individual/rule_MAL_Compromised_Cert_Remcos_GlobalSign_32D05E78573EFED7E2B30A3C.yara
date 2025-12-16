import "pe"

rule MAL_Compromised_Cert_Remcos_GlobalSign_32D05E78573EFED7E2B30A3C {
   meta:
      description         = "Detects Remcos with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-14"
      version             = "1.0"

      hash                = "df668ebc65fd0035faed898755e4dd1ee61f76f58b6a49448f6489765e1fbc2a"
      malware             = "Remcos"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "THANH LIEM ENVIRONMENT COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "32:d0:5e:78:57:3e:fe:d7:e2:b3:0a:3c"
      cert_thumbprint     = "6E12E4302CD228FD138C6412EF48B93D81FDCFA0"
      cert_valid_from     = "2025-03-14"
      cert_valid_to       = "2026-03-15"

      country             = "VN"
      state               = "Hà Nam"
      locality            = "Hà Nam"
      email               = "???"
      rdn_serial_number   = "0700463959"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "32:d0:5e:78:57:3e:fe:d7:e2:b3:0a:3c"
      )
}
