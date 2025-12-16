import "pe"

rule MAL_Compromised_Cert_FakeBat_Certum_4A29544A73CF3715B71E1482033FA811 {
   meta:
      description         = "Detects FakeBat with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-25"
      version             = "1.0"

      hash                = "d43aca5bbb482c44ab63300aee957ec5614da9bb82a537edd4805932b1b82b13"
      malware             = "FakeBat"
      malware_type        = "Loader"
      malware_notes       = "This loader was sold as a service. Most frequently it was used to load an infostealer, but could easily load anything else: https://www.sekoia.io/en/glossary/fakebat/"

      signer              = "JJK Software Oy"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "4a:29:54:4a:73:cf:37:15:b7:1e:14:82:03:3f:a8:11"
      cert_thumbprint     = ""
      cert_valid_from     = "2024-11-25"
      cert_valid_to       = "2025-11-25"

      country             = "FI"
      state               = "???"
      locality            = "Espoo"
      email               = ""
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "4a:29:54:4a:73:cf:37:15:b7:1e:14:82:03:3f:a8:11"
      )
}
