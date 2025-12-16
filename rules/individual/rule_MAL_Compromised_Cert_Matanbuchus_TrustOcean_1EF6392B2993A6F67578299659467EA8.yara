import "pe"

rule MAL_Compromised_Cert_Matanbuchus_TrustOcean_1EF6392B2993A6F67578299659467EA8 {
   meta:
      description         = "Detects Matanbuchus with compromised cert (TrustOcean)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-04-16"
      version             = "1.0"

      hash                = "490bcee7c0b9607d834fd8b3e5d01613d062fcf48be043e6f5f60c5077b55e3c"
      malware             = "Matanbuchus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ALUSEN d. o. o."
      cert_issuer_short   = "TrustOcean"
      cert_issuer         = "TrustOcean Organization Software Vendor CA"
      cert_serial         = "1e:f6:39:2b:29:93:a6:f6:75:78:29:96:59:46:7e:a8"
      cert_thumbprint     = "E87D3E289CCB9F8F9CAA53F2AEFBA102FBF4B231"
      cert_valid_from     = "2021-04-16"
      cert_valid_to       = "2022-04-16"

      country             = "SI"
      state               = "Ormož"
      locality            = "Podgorci"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "TrustOcean Organization Software Vendor CA" and
         sig.serial == "1e:f6:39:2b:29:93:a6:f6:75:78:29:96:59:46:7e:a8"
      )
}
