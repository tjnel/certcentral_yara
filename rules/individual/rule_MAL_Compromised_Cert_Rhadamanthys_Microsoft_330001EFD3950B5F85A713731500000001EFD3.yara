import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_Microsoft_330001EFD3950B5F85A713731500000001EFD3 {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (Microsoft)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-04"
      version             = "1.0"

      hash                = "22e286bfba3b106995c722b918908fcd1ee424bfc8e0a12c2f22f1344a2fcf75"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "志超 柴"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:01:ef:d3:95:0b:5f:85:a7:13:73:15:00:00:00:01:ef:d3"
      cert_thumbprint     = "518DDE0276C68C5CB5A2E9B085D5146FD7908AFD"
      cert_valid_from     = "2025-03-04"
      cert_valid_to       = "2025-03-07"

      country             = "CN"
      state               = "???"
      locality            = "平南"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:01:ef:d3:95:0b:5f:85:a7:13:73:15:00:00:00:01:ef:d3"
      )
}
