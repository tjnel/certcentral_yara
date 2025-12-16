import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_Certum_33252E4F8965178EC4D35289247A427F {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-26"
      version             = "1.0"

      hash                = "14e9e9fcbe3b729634542e7aee4b3e63b9ccdba39bc87885b6e338bad168aba5"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Shandong Yunlu Information Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "33:25:2e:4f:89:65:17:8e:c4:d3:52:89:24:7a:42:7f"
      cert_thumbprint     = "8337D3D842EDDAFB0085CBB7C044D8CA6AAB932C"
      cert_valid_from     = "2024-07-26"
      cert_valid_to       = "2025-07-26"

      country             = "CN"
      state               = "Shandong"
      locality            = "Jinan"
      email               = "???"
      rdn_serial_number   = "91370102MA3NHYDYX4"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "33:25:2e:4f:89:65:17:8e:c4:d3:52:89:24:7a:42:7f"
      )
}
