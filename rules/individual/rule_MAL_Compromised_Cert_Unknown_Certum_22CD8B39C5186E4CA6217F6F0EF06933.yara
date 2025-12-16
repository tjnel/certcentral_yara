import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_22CD8B39C5186E4CA6217F6F0EF06933 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-31"
      version             = "1.0"

      hash                = "7a090c11328347356704734060cb6ca23a3607d768decdddd90c5a73d725431e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Cangzhou Chenyue Electronic Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "22:cd:8b:39:c5:18:6e:4c:a6:21:7f:6f:0e:f0:69:33"
      cert_thumbprint     = "432BBA0314FF92DC5E3988CBD46D50D2533F61C2"
      cert_valid_from     = "2024-05-31"
      cert_valid_to       = "2025-05-31"

      country             = "CN"
      state               = "Hebei"
      locality            = "Cangzhou"
      email               = "???"
      rdn_serial_number   = "91130922MA0G8AN920"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "22:cd:8b:39:c5:18:6e:4c:a6:21:7f:6f:0e:f0:69:33"
      )
}
