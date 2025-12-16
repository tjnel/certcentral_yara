import "pe"

rule MAL_Compromised_Cert_Xworm_Certum_4AEA2FD2D3DD61D454B29A9035C7443E {
   meta:
      description         = "Detects Xworm with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-30"
      version             = "1.0"

      hash                = "0cf06c833517acebaebf18e5b36edccb4903a112117dbee1a19f9b76c7a7b36f"
      malware             = "Xworm"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Huixiantong Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "4a:ea:2f:d2:d3:dd:61:d4:54:b2:9a:90:35:c7:44:3e"
      cert_thumbprint     = "B0D949125202A88EF756E702FF910631B5E1C674"
      cert_valid_from     = "2024-09-30"
      cert_valid_to       = "2025-09-30"

      country             = "CN"
      state               = "Fujian"
      locality            = "Xiamen"
      email               = "???"
      rdn_serial_number   = "91350211MA31JF8419"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "4a:ea:2f:d2:d3:dd:61:d4:54:b2:9a:90:35:c7:44:3e"
      )
}
