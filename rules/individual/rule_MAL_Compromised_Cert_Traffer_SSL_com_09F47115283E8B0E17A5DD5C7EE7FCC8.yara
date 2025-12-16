import "pe"

rule MAL_Compromised_Cert_Traffer_SSL_com_09F47115283E8B0E17A5DD5C7EE7FCC8 {
   meta:
      description         = "Detects Traffer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-09"
      version             = "1.0"

      hash                = "b62c954dbf527bd56e7b0660be3588cb9e361a3c22ee5677dc6ed9b0de1c97b1"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "HARD - TOOLS C&C SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "09:f4:71:15:28:3e:8b:0e:17:a5:dd:5c:7e:e7:fc:c8"
      cert_thumbprint     = "33F63D4D1D932E7BBD625A6E1275305F79ECD82D"
      cert_valid_from     = "2025-06-09"
      cert_valid_to       = "2026-06-09"

      country             = "PL"
      state               = "Masovian Voivodeship"
      locality            = "Siedlce"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "09:f4:71:15:28:3e:8b:0e:17:a5:dd:5c:7e:e7:fc:c8"
      )
}
