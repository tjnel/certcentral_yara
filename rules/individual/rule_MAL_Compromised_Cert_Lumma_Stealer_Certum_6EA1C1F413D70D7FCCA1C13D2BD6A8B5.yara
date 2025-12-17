import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_Certum_6EA1C1F413D70D7FCCA1C13D2BD6A8B5 {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-02-16"
      version             = "1.0"

      hash                = "8259a493729abd201b33851f56817f812ffd8ac75bfd3abc100e04c022f5ce59"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "Software Box Limited"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "6e:a1:c1:f4:13:d7:0d:7f:cc:a1:c1:3d:2b:d6:a8:b5"
      cert_thumbprint     = "5ED0201362CAEDF3B418409B0E3270B4F24F69FA"
      cert_valid_from     = "2025-02-16"
      cert_valid_to       = "2026-02-16"

      country             = "GB"
      state               = "England"
      locality            = "York"
      email               = "???"
      rdn_serial_number   = "12567696"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "6e:a1:c1:f4:13:d7:0d:7f:cc:a1:c1:3d:2b:d6:a8:b5"
      )
}
