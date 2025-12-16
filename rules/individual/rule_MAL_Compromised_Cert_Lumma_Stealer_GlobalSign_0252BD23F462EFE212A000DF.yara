import "pe"

rule MAL_Compromised_Cert_Lumma_Stealer_GlobalSign_0252BD23F462EFE212A000DF {
   meta:
      description         = "Detects Lumma Stealer with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-03"
      version             = "1.0"

      hash                = "d5558bb4f7db0aab0c709068a9561cd79eafaf035038d42f321620c94883762a"
      malware             = "Lumma Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "This malware was sold as a service and was the most popular infostealer in 2024."

      signer              = "INNOFLOW VINA COMPANY LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "02:52:bd:23:f4:62:ef:e2:12:a0:00:df"
      cert_thumbprint     = "7E47A51679B2CB0F01C6560D662BFC0D2FDBD685"
      cert_valid_from     = "2024-06-03"
      cert_valid_to       = "2025-06-04"

      country             = "VN"
      state               = "Thai Binh"
      locality            = "Thai Binh"
      email               = "???"
      rdn_serial_number   = "1001152550"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "02:52:bd:23:f4:62:ef:e2:12:a0:00:df"
      )
}
