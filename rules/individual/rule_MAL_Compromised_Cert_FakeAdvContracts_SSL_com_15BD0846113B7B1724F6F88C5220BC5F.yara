import "pe"

rule MAL_Compromised_Cert_FakeAdvContracts_SSL_com_15BD0846113B7B1724F6F88C5220BC5F {
   meta:
      description         = "Detects FakeAdvContracts with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-08"
      version             = "1.0"

      hash                = "e4df8c48cdcf1d0e02dc7c055197bb66b0f310a0a764a7d738d97815af587b05"
      malware             = "FakeAdvContracts"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SELECTVIEW DATA SOLUTIONS SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "15:bd:08:46:11:3b:7b:17:24:f6:f8:8c:52:20:bc:5f"
      cert_thumbprint     = "BD74EC050FBFF8A8591BC7C0A7A94B72E55EFDCA"
      cert_valid_from     = "2025-08-08"
      cert_valid_to       = "2026-08-08"

      country             = "PL"
      state               = "Lower Silesian Voivodeship"
      locality            = "Wrocław"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "15:bd:08:46:11:3b:7b:17:24:f6:f8:8c:52:20:bc:5f"
      )
}
