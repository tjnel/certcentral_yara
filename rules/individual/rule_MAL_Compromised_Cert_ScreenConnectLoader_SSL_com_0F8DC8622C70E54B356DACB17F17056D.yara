import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_0F8DC8622C70E54B356DACB17F17056D {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-30"
      version             = "1.0"

      hash                = "1123b5a545aa5b29d529c4259633b314519029802855534b3afb3a14dd90d223"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Luchian Software Consulting, Inc."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0f:8d:c8:62:2c:70:e5:4b:35:6d:ac:b1:7f:17:05:6d"
      cert_thumbprint     = "D594E77231259667D6D20D738BF32B8B1D81AED0"
      cert_valid_from     = "2025-07-30"
      cert_valid_to       = "2026-07-30"

      country             = "CA"
      state               = "Ontario"
      locality            = "Ottawa"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0f:8d:c8:62:2c:70:e5:4b:35:6d:ac:b1:7f:17:05:6d"
      )
}
