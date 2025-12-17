import "pe"

rule MAL_Compromised_Cert_Telegram_Clipper_SSL_com_439064F1E1F400AF733C8F86FDFF1EA4 {
   meta:
      description         = "Detects Telegram Clipper with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-28"
      version             = "1.0"

      hash                = "e14e835f7eb8c3fa4322de27d9f40fecae82d98790f52316633591eb5915f40f"
      malware             = "Telegram Clipper"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wolf-Rudiger Kotte"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "43:90:64:f1:e1:f4:00:af:73:3c:8f:86:fd:ff:1e:a4"
      cert_thumbprint     = "2906290A31F6D55F6B5BB516E71409FB19F0672D"
      cert_valid_from     = "2025-10-28"
      cert_valid_to       = "2026-10-27"

      country             = "DE"
      state               = "Saxony"
      locality            = "Dresden"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "43:90:64:f1:e1:f4:00:af:73:3c:8f:86:fd:ff:1e:a4"
      )
}
