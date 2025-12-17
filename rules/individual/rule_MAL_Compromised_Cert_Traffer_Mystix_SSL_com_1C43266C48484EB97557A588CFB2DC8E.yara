import "pe"

rule MAL_Compromised_Cert_Traffer_Mystix_SSL_com_1C43266C48484EB97557A588CFB2DC8E {
   meta:
      description         = "Detects Traffer (Mystix) with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-22"
      version             = "1.0"

      hash                = "76a11b90a7b90b2771a287826703e9af026249bff53e8779bd5ed7170f56ec68"
      malware             = "Traffer (Mystix)"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "A man did it OY"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "1c:43:26:6c:48:48:4e:b9:75:57:a5:88:cf:b2:dc:8e"
      cert_thumbprint     = "8E84C5F39DD603E6B2B37E554130E5CFEEE678CE"
      cert_valid_from     = "2025-04-22"
      cert_valid_to       = "2026-04-22"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Klaukkala"
      email               = "???"
      rdn_serial_number   = "2952655-9"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "1c:43:26:6c:48:48:4e:b9:75:57:a5:88:cf:b2:dc:8e"
      )
}
