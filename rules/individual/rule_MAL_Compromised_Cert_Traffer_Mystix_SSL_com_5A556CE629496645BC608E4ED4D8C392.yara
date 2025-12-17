import "pe"

rule MAL_Compromised_Cert_Traffer_Mystix_SSL_com_5A556CE629496645BC608E4ED4D8C392 {
   meta:
      description         = "Detects Traffer (Mystix) with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-11"
      version             = "1.0"

      hash                = "624b6745c4d05ddcad0d60f2e169942b5575c5c423491260feb296db9b8ca9c8"
      malware             = "Traffer (Mystix)"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Tim Instruments, OSOO"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5a:55:6c:e6:29:49:66:45:bc:60:8e:4e:d4:d8:c3:92"
      cert_thumbprint     = "FAF55093400CE870E055A5A6B1D1F1168D37F5F9"
      cert_valid_from     = "2025-04-11"
      cert_valid_to       = "2026-04-11"

      country             = "KG"
      state               = "???"
      locality            = "Bishkek"
      email               = "???"
      rdn_serial_number   = "31416881"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5a:55:6c:e6:29:49:66:45:bc:60:8e:4e:d4:d8:c3:92"
      )
}
