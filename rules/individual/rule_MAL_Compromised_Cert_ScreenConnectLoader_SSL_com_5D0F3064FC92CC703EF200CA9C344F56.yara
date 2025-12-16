import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_5D0F3064FC92CC703EF200CA9C344F56 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-03"
      version             = "1.0"

      hash                = "a8cbffeb05c4d8f9f6d8a091b393c9dfdcd34305bc218588911f98f335116eda"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "jmutanen software Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5d:0f:30:64:fc:92:cc:70:3e:f2:00:ca:9c:34:4f:56"
      cert_thumbprint     = "7B4DC3ABE54BD12C68D053F7CA414006B6AAADE5"
      cert_valid_from     = "2025-03-03"
      cert_valid_to       = "2026-03-03"

      country             = "FI"
      state               = "Central Finland"
      locality            = "Jyväskylä"
      email               = "???"
      rdn_serial_number   = "2728936-9"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5d:0f:30:64:fc:92:cc:70:3e:f2:00:ca:9c:34:4f:56"
      )
}
