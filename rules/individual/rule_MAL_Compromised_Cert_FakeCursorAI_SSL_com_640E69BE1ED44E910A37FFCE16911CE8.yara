import "pe"

rule MAL_Compromised_Cert_FakeCursorAI_SSL_com_640E69BE1ED44E910A37FFCE16911CE8 {
   meta:
      description         = "Detects FakeCursorAI with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-11"
      version             = "1.0"

      hash                = "d1e661844e46ea11ac9169f7e71253a02db279b6bef4c6ffe144d298ca8db917"
      malware             = "FakeCursorAI"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SUNDAR PARIWAR NIDHI LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "64:0e:69:be:1e:d4:4e:91:0a:37:ff:ce:16:91:1c:e8"
      cert_thumbprint     = "176313C81309D12631E74FE697243F07D0A9C440"
      cert_valid_from     = "2025-09-11"
      cert_valid_to       = "2026-09-10"

      country             = "IN"
      state               = "Bihar"
      locality            = "Begusarai"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "64:0e:69:be:1e:d4:4e:91:0a:37:ff:ce:16:91:1c:e8"
      )
}
