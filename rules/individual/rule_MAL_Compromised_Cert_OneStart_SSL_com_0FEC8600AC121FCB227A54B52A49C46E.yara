import "pe"

rule MAL_Compromised_Cert_OneStart_SSL_com_0FEC8600AC121FCB227A54B52A49C46E {
   meta:
      description         = "Detects OneStart with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-04"
      version             = "1.0"

      hash                = "c571c75b1878c02f801ef1e953176c1e7db1ca2c9809811637a44e5a98d228cd"
      malware             = "OneStart"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Caerus Media LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "0f:ec:86:00:ac:12:1f:cb:22:7a:54:b5:2a:49:c4:6e"
      cert_thumbprint     = "93D7CCF32FDAC1FAAD0BA923E56FA8DAFEE2B352"
      cert_valid_from     = "2024-09-04"
      cert_valid_to       = "2025-09-04"

      country             = "US"
      state               = "Delaware"
      locality            = "Dover"
      email               = "???"
      rdn_serial_number   = "6125248"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "0f:ec:86:00:ac:12:1f:cb:22:7a:54:b5:2a:49:c4:6e"
      )
}
