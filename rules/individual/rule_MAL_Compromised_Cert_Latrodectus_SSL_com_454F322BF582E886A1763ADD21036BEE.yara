import "pe"

rule MAL_Compromised_Cert_Latrodectus_SSL_com_454F322BF582E886A1763ADD21036BEE {
   meta:
      description         = "Detects Latrodectus with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-15"
      version             = "1.0"

      hash                = "dcd82f7f01855769e9a2dad934be7231d6a7c50254077c094f4c3324daeed715"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SAFSTA ENTERPRISE LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "45:4f:32:2b:f5:82:e8:86:a1:76:3a:dd:21:03:6b:ee"
      cert_thumbprint     = "5FD2E525DF8767B559CA02B7C363A0FC5210657A"
      cert_valid_from     = "2025-09-15"
      cert_valid_to       = "2026-09-15"

      country             = "GB"
      state               = "???"
      locality            = "LEICESTER"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "45:4f:32:2b:f5:82:e8:86:a1:76:3a:dd:21:03:6b:ee"
      )
}
