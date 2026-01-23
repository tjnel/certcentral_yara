import "pe"

rule MAL_Compromised_Cert_FakeUpdate_SSL_com_7B506D3D23E689FF63395DE65FEB25A3 {
   meta:
      description         = "Detects FakeUpdate with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-07"
      version             = "1.0"

      hash                = "21db3b34ea5c058d6e998c7e3916261fee5f30644116c49da8a3f073c6780a68"
      malware             = "FakeUpdate"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "FORME PROPERTY SERVICES LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7b:50:6d:3d:23:e6:89:ff:63:39:5d:e6:5f:eb:25:a3"
      cert_thumbprint     = "49C434CD0293AC6E7CDEDA5E4E54B15AE6CF9A46"
      cert_valid_from     = "2025-05-07"
      cert_valid_to       = "2026-05-07"

      country             = "GB"
      state               = "???"
      locality            = "Maidstone"
      email               = "???"
      rdn_serial_number   = "10166016"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7b:50:6d:3d:23:e6:89:ff:63:39:5d:e6:5f:eb:25:a3"
      )
}
