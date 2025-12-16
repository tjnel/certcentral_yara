import "pe"

rule MAL_Compromised_Cert_SystemBC_SSL_com_53E1F226CB77574F8FBEB5682DA091BB {
   meta:
      description         = "Detects SystemBC with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-05-31"
      version             = "1.0"

      hash                = "b778857f8ecf2ec65eee77cd14acb1fbae86a26764a360e4d0717b7795d155cb"
      malware             = "SystemBC"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OdyLab Inc"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "53:e1:f2:26:cb:77:57:4f:8f:be:b5:68:2d:a0:91:bb"
      cert_thumbprint     = "AE21518CD94CB73660AF05347BEFD3837AF1B4ED"
      cert_valid_from     = "2022-05-31"
      cert_valid_to       = "2023-05-31"

      country             = "US"
      state               = "Florida"
      locality            = "Brandon"
      email               = "???"
      rdn_serial_number   = "P22000028161"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "53:e1:f2:26:cb:77:57:4f:8f:be:b5:68:2d:a0:91:bb"
      )
}
