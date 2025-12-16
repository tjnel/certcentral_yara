import "pe"

rule MAL_Compromised_Cert_Latrodectus_SSL_com_4DA45F056206178D7AE829F93EFEDF22 {
   meta:
      description         = "Detects Latrodectus with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-14"
      version             = "1.0"

      hash                = "3ebab9121aef087c075e8f79e67473c39331943e650f55dc11da764bf1cd1b23"
      malware             = "Latrodectus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MAKEN LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "4d:a4:5f:05:62:06:17:8d:7a:e8:29:f9:3e:fe:df:22"
      cert_thumbprint     = "97B800AC050F8C90AFB3271EBCA0CF31AD8FC9BA"
      cert_valid_from     = "2025-03-14"
      cert_valid_to       = "2026-03-14"

      country             = "KE"
      state               = "???"
      locality            = "Nairobi"
      email               = "???"
      rdn_serial_number   = "CPR/2012/88104"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "4d:a4:5f:05:62:06:17:8d:7a:e8:29:f9:3e:fe:df:22"
      )
}
