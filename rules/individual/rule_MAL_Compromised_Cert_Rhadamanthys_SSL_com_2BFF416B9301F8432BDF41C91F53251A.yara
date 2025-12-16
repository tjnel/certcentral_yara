import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_2BFF416B9301F8432BDF41C91F53251A {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-10"
      version             = "1.0"

      hash                = "4c21b40c94fcd13b60b99ef1e4f372126a86e6f526c6cc134f205794c4357bd7"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Biodime Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "2b:ff:41:6b:93:01:f8:43:2b:df:41:c9:1f:53:25:1a"
      cert_thumbprint     = "15C93C32EC1C18838B5B9D7A9D3E8F694A395306"
      cert_valid_from     = "2024-05-10"
      cert_valid_to       = "2025-05-03"

      country             = "GB"
      state               = "???"
      locality            = "Kirkintilloch"
      email               = "???"
      rdn_serial_number   = "SC663866"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "2b:ff:41:6b:93:01:f8:43:2b:df:41:c9:1f:53:25:1a"
      )
}
