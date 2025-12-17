import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_60BC12FFBC578B9115527E428D8B59CA {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-25"
      version             = "1.0"

      hash                = "a0c594d583540ce214a3c6d2a1f25ac912c476f3e806ffb98d2a8cd3e4beba3c"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "Cloudeya Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "60:bc:12:ff:bc:57:8b:91:15:52:7e:42:8d:8b:59:ca"
      cert_thumbprint     = "AD64CF2DD5BBE512E898F01FA2E99331F85CDB0B"
      cert_valid_from     = "2024-07-25"
      cert_valid_to       = "2025-07-25"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "12442044"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "60:bc:12:ff:bc:57:8b:91:15:52:7e:42:8d:8b:59:ca"
      )
}
