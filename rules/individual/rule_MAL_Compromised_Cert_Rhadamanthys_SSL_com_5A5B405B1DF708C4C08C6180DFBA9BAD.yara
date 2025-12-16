import "pe"

rule MAL_Compromised_Cert_Rhadamanthys_SSL_com_5A5B405B1DF708C4C08C6180DFBA9BAD {
   meta:
      description         = "Detects Rhadamanthys with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-27"
      version             = "1.0"

      hash                = "12e4124bf790bced8b0cff6506511bc15e8b65fd31fc2f13697ce899f6ad9b69"
      malware             = "Rhadamanthys"
      malware_type        = "Infostealer"
      malware_notes       = "An module infostealer malware: https://research.checkpoint.com/2025/rhadamanthys-0-9-x-walk-through-the-updates/"

      signer              = "CodeVue OÜ"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5a:5b:40:5b:1d:f7:08:c4:c0:8c:61:80:df:ba:9b:ad"
      cert_thumbprint     = "24CB257143B9AB51B623147FAC060676636E259E"
      cert_valid_from     = "2023-09-27"
      cert_valid_to       = "2024-09-26"

      country             = "EE"
      state               = "Harju County"
      locality            = "Tallinn"
      email               = "???"
      rdn_serial_number   = "16820165"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5a:5b:40:5b:1d:f7:08:c4:c0:8c:61:80:df:ba:9b:ad"
      )
}
