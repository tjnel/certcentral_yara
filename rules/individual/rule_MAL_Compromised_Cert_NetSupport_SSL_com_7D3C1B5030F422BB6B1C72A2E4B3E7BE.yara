import "pe"

rule MAL_Compromised_Cert_NetSupport_SSL_com_7D3C1B5030F422BB6B1C72A2E4B3E7BE {
   meta:
      description         = "Detects NetSupport with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-25"
      version             = "1.0"

      hash                = "0a827cc64b4a5c0c3199322b59681f69502ce365fdc5f97d30dda1d5f505775a"
      malware             = "NetSupport"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "BI-TEST, OSOO"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7d:3c:1b:50:30:f4:22:bb:6b:1c:72:a2:e4:b3:e7:be"
      cert_thumbprint     = "EA07FAF24DBE71EED89946698E901DA4BFE3E820"
      cert_valid_from     = "2025-03-25"
      cert_valid_to       = "2026-03-25"

      country             = "KG"
      state               = "???"
      locality            = "Bishkek"
      email               = "???"
      rdn_serial_number   = "31548832"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7d:3c:1b:50:30:f4:22:bb:6b:1c:72:a2:e4:b3:e7:be"
      )
}
