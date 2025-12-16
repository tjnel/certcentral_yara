import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_SSL_com_24991F9305780821FB0326248BCBB0EE {
   meta:
      description         = "Detects NetSupportRAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-12-19"
      version             = "1.0"

      hash                = "c14cf48a6853918d2928b42ac35c6a3952bd33f5e7ae7be01a294dc2292c1925"
      malware             = "NetSupportRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Syntech Software Sp. z o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "24:99:1f:93:05:78:08:21:fb:03:26:24:8b:cb:b0:ee"
      cert_thumbprint     = "d088c86c5b8955bd5634b17c73621e72b4d0534e7538ba850e2ec21ba2944712"
      cert_valid_from     = "2024-12-19"
      cert_valid_to       = "2025-12-19"

      country             = "PL"
      state               = "Masovian Voivodeship"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "24:99:1f:93:05:78:08:21:fb:03:26:24:8b:cb:b0:ee"
      )
}
