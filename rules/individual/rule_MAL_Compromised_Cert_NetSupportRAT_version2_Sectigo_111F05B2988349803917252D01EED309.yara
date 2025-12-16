import "pe"

rule MAL_Compromised_Cert_NetSupportRAT_version2_Sectigo_111F05B2988349803917252D01EED309 {
   meta:
      description         = "Detects NetSupportRAT_version2 with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-12-24"
      version             = "1.0"

      hash                = "ef93c3569e5a26c1caa17c8371a7897fff65a7f8f0466cefeeb8220876f66097"
      malware             = "NetSupportRAT_version2"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Ivosight Software Inc."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "11:1f:05:b2:98:83:49:80:39:17:25:2d:01:ee:d3:09"
      cert_thumbprint     = "16D3312563F689AD1716ABC8DD0E711F510F4CA2"
      cert_valid_from     = "2020-12-24"
      cert_valid_to       = "2023-10-03"

      country             = "US"
      state               = "Washington"
      locality            = "University Place"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "11:1f:05:b2:98:83:49:80:39:17:25:2d:01:ee:d3:09"
      )
}
