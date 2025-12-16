import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Certum_721A46AC53182005B04CFFC2E743EB66 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-09-05"
      version             = "1.0"

      hash                = "5436d1607e673ed60dc18778c8bebdb6a6d6091cb67668f93732546b745ec08b"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Amon Software"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "72:1a:46:ac:53:18:20:05:b0:4c:ff:c2:e7:43:eb:66"
      cert_thumbprint     = "1473005A61848671CEF1C8776C6C989EDD776D55"
      cert_valid_from     = "2024-09-05"
      cert_valid_to       = "2025-09-05"

      country             = "BE"
      state               = "???"
      locality            = "Braine-l'Alleud"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "72:1a:46:ac:53:18:20:05:b0:4c:ff:c2:e7:43:eb:66"
      )
}
