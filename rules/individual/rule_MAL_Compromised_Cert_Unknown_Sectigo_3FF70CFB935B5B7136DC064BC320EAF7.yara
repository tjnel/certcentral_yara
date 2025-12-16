import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_3FF70CFB935B5B7136DC064BC320EAF7 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-03-22"
      version             = "1.0"

      hash                = "4183d7c1b16555019f5cfc6b24a1314d166b9558f35c68e10583d8e4d02fa87e"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "周伟"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "3f:f7:0c:fb:93:5b:5b:71:36:dc:06:4b:c3:20:ea:f7"
      cert_thumbprint     = "C26C07A0BC6AEA3866472A8323F93477DD87E2DC"
      cert_valid_from     = "2023-03-22"
      cert_valid_to       = "2026-03-21"

      country             = "CN"
      state               = "湖南省"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "3f:f7:0c:fb:93:5b:5b:71:36:dc:06:4b:c3:20:ea:f7"
      )
}
