import "pe"

rule MAL_Compromised_Cert_JadeSleet_Sectigo_00EAAABEC88619D26FAC06484DC7EF4426 {
   meta:
      description         = "Detects JadeSleet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-09-08"
      version             = "1.0"

      hash                = "3da0dcf392d3d71b340e6005806c27f588c7f9a8cc00b6b03a9ac2cd808fe107"
      malware             = "JadeSleet"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Dmitry Raykhman"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:ea:aa:be:c8:86:19:d2:6f:ac:06:48:4d:c7:ef:44:26"
      cert_thumbprint     = "AB4CE4CFA68E8DA30AB0213991C1241BC96C6FC6"
      cert_valid_from     = "2022-09-08"
      cert_valid_to       = "2023-09-08"

      country             = "US"
      state               = "New York"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:ea:aa:be:c8:86:19:d2:6f:ac:06:48:4d:c7:ef:44:26"
      )
}
