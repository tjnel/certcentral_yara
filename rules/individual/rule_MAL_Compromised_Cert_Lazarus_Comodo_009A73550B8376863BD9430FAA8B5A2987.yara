import "pe"

rule MAL_Compromised_Cert_Lazarus_Comodo_009A73550B8376863BD9430FAA8B5A2987 {
   meta:
      description         = "Detects Lazarus with compromised cert (Comodo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2018-05-21"
      version             = "1.0"

      hash                = "bdff852398f174e9eef1db1c2d3fefdda25fe0ea90a40a2e06e51b5c0ebd69eb"
      malware             = "Lazarus"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CELAS LLC"
      cert_issuer_short   = "Comodo"
      cert_issuer         = "COMODO RSA Code Signing CA"
      cert_serial         = "00:9a:73:55:0b:83:76:86:3b:d9:43:0f:aa:8b:5a:29:87"
      cert_thumbprint     = "A2C8AD6352D333BB13E6FA3F1EAD87820A962CB7"
      cert_valid_from     = "2018-05-21"
      cert_valid_to       = "2019-05-21"

      country             = "US"
      state               = "Michigan"
      locality            = "Cedar Springs"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "COMODO RSA Code Signing CA" and
         sig.serial == "00:9a:73:55:0b:83:76:86:3b:d9:43:0f:aa:8b:5a:29:87"
      )
}
