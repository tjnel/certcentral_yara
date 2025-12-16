import "pe"

rule MAL_Compromised_Cert_GhostSocks_Certum_1905352485295F24C0DB0A61AE7EFC68 {
   meta:
      description         = "Detects GhostSocks with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-21"
      version             = "1.0"

      hash                = "4d1efd06b57f610e1ac066543d08176eb48dacd932eeda5735dfcaf6bf493573"
      malware             = "GhostSocks"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TeraShift GmbH"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "19:05:35:24:85:29:5f:24:c0:db:0a:61:ae:7e:fc:68"
      cert_thumbprint     = "9721B8E9C4B029ACD781ED07B5C5C50979A8C8E9"
      cert_valid_from     = "2024-11-21"
      cert_valid_to       = "2027-11-21"

      country             = "CH"
      state               = "Appenzell Innerrhoden"
      locality            = "Appenzell"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "19:05:35:24:85:29:5f:24:c0:db:0a:61:ae:7e:fc:68"
      )
}
