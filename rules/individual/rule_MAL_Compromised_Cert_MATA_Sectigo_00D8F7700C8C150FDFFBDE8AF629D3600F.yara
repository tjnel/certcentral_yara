import "pe"

rule MAL_Compromised_Cert_MATA_Sectigo_00D8F7700C8C150FDFFBDE8AF629D3600F {
   meta:
      description         = "Detects MATA with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-08-22"
      version             = "1.0"

      hash                = "81cd6e1c6e1f9400e31b122dfa2c7acf274192ec560a9d29190a70abd04b20e2"
      malware             = "MATA"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Kamiesha Mason"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:d8:f7:70:0c:8c:15:0f:df:fb:de:8a:f6:29:d3:60:0f"
      cert_thumbprint     = "E9F886EDC250A8F1C4BD991544B329E6AFFAE9E0"
      cert_valid_from     = "2022-08-22"
      cert_valid_to       = "2023-08-22"

      country             = "US"
      state               = "Texas"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:d8:f7:70:0c:8c:15:0f:df:fb:de:8a:f6:29:d3:60:0f"
      )
}
