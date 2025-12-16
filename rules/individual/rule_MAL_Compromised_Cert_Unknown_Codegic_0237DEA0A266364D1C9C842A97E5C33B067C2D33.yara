import "pe"

rule MAL_Compromised_Cert_Unknown_Codegic_0237DEA0A266364D1C9C842A97E5C33B067C2D33 {
   meta:
      description         = "Detects Unknown with compromised cert (Codegic)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-01-30"
      version             = "1.0"

      hash                = "ea49feb2417b506b1095ff67b609628df2d18d02ad68e1161cdf0608796923e6"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "EuropesServices"
      cert_issuer_short   = "Codegic"
      cert_issuer         = "Codegic CA G2"
      cert_serial         = "02:37:de:a0:a2:66:36:4d:1c:9c:84:2a:97:e5:c3:3b:06:7c:2d:33"
      cert_thumbprint     = "2c3278570b0db8dbd676a81d628061fffe32be7c667a87f2e091949f3f6cd0b6"
      cert_valid_from     = "2025-01-30"
      cert_valid_to       = "2025-03-31"

      country             = "BR"
      state               = "???"
      locality            = "???"
      email               = "deusumars@gmail.com"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Codegic CA G2" and
         sig.serial == "02:37:de:a0:a2:66:36:4d:1c:9c:84:2a:97:e5:c3:3b:06:7c:2d:33"
      )
}
