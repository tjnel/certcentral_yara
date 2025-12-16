import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00FF6F8EB16961447B9ED8DB0EC52836DB {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-04-05"
      version             = "1.0"

      hash                = "eb9ae22d364a6eb1c7aa469cc25809f4040c8a9a7722ac87ca041123e97d35ae"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SIU PHYUT"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:ff:6f:8e:b1:69:61:44:7b:9e:d8:db:0e:c5:28:36:db"
      cert_thumbprint     = "B12A0AA65C9005CDB0D2F9DC092A4B937FF322CF"
      cert_valid_from     = "2023-04-05"
      cert_valid_to       = "2026-04-04"

      country             = "VN"
      state               = "Gia Lai"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:ff:6f:8e:b1:69:61:44:7b:9e:d8:db:0e:c5:28:36:db"
      )
}
