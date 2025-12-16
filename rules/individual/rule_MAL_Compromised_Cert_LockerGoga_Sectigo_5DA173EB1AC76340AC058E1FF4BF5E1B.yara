import "pe"

rule MAL_Compromised_Cert_LockerGoga_Sectigo_5DA173EB1AC76340AC058E1FF4BF5E1B {
   meta:
      description         = "Detects LockerGoga with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2019-02-22"
      version             = "1.0"

      hash                = "eda26a1cd80aac1c42cdbba9af813d9c4bc81f6052080bc33435d1e076e75aa0"
      malware             = "LockerGoga"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ALISA LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "5d:a1:73:eb:1a:c7:63:40:ac:05:8e:1f:f4:bf:5e:1b"
      cert_thumbprint     = "ACB38D45108C4F0C8894040646137C95E9BB39D8"
      cert_valid_from     = "2019-02-22"
      cert_valid_to       = "2020-02-21"

      country             = "GB"
      state               = "LONDON"
      locality            = "LONDON"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "5d:a1:73:eb:1a:c7:63:40:ac:05:8e:1f:f4:bf:5e:1b"
      )
}
