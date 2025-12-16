import "pe"

rule MAL_Compromised_Cert_RaccoonStealer_Sectigo_54C793D2224BDD6CA527BB2B7B9DFE9D {
   meta:
      description         = "Detects RaccoonStealer with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-08-23"
      version             = "1.0"

      hash                = "0b68bc5c0df6f79fc25b191dc85bf3b5d9c3e2c9b77a3b64fe258d81cfe7169e"
      malware             = "RaccoonStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CODE - HANDLE, s. r. o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "54:c7:93:d2:22:4b:dd:6c:a5:27:bb:2b:7b:9d:fe:9d"
      cert_thumbprint     = "D171D91C33FC3E7CB4BDEFC6677FEC1DC71CA53D"
      cert_valid_from     = "2021-08-23"
      cert_valid_to       = "2022-08-23"

      country             = "SK"
      state               = "Trenčiansky kraj"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "54:c7:93:d2:22:4b:dd:6c:a5:27:bb:2b:7b:9d:fe:9d"
      )
}
