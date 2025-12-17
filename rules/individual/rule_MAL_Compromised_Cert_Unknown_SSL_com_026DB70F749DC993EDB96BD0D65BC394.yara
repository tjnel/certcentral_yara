import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_026DB70F749DC993EDB96BD0D65BC394 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-09"
      version             = "1.0"

      hash                = "153b47dcff405cb891ab9c7a25d54e998760f1eb4567751d438c70cf31c10bb6"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GreenLine Software Corp."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "02:6d:b7:0f:74:9d:c9:93:ed:b9:6b:d0:d6:5b:c3:94"
      cert_thumbprint     = "448172A55C7A9F547613944C9E34D1C3299EA46F"
      cert_valid_from     = "2024-08-09"
      cert_valid_to       = "2025-08-09"

      country             = "CA"
      state               = "Ontario"
      locality            = "Ottawa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "02:6d:b7:0f:74:9d:c9:93:ed:b9:6b:d0:d6:5b:c3:94"
      )
}
