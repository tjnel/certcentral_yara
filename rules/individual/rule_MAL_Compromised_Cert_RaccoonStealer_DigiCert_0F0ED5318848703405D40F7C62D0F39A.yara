import "pe"

rule MAL_Compromised_Cert_RaccoonStealer_DigiCert_0F0ED5318848703405D40F7C62D0F39A {
   meta:
      description         = "Detects RaccoonStealer with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-03"
      version             = "1.0"

      hash                = "e51a5ecb5c7ab754cccf2531882b6e724dcd0b15a9c3978384480605549096c5"
      malware             = "RaccoonStealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SIES UPRAVLENIE PROTSESSAMI, OOO"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert EV Code Signing CA (SHA2)"
      cert_serial         = "0f:0e:d5:31:88:48:70:34:05:d4:0f:7c:62:d0:f3:9a"
      cert_thumbprint     = "ED91194EE135B24D5DF160965D8036587D6C8C35"
      cert_valid_from     = "2021-03-03"
      cert_valid_to       = "2021-04-26"

      country             = "RU"
      state               = "???"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1155038005320"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert EV Code Signing CA (SHA2)" and
         sig.serial == "0f:0e:d5:31:88:48:70:34:05:d4:0f:7c:62:d0:f3:9a"
      )
}
