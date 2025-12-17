import "pe"

rule MAL_Compromised_Cert_Pikabot_SSL_com_2941D5F8758501F9DBC4BA158058C3B5 {
   meta:
      description         = "Detects Pikabot with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-25"
      version             = "1.0"

      hash                = "89dc50024836f9ad406504a3b7445d284e97ec5dafdd8f2741f496cac84ccda9"
      malware             = "Pikabot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "A.P.Hernandez Consulting s.r.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "29:41:d5:f8:75:85:01:f9:db:c4:ba:15:80:58:c3:b5"
      cert_thumbprint     = "AE7AD3DF41DEF3E3169FFA94B2E854D4EFDCEC35"
      cert_valid_from     = "2024-01-25"
      cert_valid_to       = "2025-01-24"

      country             = "SK"
      state               = "Trnava Region"
      locality            = "Sered"
      email               = "???"
      rdn_serial_number   = "51 770 075"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "29:41:d5:f8:75:85:01:f9:db:c4:ba:15:80:58:c3:b5"
      )
}
