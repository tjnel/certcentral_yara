import "pe"

rule MAL_Compromised_Cert_NW0rm_Comodo_00B1BBEF3ABA79AB2EAE5B8015F26B34F8 {
   meta:
      description         = "Detects NW0rm with compromised cert (Comodo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2016-05-13"
      version             = "1.0"

      hash                = "d2802c979bc2fae533fb089fcf5c6cc0622245e874bee0c3faa23056443310a3"
      malware             = "NW0rm"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DIDZHITAL ART, OOO"
      cert_issuer_short   = "Comodo"
      cert_issuer         = "COMODO RSA Code Signing CA"
      cert_serial         = "00:b1:bb:ef:3a:ba:79:ab:2e:ae:5b:80:15:f2:6b:34:f8"
      cert_thumbprint     = "A286AFFC5F6E92BDC93374646676EBC49E21BCAE"
      cert_valid_from     = "2016-05-13"
      cert_valid_to       = "2017-05-13"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "COMODO RSA Code Signing CA" and
         sig.serial == "00:b1:bb:ef:3a:ba:79:ab:2e:ae:5b:80:15:f2:6b:34:f8"
      )
}
