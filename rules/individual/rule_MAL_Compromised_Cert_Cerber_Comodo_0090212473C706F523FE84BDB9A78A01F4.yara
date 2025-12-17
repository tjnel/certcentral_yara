import "pe"

rule MAL_Compromised_Cert_Cerber_Comodo_0090212473C706F523FE84BDB9A78A01F4 {
   meta:
      description         = "Detects Cerber with compromised cert (Comodo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2017-07-17"
      version             = "1.0"

      hash                = "b3e1e9d97d74c416c2a30dd11858789af5554cf2de62f577c13944a19623777d"
      malware             = "Cerber"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DEMUS, OOO"
      cert_issuer_short   = "Comodo"
      cert_issuer         = "COMODO RSA Code Signing CA"
      cert_serial         = "00:90:21:24:73:c7:06:f5:23:fe:84:bd:b9:a7:8a:01:f4"
      cert_thumbprint     = "1AA57CD87D99753381CA95C05BD22DD91B48A943"
      cert_valid_from     = "2017-07-17"
      cert_valid_to       = "2018-07-17"

      country             = "RU"
      state               = "RU"
      locality            = "Saratov"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "COMODO RSA Code Signing CA" and
         sig.serial == "00:90:21:24:73:c7:06:f5:23:fe:84:bd:b9:a7:8a:01:f4"
      )
}
