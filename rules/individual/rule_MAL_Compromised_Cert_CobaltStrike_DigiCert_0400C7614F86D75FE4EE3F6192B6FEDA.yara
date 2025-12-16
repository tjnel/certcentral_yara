import "pe"

rule MAL_Compromised_Cert_CobaltStrike_DigiCert_0400C7614F86D75FE4EE3F6192B6FEDA {
   meta:
      description         = "Detects CobaltStrike with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-07-16"
      version             = "1.0"

      hash                = "d3ec1a84996a4443b146bfeeaded02eafe663af47b858adc650465f808498eb4"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "StackUp ApS"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "04:00:c7:61:4f:86:d7:5f:e4:ee:3f:61:92:b6:fe:da"
      cert_thumbprint     = "60CFAD87C57BE8AA499A6E51C6127C2D6DFF77B3"
      cert_valid_from     = "2021-07-16"
      cert_valid_to       = "2022-07-19"

      country             = "DK"
      state               = "???"
      locality            = "Kastrup"
      email               = "???"
      rdn_serial_number   = "42492043"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "04:00:c7:61:4f:86:d7:5f:e4:ee:3f:61:92:b6:fe:da"
      )
}
