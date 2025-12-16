import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_0915E7AD8C2B57E11D65AFC9E497D252 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-09-11"
      version             = "1.0"

      hash                = "b55b93ec2e7b962840adfacb4e6007c620f6e7fc9a1289825b44b1376a5cc081"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "ТОВ \"Ветох\""
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "09:15:e7:ad:8c:2b:57:e1:1d:65:af:c9:e4:97:d2:52"
      cert_thumbprint     = "5B6F1EC184C2421EE80FCA729DF45DB815064A3B"
      cert_valid_from     = "2023-09-11"
      cert_valid_to       = "2024-09-10"

      country             = "UA"
      state               = "Dnipropetrovsk Oblast"
      locality            = "Dnipro"
      email               = "???"
      rdn_serial_number   = "45226750"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "09:15:e7:ad:8c:2b:57:e1:1d:65:af:c9:e4:97:d2:52"
      )
}
