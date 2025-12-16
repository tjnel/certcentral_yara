import "pe"

rule MAL_Compromised_Cert_SolarMarker_SSL_com_5A472CA5C4DDFFA6493FAFDCF135F4B0 {
   meta:
      description         = "Detects SolarMarker with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-26"
      version             = "1.0"

      hash                = "2db7438e5b4298ce068006ef96f729fd0bb4863e856425215ad9e77f807562e0"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "HOLDING MEDICAL GROUP KATOWICE SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5a:47:2c:a5:c4:dd:ff:a6:49:3f:af:dc:f1:35:f4:b0"
      cert_thumbprint     = "287819474F99798A56472A6E4FCAD3FD5A048757"
      cert_valid_from     = "2023-12-26"
      cert_valid_to       = "2024-12-25"

      country             = "PL"
      state               = "???"
      locality            = "Katowice"
      email               = "???"
      rdn_serial_number   = "0000829859"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5a:47:2c:a5:c4:dd:ff:a6:49:3f:af:dc:f1:35:f4:b0"
      )
}
