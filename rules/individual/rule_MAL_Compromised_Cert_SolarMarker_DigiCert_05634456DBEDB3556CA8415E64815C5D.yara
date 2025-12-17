import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_05634456DBEDB3556CA8415E64815C5D {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-28"
      version             = "1.0"

      hash                = "1d4ab34baa9e5c2cc73ec2788ca8d849befe8c0ef5d8fdd5b7a4bed5de6ebaff"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Walden Intertech Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "05:63:44:56:db:ed:b3:55:6c:a8:41:5e:64:81:5c:5d"
      cert_thumbprint     = "7352ED799D09FCCA265CF22A3313D4CF2343D7FD"
      cert_valid_from     = "2022-03-28"
      cert_valid_to       = "2023-03-29"

      country             = "CA"
      state               = "British Columbia"
      locality            = "Vancouver"
      email               = "???"
      rdn_serial_number   = "1267304-5"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "05:63:44:56:db:ed:b3:55:6c:a8:41:5e:64:81:5c:5d"
      )
}
