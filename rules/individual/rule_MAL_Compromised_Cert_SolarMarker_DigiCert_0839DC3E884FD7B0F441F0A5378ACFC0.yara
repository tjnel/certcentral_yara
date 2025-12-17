import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_0839DC3E884FD7B0F441F0A5378ACFC0 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-09-03"
      version             = "1.0"

      hash                = "b1620fbd2194bc09812c01134b7f60292cfbabd26f1360ecb04c1f66cb2dd4f5"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "SN Pelletier Consulting Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "08:39:dc:3e:88:4f:d7:b0:f4:41:f0:a5:37:8a:cf:c0"
      cert_thumbprint     = "B3989A6B973C0DEEDDDC240A58E3E53D71560FD6"
      cert_valid_from     = "2021-09-03"
      cert_valid_to       = "2022-08-24"

      country             = "CA"
      state               = "Quebec"
      locality            = "Marston"
      email               = "???"
      rdn_serial_number   = "1000745-5"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "08:39:dc:3e:88:4f:d7:b0:f4:41:f0:a5:37:8a:cf:c0"
      )
}
