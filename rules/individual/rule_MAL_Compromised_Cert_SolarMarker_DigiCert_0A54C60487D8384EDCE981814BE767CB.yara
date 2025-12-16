import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_0A54C60487D8384EDCE981814BE767CB {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-10-31"
      version             = "1.0"

      hash                = "0abe73a746671028db3ef2ba3ea8bea059888fc177d76a11e34cd1f075b24b69"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Decapolis Consulting Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0a:54:c6:04:87:d8:38:4e:dc:e9:81:81:4b:e7:67:cb"
      cert_thumbprint     = "BB800B7DE9E457D670303AF12E1940C732CC5975"
      cert_valid_from     = "2021-10-31"
      cert_valid_to       = "2022-10-24"

      country             = "CA"
      state               = "Ontario"
      locality            = "Oakville"
      email               = "???"
      rdn_serial_number   = "1000934-2"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0a:54:c6:04:87:d8:38:4e:dc:e9:81:81:4b:e7:67:cb"
      )
}
