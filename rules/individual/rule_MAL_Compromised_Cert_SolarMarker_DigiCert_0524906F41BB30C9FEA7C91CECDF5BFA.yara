import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_0524906F41BB30C9FEA7C91CECDF5BFA {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-04-19"
      version             = "1.0"

      hash                = "7c213efd427bc3a594a4d794cbb40b63ce8a3e3dc19312011cb7ddbf60811da1"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Snowi Tech Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "05:24:90:6f:41:bb:30:c9:fe:a7:c9:1c:ec:df:5b:fa"
      cert_thumbprint     = "BCFB608BE12E70321AD6D1360C3EFB8BBD85240E"
      cert_valid_from     = "2022-04-19"
      cert_valid_to       = "2023-04-28"

      country             = "CA"
      state               = "Ontario"
      locality            = "Toronto"
      email               = "???"
      rdn_serial_number   = "1286838-5"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "05:24:90:6f:41:bb:30:c9:fe:a7:c9:1c:ec:df:5b:fa"
      )
}
