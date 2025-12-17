import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_05BB162F6EFE852B7BD4712FD737A61E {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-08-12"
      version             = "1.0"

      hash                = "770658cdc73ef874c0f4daedb014daea71b5c179c1474ecd6d373d89ac45b48c"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Wellpro Impact Solutions Oy"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "05:bb:16:2f:6e:fe:85:2b:7b:d4:71:2f:d7:37:a6:1e"
      cert_thumbprint     = "1D43DDBC621D92B35E3059FC0D4F0CCEAABB51D6"
      cert_valid_from     = "2021-08-12"
      cert_valid_to       = "2022-08-10"

      country             = "FI"
      state               = "???"
      locality            = "Jyväskylä"
      email               = "???"
      rdn_serial_number   = "3227015-2"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "05:bb:16:2f:6e:fe:85:2b:7b:d4:71:2f:d7:37:a6:1e"
      )
}
