import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_068D0AB0A8356C79919FE07391362873 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-08-15"
      version             = "1.0"

      hash                = "0404db80657a603605b3c0128269a1d7eea2b4e0a17b7a3f48ddc0640248f2c0"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Vespero s. r. o."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "06:8d:0a:b0:a8:35:6c:79:91:9f:e0:73:91:36:28:73"
      cert_thumbprint     = "F3FA0E4E972FF770E13D9080A8F812AF1D06AA56"
      cert_valid_from     = "2021-08-15"
      cert_valid_to       = "2022-08-13"

      country             = "SK"
      state               = "???"
      locality            = "Bratislava"
      email               = "???"
      rdn_serial_number   = "53 957 440"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "06:8d:0a:b0:a8:35:6c:79:91:9f:e0:73:91:36:28:73"
      )
}
