import "pe"

rule MAL_Compromised_Cert_SolarMarker_DigiCert_075D421B06BDB8CF2E01A79D07F094F1 {
   meta:
      description         = "Detects SolarMarker with compromised cert (DigiCert)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-05-17"
      version             = "1.0"

      hash                = "92279e087fea81889e228bf4032ff3765ecfbb9231ffb8e8d63662e22300599b"
      malware             = "SolarMarker"
      malware_type        = "Remote access tool"
      malware_notes       = "A remote access tool active 2020-2023. Installs a VNC client to perform on-device-fraud."

      signer              = "Stream Synergy Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "07:5d:42:1b:06:bd:b8:cf:2e:01:a7:9d:07:f0:94:f1"
      cert_thumbprint     = "42E4AC1EA0E50803C152A1E498A847B54B9595DE"
      cert_valid_from     = "2022-05-17"
      cert_valid_to       = "2023-06-06"

      country             = "CA"
      state               = "Ontario"
      locality            = "Markham"
      email               = "???"
      rdn_serial_number   = "1300793-6"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "07:5d:42:1b:06:bd:b8:cf:2e:01:a7:9d:07:f0:94:f1"
      )
}
