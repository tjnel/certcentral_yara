import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_DigiCert_0D848B64F0E176904FFC50DE2497D6E8 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-12-03"
      version             = "1.0"

      hash                = "032b067091d530a3a2079140e7550b447ecb3accd2a09b247d0126193bb3953c"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Rbit Limited"
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
      cert_serial         = "0d:84:8b:64:f0:e1:76:90:4f:fc:50:de:24:97:d6:e8"
      cert_thumbprint     = "F5C77CE3DD49167541BE6E5A2E5334F16B9770E3"
      cert_valid_from     = "2021-12-03"
      cert_valid_to       = "2022-12-03"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "11633091"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1" and
         sig.serial == "0d:84:8b:64:f0:e1:76:90:4f:fc:50:de:24:97:d6:e8"
      )
}
